# outpost: plan

outpost is a self-hosted TURN relay for NESER network play. It carries the games of players
whose networks cannot be connected directly (both on mobile networks, carrier-grade NAT, work
networks). It runs as its own program and container next to liaison, the signaling server, on
the rmstdope VPS.

This plan covers three repositories: **outpost** (the relay), **rmstdope-infra** (the first app
that publishes a non-HTTP port) and **liaison** (handing out relay credentials). The NESER side
is a bead filed after nr-z4nw and nr-ri8n.

## How it fits together

```text
             wss://liaison.rmstdope.eu/ws                  (Caddy, 443)
Browser A ─────────────── liaison ─────────────── Browser B
                             │ internal: "credentials for room X"
                             ▼   (rmstdope-proxy network, never routed by Caddy)
                          outpost
Browser A ── UDP 3478 ──►  outpost  ◄── UDP 3478 ── Browser B
                     relays A ⇄ B, only within room X
             https://outpost.rmstdope.eu/healthz, /release.json   (Caddy, 443)
```

1. When a room is created or joined, liaison asks outpost, over the internal Docker network, for
   TURN credentials tied to that room. It passes them to the browser with `created`/`joined`
   as a ready-made `iceServers` entry.
2. Each browser allocates a relay address on outpost. WebRTC tries direct paths first and uses
   the relay only when they fail.
3. outpost forwards traffic **only between the two allocations of the same room**, inside the
   process. It never sends anything to any other address.

## Key design choices (D1–D4 decided by the navigator, 2026-10-30)

**D1. Relay only within a room, forwarded inside outpost.** A general TURN server relays to
any address a client names. That makes it an open proxy that needs a deny-list (otherwise a
client could reach `dominos-db` or other services inside the VPS) and a published range of relay
ports. outpost instead allows a peer only if it is the other allocation in the same room, and
forwards between the two in memory. Consequences:
- **one published port number** (3478, UDP and TCP; see D3) instead of a port range;
- no route out to the internet or into the VPS, so neither an open proxy nor a way into
  internal services;
- a relayed pair is always relay↔relay through outpost. That is fine, because both browsers in
  a room get credentials.

This depends on Chrome and Firefox accepting it. **Step 1 proves it before anything else is
built.**

**D2. Credentials come from outpost over the internal network, with no shared secret.**
liaison calls `POST http://outpost-web:8081/rooms` (a port Caddy never routes), and outpost
returns a random username and password for that room, valid for 12 hours. So:
- no secrets anywhere, and liaison keeps its current static registration and automatic updates;
- any container on `rmstdope-proxy` could ask for credentials. Those are your own trusted apps,
  and the credentials only allow relaying within a room they create;
- an outpost restart forgets credentials. It drops relayed games anyway.

The alternative is the standard "TURN REST API" scheme: liaison signs credentials with an HMAC
secret shared with outpost. That needs a secret in liaison, and liaison's host registration
allows none. Moving liaison to a reviewed definition is an unsupported registration migration.

**D3. UDP and TCP on 3478 from the start.** TCP helps networks that block UDP but allow
outgoing TCP to 3478. The browser keeps one TCP connection to outpost, and outpost still relays
inside the process, so a TCP client and a UDP client can share a room. TURN over TLS on 443,
for networks that allow only web traffic, stays out of scope: 443 belongs to Caddy.

**D4. Manual releases only.** Restarting outpost drops every relayed game in progress, so it
is released deliberately (`rmstdope-deploy release outpost --latest`) and **not** enrolled in
automatic updates. liaison keeps its automatic updates, because restarting it drops only
handshakes.

**D5. Written in Rust, like liaison.** It uses tokio, and axum for the small HTTP side. The
TURN logic is our own, because the room-only rule is not something off-the-shelf servers
offer. A maintained STUN message crate handles parsing and integrity, chosen with you in step 2.
The subset needed is small:
- STUN Binding (which also makes outpost a STUN server);
- the TURN requests Allocate, Refresh, CreatePermission and ChannelBind;
- Send and Data indications, and ChannelData;
- long-term credential authentication.

## Steps

Each step is one PR with tests, merged green, in the order below.

### 1. Spike: Chrome connects through a room-only relay (outpost)

A throwaway, minimal relay in Rust (Allocate, CreatePermission, Send/Data, no auth) plus a
Playwright test. Two headless Chrome pages with `iceTransportPolicy: "relay"` open a data
channel through it. Also run it once on the VPS behind Docker's UDP port publishing, to confirm:
- each client's real public address reaches the container;
- UFW and Hostup's network let 3478/udp through.

**Gate:** if Chrome won't use relay↔relay forwarding inside one process, stop and revisit D1.
The fallback is a general relay with a deny-list and a port range.

### 2. outpost skeleton and CI (outpost)

Same shape as liaison:
- HTTP on 8080: `/`, `/healthz`, `/release.json`;
- the internal API on 8081;
- UDP and TCP listeners on 3478;
- a non-root Alpine image;
- CI: fmt, clippy and all tests; build the image, start it and smoke-test it; on `main`, push
  `ghcr.io/rmstdope/outpost` and the `deployment-manifest`.

`/healthz` is healthy only when the UDP listener answers a STUN Binding request.

### 3. STUN Binding (outpost)

Answer Binding requests with the client's public address. Unit tests check the messages
against RFC 8489's test vectors.

### 4. TURN relay (outpost)

- Allocations with long-term credential authentication (realm, nonce).
- Refresh, CreatePermission, ChannelBind, Send/Data indications, ChannelData.
- The same requests over TCP 3478, with RFC 8656's framing (D3).
- The room rule from D1.
- Limits:
  - two allocations per room;
  - allocations per client address;
  - a bandwidth cap per allocation, with room for bursts;
  - lifetimes;
  - total allocations.

Logs show only counts, no addresses. Tests:
- unit tests of each request;
- integration tests with a Rust TURN test client;
- the Playwright test from step 1, run in CI against the container.

### 5. Credentials API (outpost)

`POST /rooms` on 8081 only. It returns `{urls, username, credential}` for one room, valid for
12 hours, and the credentials work only within that room. Port 8081 is never published or
routed by Caddy.

### 6. rmstdope-infra: the first app with a public non-HTTP port (infra PR)

- **Policy.** Allow a reviewed in-repo definition to publish named non-HTTP ports, listed
  explicitly. Update:
  - the instructions in `.github/copilot-instructions.md`;
  - `ARCHITECTURE.md`: the networking diagram and trust boundaries;
  - `docs/applications.md`, under custom Compose definitions;
  - `docs/setup.md`: the intended public listeners and UFW.
- **Enforcement.** A test that fails if any definition publishes a port that is not on an
  explicit allowlist. Initially that is only Caddy's 80/443 and outpost's `3478/udp` and
  `3478/tcp`.
  Today the rule is policy only.
- **`apps/outpost/`:**
  - `app.json`: static profile, workflow source `rmstdope/outpost`, used for
    `release --latest` but not enrolled;
  - `compose.json`: `ports: ["3478:3478/udp", "3478:3478/tcp"]` and proxy alias `outpost-web`,
    hardened like
    `control` (`user 10001`, `read_only`, `cap_drop: ALL`, `no-new-privileges`), plus
    `mem_limit`, healthcheck and logging;
  - `route.caddy`: `outpost.rmstdope.eu` to `outpost-web:8080`.
- **`docs/outpost.md`:**
  - why it is released by hand;
  - what a restart does to games in progress;
  - the host prerequisites (UFW rule, Hostup firewall);
  - how to roll back.

Validation already only renders the Compose config and checks Caddy, so the published port
needs no change there.

### 7. Host changes and first deployment (operator, with your go-ahead)

1. Add UFW rules for `3478/udp` and `3478/tcp` (IPv4; the VPS has no IPv6). Docker's published ports bypass
   UFW, so this mainly keeps the firewall's record honest. Check Hostup's own network firewall,
   if there is one.
2. Grant GHCR read access and the polling token access for `rmstdope/outpost`. DNS is already
   covered by the wildcard.
3. `rmstdope-deploy tooling install <infra-sha>`, then `validate outpost`, then
   `release outpost --latest`.
4. Check from outside:
   - `https://outpost.rmstdope.eu/release.json`;
   - a STUN Binding to `outpost.rmstdope.eu:3478` returns your public address;
   - the step-1 Playwright test pointed at production.

### 8. liaison hands out relay credentials (liaison)

On `create` and `join`, liaison asks outpost for the room's credentials and adds
`"iceServers": [...]` to `created` and `joined`. It updates the protocol in the README and keeps
automatic updates.

If outpost doesn't answer within a second, liaison leaves the relay out and the room still
works; direct connections are unaffected. Tests use a fake outpost.

### 9. NESER uses the relay (bead, after nr-z4nw and nr-ri8n)

Network play passes liaison's `iceServers` to the connection. Players see this change, so it
goes through a design session (for example, whether to show that a game is relayed and what
that means for delay). nr-ri8n's "cannot connect" message then appears only when even the relay
fails.

## Costs and limits

- **Traffic:** about 25 MB per player per relayed hour (one small message per frame each way;
  not yet measured). The VPS sees about 100 MB in and out per relayed game-hour, plus the ROM
  once. Check Hostup's monthly transfer allowance once, in step 7.
- **Delay:** every relayed game goes via the VPS in Sweden. NESER's existing response-time check
  shows the delay and warns when it is too slow.
- **Not covered:** networks that allow only web traffic, which would need TURN over TLS on 443
  (D3), and IPv6-only clients.
- **Privacy:** the relay sees players' public addresses and the encrypted WebRTC traffic.
  It cannot read the game data, which WebRTC encrypts end to end.
