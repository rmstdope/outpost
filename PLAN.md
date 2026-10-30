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
offer. So is the STUN message code (decided 2026-10-30, after the spike handled it in a few
hundred lines), using small crates only for MD5, HMAC-SHA1 and CRC32. The subset needed is small:
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

**Done (2026-10-30): passed** in Chrome and Firefox, locally and on the VPS behind Docker's
published UDP port, which keeps the players' real addresses. Details are in `spike/README.md`.

### 2. outpost skeleton and CI (outpost)

Same shape as liaison:
- HTTP on 8080: `/`, `/healthz`, `/release.json`;
- UDP and TCP listeners on 3478, answering Binding requests;
- a non-root Alpine image;
- CI: fmt, clippy and all tests; build the image, start it and smoke-test it; on `main`, push
  `ghcr.io/rmstdope/outpost` and the `deployment-manifest`.

`/healthz` is healthy only when the UDP listener answers a STUN Binding request.

**Done (2026-10-30).** Binding moved here from step 3, because `/healthz` needs it. The internal
API on 8081 moved to step 5, where it first has something to serve.

### 3. STUN conformance (outpost)

The rest of RFC 8489 that step 4 relies on:
- FINGERPRINT and MESSAGE-INTEGRITY, checked against RFC 5769's test vectors;
- error responses, including 420 for unknown comprehension-required attributes;
- ignoring what is not addressed to a server (responses, unknown classes).

**Done (2026-10-30).** RFC 8489 §6.3 settled one point: a server drops requests for methods it
does not serve silently, rather than answering them with an error. Chrome and Firefox both
gathered through a local outpost as their STUN server.

### 4. TURN relay (outpost)

Delivered in four pull requests:
- **4a.** Allocate and Refresh with long-term authentication, a quota per room, and lifetimes.
- **4b.** CreatePermission, and Send and Data indications, within a room only.
- **4c.** ChannelBind and ChannelData, over UDP and TCP.
- **4d.** The limits below. The Playwright test in CI moves to step 5, which first lets a
  test ask outpost for a room's credentials.

**4a done (2026-10-30).** Chrome and Firefox allocate over UDP and TCP; a wrong password draws a
401. Decisions on the way:
- A room is one username and password, as D2 has it, so its quota is the per-username quota
  RFC 8656 §7.2 recommends. It is **eight allocations, not two**. A browser allocates once per
  TURN URL and network interface (UDP and TCP from D3; Wi-Fi and a VPN), and a reload leaves
  the old allocation until it expires, so with two places one player could fill the room. The
  room rule (D1) still keeps relaying inside the room.
- Only TURN requests take the relay's lock. Reading, Binding, signing and fingerprinting
  happen outside it, so a large unauthenticated message cannot stall the relay.
- Nonces are stateless: an issue time plus an HMAC over the client's address and transport,
  under a per-process secret. RFC 8489 forbids giving two source addresses the same nonce.
- Nonces carry no RFC 8489 "nonce cookie", so clients use plain MD5 keys and MESSAGE-INTEGRITY,
  as browsers do.
- Rooms do not expire yet; step 5 gives them their 12 hours.

**4b done (2026-10-30).** With a local outpost, Chrome and Firefox opened a data channel
relay↔relay over UDP and over TCP, both with both pages relay-only and with one free to use any
path (23–81 ms after the answer). Decisions on the way:
- Every relayed address shares `OUTPOST_PUBLIC_IP`, and permissions are by IP address only
  (RFC 8656 §9). A permission cannot tell rooms apart, so the room rule is applied when data is
  sent, as §11.2 allows: the peer must be another live allocation of the sender's room, and
  each must have a permission for the other.
- CreatePermission is granted for any IPv4 address, as in the spike, because on its own it lets
  nothing through. An allocation holds at most 64 permissions (508 beyond).
- Answers and data for a TCP client go through a queue of 256 messages per connection. A client
  that falls further behind loses what does not fit, as it would over UDP. Messages over TCP
  are capped at 2048 bytes, like datagrams, so one connection's queue holds at most about
  0.5 MB.
- TCP clients are told apart by address. A new connection from an address whose old one is
  still being cleaned up takes the address over and ends the old allocation, and the old
  connection then cleans up only what is still its own.

**4c done (2026-10-30).** Chrome binds channels and sends most of its data as ChannelData, over
UDP and TCP; Firefox uses only Send indications. Both opened their data channels through a
local outpost in every run. Decisions on the way:
- A channel can be bound to any IPv4 peer and installs a permission for it, under the same
  all-or-nothing cap of 64 permissions; data on it still reaches only another allocation of
  the same room. An allocation binds at most 64 channels.
- Relayed data reaches the receiver on its channel to the sender if it has one, whichever way
  it was sent, and as a Data indication otherwise.
- Over TCP the first four bytes tell ChannelData from STUN; ChannelData is padded to four
  bytes there and not over UDP.

**4d done (2026-10-30).** The limits are in `src/limit.rs` and listed in the README, with
these defaults:
- 16 allocations per IP address and 1000 in all;
- 512 KiB/s per room with bursts of 2 MiB, each message counted as its data plus 40 bytes;
- 16 TCP connections per address and 1000 in all. A connection is closed after 120 s without a
  whole message, or 30 s without an allocation;
- 20 UDP answers a second per address, with bursts of 40, to requests that did not log in.

Data beyond the bandwidth is dropped, as if lost on the way, and WebRTC's congestion control
slows down. Chrome and Firefox still connected in every run with these defaults.

The review of 4d found ways around a first version, which shaped the limits:
- **Bandwidth is per room, not per allocation.** Ending an allocation and making a new one
  refilled a per-allocation bucket, and one player could hold several allocations.
- **Every relayed message costs its data plus 40 bytes,** so empty messages are not free.
- **Answers to requests that logged in are not limited.** Their nonce cannot be forged for
  another address, so forged floods cannot cut a player off from their allocation.
- **The answers are counted in a fixed table of buckets** picked by a keyed hash of the
  address, rather than one bucket per address seen. A first version tracked up to 100,000
  addresses with a shared overflow, which forged sources could fill and drain.
- **A TCP connection that has not allocated within 30 s is closed.** That bounds how long one
  connection without credentials holds a place, but a client reconnecting from many
  addresses can still keep them taken; the README lists this.

Total bandwidth is not capped; step 7 checks Hostup's link and monthly allowance against it.

- Allocations with long-term credential authentication (realm, nonce).
- Refresh, CreatePermission, ChannelBind, Send/Data indications, ChannelData.
- The same requests over TCP 3478, with RFC 8656's framing (D3).
- The room rule from D1.
- Limits:
  - eight allocations per room (4a);
  - allocations per client address;
  - TCP connections per client address and in all, and idle TCP connections closed;
  - answers per client address over UDP: a spoofed 20-byte Binding request draws a reply about
    three times its size, so outpost must not be a useful reflector;
  - a bandwidth cap per allocation, with room for bursts;
  - lifetimes;
  - total allocations.

Logs show only counts, no addresses. Tests:
- unit tests of each request;
- integration tests with a Rust TURN test client;
- the Playwright test from step 1, run in CI against the container.

### 5. Credentials API (outpost)

A second HTTP listener on 8081, with `POST /rooms` only. It returns
`{urls, username, credential}` for one room, valid for 12 hours, and the credentials work only
within that room. Port 8081 is never published or routed by Caddy.

Rooms are opened at a limited rate (a new room gets a fresh allowance of bandwidth, so the
room limits in 4d hold only if rooms cannot be had at will).

CI then runs the step-1 Playwright test against the container (moved here from step 4): it
asks the container for a room's credentials on 8081 and opens a data channel through it, in
Chrome and Firefox, over UDP and TCP.

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
  - `compose.json`: `ports: ["3478:3478/udp", "3478:3478/tcp"]`, `OUTPOST_PUBLIC_IP` set to
    the VPS's address, and proxy alias `outpost-web`,
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
