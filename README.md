# outpost

TURN relay for NESER network play. When two players' networks cannot be connected directly
(both on mobile networks, carrier-grade NAT, strict work networks), their browsers send the game
through outpost instead. outpost relays only between the two players of one room, never to any
other address. How it gets there is in [PLAN.md](PLAN.md).

So far outpost is a STUN server (RFC 8489) that also hands out TURN allocations (RFC 8656):
- a Binding request is answered with the address it came from, which tells a browser its public
  address;
- Allocate and Refresh need a room's credentials (the long-term credential mechanism, realm
  `outpost`). A room is one username and password, shared by its two players, and holds at
  most eight allocations: a browser allocates once per TURN URL and network interface, and a
  reloaded page leaves its old allocation behind until it expires. Relaying data between them comes in PLAN.md step 4b.

How it answers, over UDP and TCP alike:
- every response ends in a FINGERPRINT and names `outpost` as its SOFTWARE;
- a request whose FINGERPRINT fails is dropped, as is anything that is not a request, or a
  request for a method outpost does not serve;
- a request carrying a comprehension-required attribute outpost does not know gets a 420 (Unknown
  Attribute) naming it;
- a TURN request without a valid login is challenged with a 401 carrying the realm and a nonce.
  The nonce is tied to the client's address and transport and lasts an hour, then draws a 438;
- an allocation is UDP over IPv4 only. It lasts 10 minutes unless the client asks for longer
  (at most an hour), and it ends with a Refresh of lifetime 0, or when its TCP connection
  closes. Relayed ports are picked at random from 49152–65535. Nothing listens on them,
  because an allocation is reached only through outpost.

## Running

```sh
cargo run                      # HTTP on 0.0.0.0:8080, STUN/TURN on 0.0.0.0:3478 (UDP and TCP)
cargo test                     # unit and end-to-end tests
```

| Environment variable | Default | Meaning |
|---|---|---|
| `OUTPOST_REVISION` | `unknown` | Source commit served from `/release.json`; the image sets it at build time. |
| `OUTPOST_PUBLIC_IP` | `127.0.0.1` | The IPv4 address players reach port 3478 at. Relayed addresses are given on it, so production must set it; the startup log shows the one in use. |

## Ports

| Port | What |
|---|---|
| `8080/tcp` | HTTP, behind Caddy at `outpost.rmstdope.eu`. |
| `3478/udp`, `3478/tcp` | STUN and TURN, published straight to the internet. Over TCP, messages follow each other with no other framing; anything that is not STUN closes the connection. |

## HTTP endpoints

| Path | Answer |
|---|---|
| `GET /` | A short page saying what outpost is, linking to NESER |
| `GET /healthz` | `200 ok` when the UDP port answers a Binding request within a second, `503` otherwise |
| `GET /release.json` | `{"revision":"<commit>"}`, never cached |

## Deployment

CI (`.github/workflows/ci.yml`) checks formatting, runs clippy and every test, then builds the
amd64 image, starts it with port 3478 published over UDP and TCP and probes it: health,
`/release.json`, the non-root user, a Binding request over each transport
(`cargo run --example smoke -- 127.0.0.1:13478`) and a quick clean stop. On `main` it then pushes
that tested image to `ghcr.io/rmstdope/outpost` and uploads the `deployment-manifest` artifact
that `rmstdope-infra` deploys.

Unlike liaison, outpost publishes a port of its own and a restart drops the games it is relaying,
so it is a reviewed definition in `rmstdope-infra` and released by hand, never automatically
(PLAN.md steps 6 and 7).

The STUN message code is our own (`src/stun.rs`): the subset outpost needs is small. It is
checked against the sample messages of RFC 5769, and uses crates only for MD5, HMAC-SHA1 and
CRC32.
