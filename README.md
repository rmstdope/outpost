# outpost

TURN relay for NESER network play. When two players' networks cannot be connected directly
(both on mobile networks, carrier-grade NAT, strict work networks), their browsers send the game
through outpost instead. outpost relays only between the two players of one room, never to any
other address. How it gets there is in [PLAN.md](PLAN.md).

outpost is a STUN server (RFC 8489) and a TURN relay (RFC 8656) whose relaying never leaves the
room:
- a Binding request is answered with the address it came from, which tells a browser its public
  address;
- Allocate and Refresh need a room's credentials (the long-term credential mechanism, realm
  `outpost`). A room is one username and password, shared by its two players, and holds at
  most eight allocations: a browser allocates once per TURN URL and network interface, and a
  reloaded page leaves its old allocation behind until it expires;
- data sent with a Send indication or on a channel (ChannelBind and ChannelData) reaches
  another allocation of the same room, if each has a permission for the other. It arrives on
  the receiver's channel to the sender if it has bound one, padded to four bytes over TCP, and
  as a Data indication otherwise. Anything else is dropped: data never goes to any other
  address, inside the VPS or on the internet.

How it answers, over UDP and TCP alike:
- every response ends in a FINGERPRINT and names `outpost` as its SOFTWARE;
- a request whose FINGERPRINT fails is dropped, as is anything that is not a request, or a
  request for a method outpost does not serve;
- a request carrying a comprehension-required attribute outpost does not know gets a 420 (Unknown
  Attribute) naming it;
- a TURN request without a valid login is challenged with a 401 carrying the realm and a nonce.
  The nonce is tied to the client's address and transport and lasts an hour, then draws a 438;
- a permission is for an IPv4 address and lasts five minutes unless renewed; a channel binding
  lasts ten minutes and also installs a permission. An allocation holds at most 64 of each. Every relayed address shares `OUTPOST_PUBLIC_IP`, so the room rule is
  applied when data is sent, not when permissions are given;
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

## Limits

Set in `src/limit.rs` (`Limits`); none can be changed without a new build.

| Limit | Value | Beyond it |
|---|---|---|
| Allocations in a room | 8 | 486 |
| Allocations from one IP address | 16 | 486 |
| Allocations in all | 1000 | 508 |
| Permissions, and channels, per allocation | 64 each | 508 |
| Bytes one room relays, both players together, each message counted as its data plus 36 bytes | 512 KiB/s, bursts of 2 MiB | dropped |
| TCP connections from one IP address, and in all | 16, and 1000 | closed at once |
| A TCP connection sending no whole message | 120 s | closed |
| A TCP connection without an allocation, from when it opened | 30 s | closed |
| Answers over UDP to one IP address, to requests that did not log in | 20 a second, bursts of 40 | dropped |
| IP addresses those answers are tracked for | 100,000; beyond that, new ones share 1000 a second | dropped |
| A message, over UDP or TCP | 2048 bytes | dropped, or the TCP connection closed |

A game sends a few kilobytes a second, so the bandwidth leaves room for a ROM to cross in
seconds. It is kept per room, so allocating again does not refill it.

The UDP answer limit is there because a UDP source can be forged: without it, outpost could be
used to flood someone else with its answers. Answers to requests that logged in are not
counted, since their nonce is tied to the address they came from and nobody else can produce
one. So a flood of forged requests cannot cut a player off from their own allocation.

Known limits of the limits:
- Behind carrier-grade NAT (mobile networks, campuses), unrelated players share one IP
  address and its per-address limits.
- Nothing caps the total bandwidth: 1000 allocations could ask for more than the VPS's link.
  The link and its monthly transfer allowance are the real ceiling.
- The per-address limits are for IPv4, which is all outpost listens on. Listening on IPv6
  would need them per /64, since one host can have many addresses.

## Ports

| Port | What |
|---|---|
| `8080/tcp` | HTTP, behind Caddy at `outpost.rmstdope.eu`. |
| `3478/udp`, `3478/tcp` | STUN and TURN, published straight to the internet. A message may be at most 2048 bytes. Over TCP, messages follow each other with no other framing; anything that is not STUN, or is longer, closes the connection. |

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
