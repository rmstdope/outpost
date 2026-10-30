# outpost

TURN relay for NESER network play. When two players' networks cannot be connected directly
(both on mobile networks, carrier-grade NAT, strict work networks), their browsers send the game
through outpost instead. outpost relays only between the two players of one room, never to any
other address. How it gets there is in [PLAN.md](PLAN.md).

So far outpost answers STUN Binding requests (RFC 8489), which tell a browser its public address.
The relay itself comes in PLAN.md step 4.

## Running

```sh
cargo run                      # HTTP on 0.0.0.0:8080, STUN/TURN on 0.0.0.0:3478 (UDP and TCP)
cargo test                     # unit and end-to-end tests
```

| Environment variable | Default | Meaning |
|---|---|---|
| `OUTPOST_REVISION` | `unknown` | Source commit served from `/release.json`; the image sets it at build time. |

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

The STUN message code is our own (`src/stun.rs`): the subset outpost needs is small.
