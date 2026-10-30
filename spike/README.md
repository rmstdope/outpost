# Spike: a room-only relay (PLAN.md step 1)

Throwaway code that answered one question before outpost is built: **do browsers accept a TURN
relay that forwards only between its own allocations, inside one process, through one port?**

- `relay/`: the smallest TURN relay (RFC 8656) that does this, over UDP. It has one fixed user
  and one room, and no limits.
- `browser/spike.mjs`: two headless browser pages open a WebRTC data channel through the relay
  and report the candidate pair that carried it.

```sh
(cd relay && cargo build && PUBLIC_IP=<address> target/debug/relay-spike)
(cd browser && npm install && npx playwright install chromium firefox \
  && BROWSER=chromium node spike.mjs "turn:<address>:3478?transport=udp")
```

## Result (2026-10-30): yes

| Where | Browser | Both relay-only | Relay-only + any path | Open after answer |
|---|---|---|---|---|
| This Mac, LAN address | Chrome | pass | pass | 68–81 ms |
| This Mac, LAN address | Firefox | pass | pass | 35–55 ms |
| VPS, in Docker, UDP 3478 published | Chrome | pass | pass | 175–260 ms |
| VPS, in Docker, UDP 3478 published | Firefox | pass | pass | 211–383 ms |

Every run chose relay↔relay. In the "any path" runs the browser also tried the other player's
own address, the relay dropped it ("not an allocation here"), and ICE moved on to relay↔relay.

What was learned:
- **The room rule works with real browsers**, and the relay needs only one published port.
- **Docker's published UDP port keeps the player's real address**: the relay on the VPS saw the
  Mac's public address, not a Docker-internal one. Hostup's network lets UDP 3478 through without
  a UFW change, because Docker bypasses UFW.
- **Firefox ignores loopback addresses** for ICE unless configured otherwise. Tests must use a
  real interface address, or set `media.peerconnection.ice.loopback`.
- In one early Firefox run the first allocation took seven 401 challenges before succeeding. It
  did not happen again; step 4 should test that an allocation succeeds after one challenge.
- Building amd64 images on this arm64 Mac with the legacy Docker builder fails. Step 2's CI
  builds the real image on GitHub's amd64 runners instead.
