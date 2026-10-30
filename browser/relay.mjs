// Two browser pages open a WebRTC data channel through a running outpost and nothing else:
// `node relay.mjs <rooms-url>`, e.g. `node relay.mjs http://127.0.0.1:18081/rooms`.
//
// For Chrome and Firefox, over UDP and over TCP, it asks outpost for a room and runs two
// cases: both pages relay-only, and one relay-only with the other free to use any path. Every
// case must open the channel relay to relay, through outpost. The TURN address must not be a
// loopback address, which Firefox ignores.

import { chromium, firefox } from "playwright";

const roomsUrl = process.argv[2] ?? "http://127.0.0.1:8081/rooms";

async function openRoom(transport) {
    const response = await fetch(roomsUrl, { method: "POST" });
    if (!response.ok) throw new Error(`POST ${roomsUrl}: ${response.status}`);
    const server = await response.json();
    return { ...server, urls: server.urls.filter((url) => url.endsWith(`transport=${transport}`)) };
}

async function page(browser, iceServer, policy) {
    const page = await (await browser.newContext()).newPage();
    await page.evaluate(
        ({ iceServer, policy }) => {
            window.pc = new RTCPeerConnection({ iceServers: [iceServer], iceTransportPolicy: policy });
            // Gathering that does not finish in time fails the case rather than hanging the run.
            window.gathered = () =>
                new Promise((resolve, reject) => {
                    if (pc.iceGatheringState === "complete") return resolve();
                    const timer = setTimeout(() => reject(new Error("gathering did not finish in 15 s")), 15000);
                    pc.addEventListener("icegatheringstatechange", () => {
                        if (pc.iceGatheringState === "complete") {
                            clearTimeout(timer);
                            resolve();
                        }
                    });
                });
            window.state = () => {
                const types = pc.localDescription?.sdp
                    .split("\n")
                    .filter((line) => line.startsWith("a=candidate"))
                    .map((line) => line.split(" ")[7]);
                return `ice ${pc.iceConnectionState}, gathered ${types?.join(" ") || "nothing"}`;
            };
            window.selectedPair = async () => {
                const stats = [...(await pc.getStats()).values()];
                const transport = stats.find((s) => s.type === "transport");
                // Chrome names the pair on the transport; Firefox marks the pair itself.
                const pair =
                    stats.find((s) => s.id === transport?.selectedCandidatePairId) ??
                    stats.find((s) => s.type === "candidate-pair" && s.selected);
                const type = (id) => stats.find((s) => s.id === id)?.candidateType;
                return `${type(pair?.localCandidateId)}<->${type(pair?.remoteCandidateId)}`;
            };
        },
        { iceServer, policy }
    );
    return page;
}

async function connect(browser, iceServer, hostPolicy, joinerPolicy) {
    const host = await page(browser, iceServer, hostPolicy);
    const joiner = await page(browser, iceServer, joinerPolicy);
    try {
        const offer = await host.evaluate(async () => {
            window.channel = pc.createDataChannel("outpost");
            window.pong = new Promise((resolve) => {
                channel.onopen = () => channel.send("ping");
                channel.onmessage = (event) => resolve(event.data);
            });
            await pc.setLocalDescription();
            await gathered();
            return pc.localDescription.sdp;
        });
        const answer = await joiner.evaluate(async (sdp) => {
            pc.ondatachannel = ({ channel }) => {
                channel.onmessage = (event) => event.data === "ping" && channel.send("pong");
            };
            await pc.setRemoteDescription({ type: "offer", sdp });
            await pc.setLocalDescription();
            await gathered();
            return pc.localDescription.sdp;
        }, offer);
        await host.evaluate((sdp) => pc.setRemoteDescription({ type: "answer", sdp }), answer);
        const reply = await host.evaluate(() =>
            Promise.race([pong, new Promise((resolve) => setTimeout(() => resolve("timeout"), 15000))])
        );
        const pairs = reply === "pong" ? [await host.evaluate(() => selectedPair()), await joiner.evaluate(() => selectedPair())] : [];
        return { ok: reply === "pong" && pairs.every((pair) => pair === "relay<->relay"), pairs };
    } catch (error) {
        const states = [await host.evaluate(() => state()), await joiner.evaluate(() => state())];
        return { ok: false, pairs: [`${error.message}; host ${states[0]}; joiner ${states[1]}`] };
    } finally {
        await host.context().close();
        await joiner.context().close();
    }
}

let failed = false;
for (const [name, type] of [["chrome", chromium], ["firefox", firefox]]) {
    const browser = await type.launch();
    for (const transport of ["udp", "tcp"]) {
        for (const [hostPolicy, joinerPolicy] of [["relay", "relay"], ["relay", "all"]]) {
            const iceServer = await openRoom(transport);
            const { ok, pairs } = await connect(browser, iceServer, hostPolicy, joinerPolicy);
            failed ||= !ok;
            console.log(`${ok ? "PASS" : "FAIL"}  ${name} over ${transport}, ${hostPolicy}/${joinerPolicy}: ${pairs.join(", ") || "no channel"}`);
        }
    }
    await browser.close();
}
process.exit(failed ? 1 : 0);
