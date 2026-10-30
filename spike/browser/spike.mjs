// Spike for PLAN.md step 1: two headless Chrome pages open a WebRTC data channel through the
// spike relay, and report which candidate pair carried it.
// Usage: node spike.mjs <turn-url>     e.g. turn:127.0.0.1:3478?transport=udp

import { chromium, firefox } from "playwright";

const turn = process.argv[2] ?? "turn:127.0.0.1:3478?transport=udp";

async function peer(browser, policy) {
    const page = await (await browser.newContext()).newPage();
    page.on("console", (message) => console.log(`[${policy}] ${message.text()}`));
    await page.evaluate(
        ({ turn, policy }) => {
            window.pc = new RTCPeerConnection({
                iceServers: [{ urls: turn, username: "spike", credential: "spike" }],
                iceTransportPolicy: policy,
            });
            window.gathered = () =>
                new Promise((resolve) => {
                    if (pc.iceGatheringState === "complete") return resolve();
                    pc.addEventListener("icegatheringstatechange", () => {
                        if (pc.iceGatheringState === "complete") resolve();
                    });
                });
            window.selectedPair = async () => {
                const stats = [...(await pc.getStats()).values()];
                const transport = stats.find((s) => s.type === "transport");
                // Chrome names the pair on the transport; Firefox marks the pair itself.
                const pair =
                    stats.find((s) => s.id === transport?.selectedCandidatePairId) ??
                    stats.find((s) => s.type === "candidate-pair" && s.selected);
                const local = stats.find((s) => s.id === pair?.localCandidateId);
                const remote = stats.find((s) => s.id === pair?.remoteCandidateId);
                return `${local?.candidateType}(${local?.address}:${local?.port}) <-> ${remote?.candidateType}(${remote?.address}:${remote?.port})`;
            };
        },
        { turn, policy }
    );
    return page;
}

async function scenario(browser, hostPolicy, joinerPolicy) {
    const host = await peer(browser, hostPolicy);
    const joiner = await peer(browser, joinerPolicy);
    const offer = await host.evaluate(async () => {
        window.channel = pc.createDataChannel("spike");
        window.pong = new Promise((resolve) => {
            channel.onopen = () => channel.send("ping");
            channel.onmessage = (event) => resolve(event.data);
        });
        await pc.setLocalDescription();
        await gathered();
        const candidates = pc.localDescription.sdp.split("\n").filter((l) => l.startsWith("a=candidate"));
        console.log(`host candidates: ${candidates.map((c) => c.split(" ")[7]).join(", ")}`);
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
    const started = Date.now();
    await host.evaluate((sdp) => pc.setRemoteDescription({ type: "answer", sdp }), answer);
    const reply = await host.evaluate(() =>
        Promise.race([pong, new Promise((resolve) => setTimeout(() => resolve("timeout"), 15000))])
    );
    const pairs = reply === "pong" ? [await host.evaluate(() => selectedPair()), await joiner.evaluate(() => selectedPair())] : [];
    await host.context().close();
    await joiner.context().close();
    const ms = Date.now() - started;
    return { name: `host ${hostPolicy} / joiner ${joinerPolicy} (${ms} ms after answer)`, ok: reply === "pong", pairs };
}

const browser = await (process.env.BROWSER === "firefox" ? firefox : chromium).launch();
const results = [await scenario(browser, "relay", "relay"), await scenario(browser, "relay", "all")];
await browser.close();
for (const { name, ok, pairs } of results) {
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${pairs.length ? `\n      host:   ${pairs[0]}\n      joiner: ${pairs[1]}` : ""}`);
}
process.exit(results.every((r) => r.ok) ? 0 : 1);
