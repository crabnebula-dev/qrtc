// Interop between qrtc (its stdio_peer example) and headless Chromium:
// data channels both ways, and the DTLS key exchange group each side agrees.
//
//   node tests/chromium-interop.mjs
//
// Cases:
//   classical    default Chromium, qrtc Prefer: DTLS 1.2, no post-quantum group
//   pq           Chromium with its DTLS 1.3 and post-quantum field trials,
//                qrtc Prefer: DTLS 1.3 with X25519MLKEM768, both directions
//   pq-require   the same Chromium, qrtc Require: X25519MLKEM768
//   require-fail default Chromium, qrtc Require: the connection must fail
//
// The stdio_peer binary is QRTC_STDIO_PEER, or target/debug/examples/stdio_peer
// (build it with `cargo build --example stdio_peer`). The browser is CHROMIUM,
// or the Chromium that `npx playwright install chromium` put in place.
// Exits non-zero when any case does not behave as described above.
import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = process.env.QRTC_STDIO_PEER || path.join(root, 'target/debug/examples/stdio_peer');
const exe = process.env.CHROMIUM || undefined;
const PQ_TRIALS = '--force-fieldtrials=WebRTC-ForceDtls13/Enabled/WebRTC-EnableDtlsPqc/Enabled/';
const HYBRID = 'X25519MLKEM768';

function startPeer(role, config) {
  const child = spawn(bin, [role], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: { ...process.env, WEBRTC_CONFIG: JSON.stringify(config) },
  });
  const listeners = new Set();
  const early = [];
  createInterface({ input: child.stdout }).on('line', (line) => {
    let m;
    try { m = JSON.parse(line); } catch { return; }
    if (!listeners.size) early.push(m);
    for (const f of listeners) f(m);
  });
  return {
    send: (m) => child.stdin.write(JSON.stringify(m) + '\n'),
    on: (f) => { listeners.add(f); early.splice(0).forEach(f); },
    off: (f) => listeners.delete(f),
    stop: () => child.kill(),
  };
}

// Ask the engine for its stats and return the transport's tlsGroup.
function engineTlsGroup(peer) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { peer.off(f); resolve(undefined); }, 5000);
    const f = (m) => {
      if (m.op !== 'stats') return;
      clearTimeout(timer); peer.off(f);
      const list = Array.isArray(m.stats) ? m.stats : Object.values(m.stats || {});
      const transport = list.find((s) => s && s.type === 'transport');
      resolve(transport ? transport.tlsGroup ?? null : undefined);
    };
    peer.on(f);
    peer.send({ op: 'stats' });
  });
}

// Browser offers; the engine answers and echoes text and binary.
async function browserOffers() {
  const pc = new RTCPeerConnection();
  const queue = [];
  window.fromEngine = async (m) => {
    if (m.op === 'answer') {
      await pc.setRemoteDescription({ type: 'answer', sdp: m.sdp });
      for (const c of queue.splice(0)) await pc.addIceCandidate(c);
    } else if (m.op === 'event' && m.event.type === 'icecandidate' && m.event.candidate) {
      if (pc.remoteDescription) await pc.addIceCandidate(m.event.candidate); else queue.push(m.event.candidate);
    }
  };
  pc.onicecandidate = (e) => { if (e.candidate) toEngine({ op: 'candidate', candidate: e.candidate.toJSON() }); };
  toEngine({ op: 'ready' });
  const dc = pc.createDataChannel('echo');
  dc.binaryType = 'arraybuffer';
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  toEngine({ op: 'offer', sdp: offer.sdp });
  await new Promise((r) => (dc.onopen = r));
  const next = () => new Promise((r) => (dc.onmessage = (e) => r(e.data)));
  dc.send('ping ü 🦀');
  const text = await next();
  const bin = new Uint8Array(1000).map((_, i) => i & 255);
  dc.send(bin);
  const back = new Uint8Array(await next());
  const binOk = back.length === bin.length && back.every((v, i) => v === bin[i]);
  let dtls = {};
  (await pc.getStats()).forEach((s) => {
    if (s.type === 'transport') dtls = { tlsVersion: s.tlsVersion, dtlsCipher: s.dtlsCipher, tlsGroup: s.tlsGroup };
  });
  window.__pc = pc;
  return { ok: text === 'ping ü 🦀' && binOk, text, binOk, browser: dtls };
}

// The engine offers with its own channel; the browser answers.
async function engineOffers() {
  const pc = new RTCPeerConnection();
  const queue = [];
  pc.onicecandidate = (e) => { if (e.candidate) toEngine({ op: 'candidate', candidate: e.candidate.toJSON() }); };
  const got = new Promise((resolve) => {
    pc.ondatachannel = (e) => {
      const ch = e.channel; const msgs = [];
      ch.onmessage = (m) => {
        msgs.push(m.data);
        if (msgs.length === 1) ch.send('ack');
        if (msgs.length === 2) resolve({ label: ch.label, msgs });
      };
    };
  });
  window.fromEngine = async (m) => {
    if (m.op === 'offer') {
      await pc.setRemoteDescription({ type: 'offer', sdp: m.sdp });
      const a = await pc.createAnswer();
      await pc.setLocalDescription(a);
      toEngine({ op: 'answer', sdp: a.sdp });
      for (const c of queue.splice(0)) await pc.addIceCandidate(c);
    } else if (m.op === 'event' && m.event.type === 'icecandidate' && m.event.candidate) {
      if (pc.remoteDescription) await pc.addIceCandidate(m.event.candidate); else queue.push(m.event.candidate);
    }
  };
  toEngine({ op: 'ready' });
  const r = await got;
  let dtls = {};
  (await pc.getStats()).forEach((s) => {
    if (s.type === 'transport') dtls = { tlsVersion: s.tlsVersion, dtlsCipher: s.dtlsCipher, tlsGroup: s.tlsGroup };
  });
  window.__pc = pc;
  return { ok: r.label === 'engine' && r.msgs[0] === 'hello from engine' && r.msgs[1] === 'ack', ...r, browser: dtls };
}

async function runDirection(browser, role, pageFn, config, timeoutMs) {
  const peer = startPeer(role, config);
  const page = await browser.newPage();
  let ready = false;
  const backlog = [];
  const deliver = (m) => page.evaluate((mm) => window.fromEngine && window.fromEngine(mm), m).catch(() => {});
  await page.exposeFunction('toEngine', (m) => {
    if (m.op === 'ready') { ready = true; backlog.splice(0).forEach(deliver); } else peer.send(m);
  });
  peer.on((m) => {
    if (m.op === 'fatal') console.log(`  engine fatal: ${m.error}`);
    if (ready) deliver(m); else backlog.push(m);
  });
  let result;
  try {
    result = await Promise.race([
      page.evaluate(pageFn),
      new Promise((_, reject) => setTimeout(() => reject(new Error(`timeout ${timeoutMs / 1000}s`)), timeoutMs)),
    ]);
    result.engineTlsGroup = await engineTlsGroup(peer);
  } catch (e) {
    result = { ok: false, error: String(e.message || e) };
  }
  await page.evaluate(() => window.__pc && window.__pc.close()).catch(() => {});
  peer.send({ op: 'close' });
  await page.close();
  peer.stop();
  return result;
}

const cases = [
  { name: 'classical', args: [], config: { postQuantum: 'prefer' }, expect: 'classical' },
  { name: 'pq', args: [PQ_TRIALS], config: { postQuantum: 'prefer' }, expect: 'pq' },
  { name: 'pq-require', args: [PQ_TRIALS], config: { postQuantum: 'require' }, expect: 'pq' },
  { name: 'require-fail', args: [], config: { postQuantum: 'require' }, expect: 'fail' },
];

const report = {};
let failed = false;
for (const c of cases) {
  const browser = await chromium.launch({
    executablePath: exe,
    args: ['--disable-features=WebRtcHideLocalIpsWithMdns', ...c.args],
  });
  const timeout = c.expect === 'fail' ? 15000 : 30000;
  const directions = {
    'browser-offers': await runDirection(browser, 'answerer', browserOffers, c.config, timeout),
    'engine-offers': await runDirection(browser, 'offerer', engineOffers, c.config, timeout),
  };
  await browser.close();
  const pass = Object.values(directions).every((r) => {
    if (c.expect === 'fail') return !r.ok;
    if (!r.ok) return false;
    // Chromium reports the DTLS version as hex: FEFC is 1.3, FEFD is 1.2.
    if (c.expect === 'pq') return r.engineTlsGroup === HYBRID && r.browser?.tlsVersion === 'FEFC';
    // Classical: DTLS 1.2, where the engine reports no post-quantum group.
    return r.engineTlsGroup == null && r.browser?.tlsVersion === 'FEFD';
  });
  report[c.name] = { pass, expect: c.expect, directions };
  console.log(`${pass ? 'ok  ' : 'FAIL'} ${c.name}: ${Object.entries(directions)
    .map(([d, r]) => `${d} ${r.ok ? 'connected' : 'no connection'}, engine group ${r.engineTlsGroup ?? 'none'}${r.browser?.tlsVersion ? `, browser ${r.browser.tlsVersion}` : ''}`)
    .join('; ')}`);
  if (!pass) failed = true;
}

console.log(JSON.stringify(report, null, 2));
process.exit(failed ? 1 : 0);
