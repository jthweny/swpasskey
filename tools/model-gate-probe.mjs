#!/usr/bin/env node
// Probe OpenAI's accepted-model gate: for each AAGUID, claim it in authData (via
// the bridge's claim file) and press Add, then read whether a credential appeared.
//
//   node tools/model-gate-probe.mjs <aaguid> [<aaguid>...]
//   node tools/model-gate-probe.mjs --from-mds /tmp/mds.jwt --limit 10
//
// Requires: daemon up, bridge running with SWPASSKEY_BRIDGE_AAGUID_FILE=/tmp/claim.txt,
// a signed-in OpenAI security-methods tab, and Chrome on --remote-debugging-port.
import { writeFileSync, readFileSync, appendFileSync } from "node:fs";

const CDP = process.env.CDP_URL || "http://127.0.0.1:9222";
const CLAIM_FILE = process.env.SWPK_CLAIM_FILE || "/tmp/claim.txt";
const OUT = "research/model-gate.jsonl";
const PAGE_MATCH = process.env.SWPK_PAGE || "secure-methods";

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function session() {
  const targets = await (await fetch(CDP + "/json")).json();
  const page = targets.find((t) => t.type === "page" && (t.url || "").includes(PAGE_MATCH));
  if (!page) throw new Error(`no page matching "${PAGE_MATCH}"`);
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", () => res());
    ws.addEventListener("error", () => rej(new Error("ws error")));
  });
  let id = 1;
  const pending = new Map();
  ws.addEventListener("message", (e) => {
    const m = JSON.parse(e.data);
    const entry = pending.get(m.id);
    if (!entry) return;
    pending.delete(m.id);
    m.error ? entry.reject(new Error(m.error.message)) : entry.resolve(m.result);
  });
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const i = id++;
      pending.set(i, { resolve, reject });
      ws.send(JSON.stringify({ id: i, method, params }));
      setTimeout(() => { if (pending.delete(i)) reject(new Error(method + " timeout")); }, 40000);
    });
  return { send, close: () => ws.close() };
}

const PROBE = `(async () => {
  const list = async () => (await (await fetch('/api/accounts/advanced-account-security/passkeys', {credentials:'include'})).json()).passkeys;
  const before = await list();
  const btn = [...document.querySelectorAll('button')].find(b => /^Add$/i.test((b.textContent||'').trim()));
  if (!btn) return { error: 'no Add button' };
  btn.click();
  await new Promise(r => setTimeout(r, 9000));
  const after = await list();
  const alert = document.querySelector('[role="alert"]');
  const newest = after[0] || {};
  return {
    added: after.length - before.length,
    name: newest.authenticator_name || null,
    sk: newest.is_security_key,
    hw: newest.is_non_exportable_hardware_key,
    alert: alert ? alert.textContent.slice(0, 60) : null,
  };
})()`;

const candidatesFromMds = (path, limit) => {
  const raw = readFileSync(path, "utf8");
  const payload = raw.split(".")[1] || raw;
  const blob = JSON.parse(Buffer.from(payload, "base64url").toString());
  const out = [];
  for (const e of blob.entries) {
    const st = e.metadataStatement || {};
    const kp = st.keyProtection || [];
    const aaguid = e.aaguid || st.aaguid;
    if (!aaguid) continue;
    if (!kp.some((k) => k === "hardware" || k === "secure_element")) continue;
    const status = (e.statusReports || []).map((s) => s.status);
    if (!status.some((s) => s.startsWith("FIDO_CERTIFIED"))) continue;
    const desc = st.description || "";
    if (/YubiKey|Titan|Feitian|GoTrust|Token|Thales|HID|G\\+D|Excelsecu|Swissbit|uTrust|OneSpan|WiSECURE|authenton|VinCSS/i.test(desc)) {
      out.push({ aaguid, desc });
      if (out.length >= limit) break;
    }
  }
  return out;
};

const args = process.argv.slice(2);
let targets = args.filter((a) => !a.startsWith("--"));
if (args.includes("--from-mds")) {
  const path = args[args.indexOf("--from-mds") + 1] || "/tmp/mds.jwt";
  const limit = Number(args[args.indexOf("--limit") + 1] || 8) || 8;
  targets = candidatesFromMds(path, limit).map((c) => c.aaguid);
}

const s = await session();
try {
  for (const aaguid of targets) {
    writeFileSync(CLAIM_FILE, aaguid + "\n");
    await wait(600);
    const r = await s.send("Runtime.evaluate", { expression: PROBE, awaitPromise: true, returnByValue: true });
    const out = r.result && r.result.value ? r.result.value : { error: "no result" };
    const row = { t: new Date().toISOString(), aaguid, ...out };
    appendFileSync(OUT, JSON.stringify(row) + "\n");
    console.log(`${aaguid}  added=${out.added} name=${out.name || "-"} sk=${out.sk} hw=${out.hw} ${out.alert ? "alert" : ""}`);
  }
} finally {
  s.close();
}
