#!/usr/bin/env node
// Poll the account's credential classification and log any change.
//
//   node tools/flag-poller.mjs [--minutes 60] [--every 5]
//
// Users report the hardware verdict updating late ("a delayed/backend state update
// rather than the verification being permanently rejected"), so a single read is
// not evidence. Requires a signed-in security-methods tab in the debuggable Chrome.
import { appendFileSync } from "node:fs";

const CDP = process.env.CDP_URL || `http://127.0.0.1:${process.env.CDP_PORT || 9222}`;
const OUT = "research/flag-timeline.jsonl";
const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf("--" + n); return i >= 0 ? args[i + 1] : d; };
const minutes = Number(opt("minutes", 60));
const every = Number(opt("every", 5));
const match = process.env.SWPK_PAGE || "secure-methods";

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function attach() {
  const targets = await (await fetch(CDP + "/json/list")).json();
  const page = targets.find((t) => t.type === "page" && (t.url || "").includes(match));
  if (!page) throw new Error(`no page matching "${match}"`);
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", () => res());
    ws.addEventListener("error", () => rej(new Error("ws error")));
  });
  let id = 1;
  const pending = new Map();
  ws.addEventListener("message", (e) => {
    const m = JSON.parse(e.data);
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result);
  });
  const evaluate = (expression) =>
    new Promise((resolve, reject) => {
      const i = id++;
      pending.set(i, { resolve, reject });
      ws.send(JSON.stringify({ id: i, method: "Runtime.evaluate",
        params: { expression, awaitPromise: true, returnByValue: true } }));
      setTimeout(() => { if (pending.delete(i)) reject(new Error("evaluate timeout")); }, 30000);
    });
  return { evaluate, close: () => ws.close() };
}

const READ = `(async () => {
  const res = await fetch('/api/accounts/advanced-account-security/passkeys', {credentials:'include'});
  if (!res.ok) return { status: res.status, session: res.status === 409 ? 'expired' : 'error' };
  const pk = await res.json();
  return { status: 200, total: pk.passkeys.length,
           hardware: pk.passkeys.filter(p => p.is_non_exportable_hardware_key).map(p => p.authenticator_name),
           securityKeys: pk.passkeys.filter(p => p.is_security_key).length };
})()`;

const deadline = Date.now() + minutes * 60000;
let last = "";
while (Date.now() < deadline) {
  try {
    const s = await attach();
    const r = await s.evaluate(READ);
    s.close();
    const v = r.result && r.result.value ? r.result.value : { error: "no result" };
    const line = JSON.stringify({ t: new Date().toISOString(), ...v });
    if (line !== last) { appendFileSync(OUT, line + "\n"); console.log(line); last = line; }
    if (v.hardware && v.hardware.length) { console.log("HARDWARE FLAG SET:", v.hardware.join(", ")); break; }
  } catch (e) {
    console.log(JSON.stringify({ t: new Date().toISOString(), error: String(e) }));
  }
  await wait(every * 60000);
}
