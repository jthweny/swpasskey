#!/usr/bin/env node
// Drive a real, already-signed-in Chrome over the DevTools protocol: find the
// page's security-key control, press it, and report what the ceremony produced.
//
// Zero dependencies: Node's global fetch and WebSocket speak CDP directly.
//
//   # once per browser session
//   open -na "Google Chrome" --args --remote-debugging-port=9222
//
//   node tools/drive/drive.mjs pages
//   node tools/drive/drive.mjs status
//   node tools/drive/drive.mjs find    --url openai
//   node tools/drive/drive.mjs press   --url openai
//   node tools/drive/drive.mjs flow    --url openai --shot /tmp/after.png
//
// Exit codes: 0 ok, 1 nothing found / nothing happened, 2 cannot reach Chrome.
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

const CDP = process.env.CDP_URL || "http://127.0.0.1:9222";
const ROOT = new URL("../..", import.meta.url).pathname.replace(/\/$/, "");
const BRIDGE = process.env.SWPASSKEY_BRIDGE || "http://localhost:3000";
const BRIDGE_LOG = process.env.SWPASSKEY_BRIDGE_LOG || "/tmp/bridge.log";
const CTL = process.env.SWPASSKEY_CTL_SOCKET || "/tmp/swpk-bridge.sock";

const argv = process.argv.slice(2);
const cmd = argv[0] || "status";
const opt = (name, def) => {
  const i = argv.indexOf("--" + name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : def;
};

// ------------------------------------------------------------------ CDP client
class Session {
  static async open(urlFilter) {
    let targets;
    try {
      targets = await (await fetch(CDP + "/json")).json();
    } catch (err) {
      console.error(`cannot reach Chrome at ${CDP} (start it with --remote-debugging-port=9222)`);
      process.exit(2);
    }
    const pages = targets.filter((t) => t.type === "page" && t.webSocketDebuggerUrl);
    if (pages.length === 0) {
      console.error("Chrome is reachable but has no page targets");
      process.exit(2);
    }
    const match = urlFilter
      ? pages.filter((t) => (t.url || "").includes(urlFilter))
      : pages;
    if (match.length === 0) {
      console.error(`no page matching "${urlFilter}". Open tabs:`);
      for (const p of pages) console.error("  " + p.url);
      process.exit(1);
    }
    return new Session(match[0]);
  }

  constructor(target) {
    this.target = target;
    this.nextId = 1;
    this.pending = new Map();
    this.ws = new WebSocket(target.webSocketDebuggerUrl);
    this.ready = new Promise((resolve, reject) => {
      this.ws.addEventListener("open", () => resolve());
      this.ws.addEventListener("error", (e) => reject(new Error("ws error: " + e.message)));
    });
    this.ws.addEventListener("message", (event) => {
      const msg = JSON.parse(event.data);
      const entry = this.pending.get(msg.id);
      if (!entry) return;
      this.pending.delete(msg.id);
      if (msg.error) entry.reject(new Error(msg.error.message));
      else entry.resolve(msg.result);
    });
  }

  async send(method, params = {}) {
    await this.ready;
    const id = this.nextId++;
    const payload = JSON.stringify({ id, method, params });
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(payload);
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`${method} timed out`));
      }, 30000);
    });
  }

  watchConsole(sink) {
    this.ws.addEventListener("message", (event) => {
      const msg = JSON.parse(event.data);
      if (msg.method === "Runtime.consoleAPICalled") {
        const text = (msg.params.args || [])
          .map((a) => a.value ?? a.description ?? a.type)
          .join(" ");
        sink(`console.${msg.params.type}: ${text}`.slice(0, 300));
      } else if (msg.method === "Runtime.exceptionThrown") {
        const d = msg.params.exceptionDetails;
        sink(`exception: ${(d.exception?.description || d.text || "").slice(0, 400)}`);
      }
    });
    return this.send("Runtime.enable", {});
  }

  async evaluate(expression) {
    const res = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.exception?.description || "evaluation failed");
    }
    return res.result.value;
  }

  async shot(path) {
    const res = await this.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(path, Buffer.from(res.data, "base64"));
    return path;
  }

  close() {
    try {
      this.ws.close();
    } catch (e) {
      /* ignore */
    }
  }
}

// --------------------------------------------------------------- page scripts
const SCAN = String.raw`
(() => {
  const CANDIDATE = /(security\s*key|passkey|add\s*(a\s*)?(security\s*)?key|create\s*(a\s*)?passkey|use\s*(a\s*)?security\s*key)/i;
  const REJECT = /(delete|remove|rename|cancel|sign out|log out|revoke|learn more)/i;
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 4 && r.height > 4 && s.visibility !== "hidden" && s.display !== "none";
  };
  const label = (el) => [el.innerText || el.textContent || "", el.getAttribute("aria-label") || "",
                         el.getAttribute("title") || ""].join(" ").replace(/\s+/g, " ").trim();
  const els = [...document.querySelectorAll('button, a, [role="button"], input[type="button"], [role="menuitem"]')];
  return els.filter(visible).map((el, i) => {
    const text = label(el);
    let score = 0;
    if (CANDIDATE.test(text)) score += 10;
    if (/add/i.test(text)) score += 4;
    if (/security\s*key/i.test(text)) score += 4;
    if (REJECT.test(text)) score -= 20;
    if (text.length > 90) score -= 2;
    return { i, text: text.slice(0, 90), score, tag: el.tagName.toLowerCase(),
             disabled: !!el.disabled, aria: el.getAttribute("aria-label") || "" };
  }).filter(c => c.score > 0).sort((a, b) => b.score - a.score).slice(0, 8);
})()`;

const PRESS = (index) => String.raw`
(() => {
  const CANDIDATE = /(security\s*key|passkey|add\s*(a\s*)?(security\s*)?key|create\s*(a\s*)?passkey|use\s*(a\s*)?security\s*key)/i;
  const REJECT = /(delete|remove|rename|cancel|sign out|log out|revoke|learn more)/i;
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 4 && r.height > 4 && s.visibility !== "hidden" && s.display !== "none";
  };
  const label = (el) => [el.innerText || el.textContent || "", el.getAttribute("aria-label") || "",
                         el.getAttribute("title") || ""].join(" ").replace(/\s+/g, " ").trim();
  const els = [...document.querySelectorAll('button, a, [role="button"], input[type="button"], [role="menuitem"]')]
    .filter(visible).map((el, i) => {
      const text = label(el);
      let score = 0;
      if (CANDIDATE.test(text)) score += 10;
      if (/add/i.test(text)) score += 4;
      if (/security\s*key/i.test(text)) score += 4;
      if (REJECT.test(text)) score -= 20;
      if (text.length > 90) score -= 2;
      return { el, text, score };
    }).filter(c => c.score > 0).sort((a, b) => b.score - a.score);
  const pick = els[${index}];
  if (!pick) return { pressed: false, reason: "no candidate at that index" };
  pick.el.scrollIntoView({ block: "center" });
  pick.el.style.outline = "2px solid #8fd0bd";
  pick.el.click();
  return { pressed: true, text: pick.text.slice(0, 90) };
})()`;

// ----------------------------------------------------------------- commands
const status = async () => {
  let health = "(no answer)";
  try {
    health = JSON.stringify(await (await fetch(BRIDGE + "/health")).json());
  } catch (e) {
    health = `unreachable at ${BRIDGE}`;
  }
  let attestation = "(ctl unavailable)";
  try {
    attestation = execFileSync("build/debug/swpasskeyctl",
      ["--socket", CTL, "attestation"], { cwd: ROOT, encoding: "utf8" }).trim();
  } catch (e) {
    /* keep the placeholder */
  }
  console.log("bridge health:", health);
  console.log("attestation:  ", attestation.slice(0, 300));
};

const pages = async () => {
  const targets = await (await fetch(CDP + "/json")).json();
  for (const t of targets.filter((x) => x.type === "page")) {
    console.log(`${(t.title || "").slice(0, 50).padEnd(52)} ${t.url.slice(0, 90)}`);
  }
};

const find = async (url) => {
  const s = await Session.open(url);
  try {
    const candidates = await s.evaluate(SCAN);
    console.log(`page: ${s.target.url}`);
    if (candidates.length === 0) {
      console.log("no matching control on this screen");
      process.exit(1);
    }
    candidates.forEach((c, i) => console.log(`  [${i}] ${c.score.toString().padStart(3)} ${c.tag.padEnd(8)} "${c.text}"${c.disabled ? " (disabled)" : ""}`));
  } finally {
    s.close();
  }
};

const press = async (url, index) => {
  const s = await Session.open(url);
  try {
    const result = await s.evaluate(PRESS(index));
    console.log(result.pressed ? `pressed: "${result.text}"` : `not pressed: ${result.reason}`);
    if (!result.pressed) process.exit(1);
  } finally {
    s.close();
  }
};

const flow = async (url, shotPath, watch) => {
  const before = readLogLines();
  const s = await Session.open(url);
  if (watch) {
    await s.watchConsole((line) => console.log("  " + line));
  }
  let marker;
  try {
    const candidates = await s.evaluate(SCAN);
    if (candidates.length === 0) {
      console.log("no candidate; open the security-key screen first");
      process.exit(1);
    }
    console.log(`candidate: "${candidates[0].text}"`);
    marker = await s.evaluate(PRESS(0));
    console.log(marker.pressed ? `pressed: "${marker.text}"` : "not pressed");
    if (!marker.pressed) process.exit(1);

    const deadline = Date.now() + 20000;
    let lines = [];
    while (Date.now() < deadline) {
      lines = readLogLines().slice(before.length);
      if (lines.some((l) => /\[bridge\] (create|get|ERROR)/.test(l))) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    if (shotPath) {
      await new Promise((r) => setTimeout(r, 800));
      console.log("screenshot:", await s.shot(shotPath));
    }
    const relevant = lines.filter((l) => /\[bridge\] (request|create|get|ERROR)/.test(l));
    if (relevant.length === 0) {
      console.log("no ceremony in the bridge log within 20s (site may have asked for a platform authenticator)");
      process.exit(1);
    }
    relevant.forEach((l) => console.log("  " + l.replace(/^\[bridge\] /, "")));
  } finally {
    s.close();
  }
};

function readLogLines() {
  try {
    return readFileSync(BRIDGE_LOG, "utf8").split("\n").filter(Boolean);
  } catch (e) {
    return [];
  }
}

// ---------------------------------------------------------------------- main
const url = opt("url", undefined);
const index = Number(opt("index", "0")) || 0;
switch (cmd) {
  case "status":
    await status();
    break;
  case "pages":
    await pages();
    break;
  case "find":
    await find(url);
    break;
  case "press":
    await press(url, index);
    break;
  case "flow":
    await flow(url, opt("shot", undefined), argv.includes("--console"));
    break;
  case "shot": {
    const s = await Session.open(url);
    try {
      console.log(await s.shot(opt("out", "/tmp/swpk-page.png")));
    } finally {
      s.close();
    }
    break;
  }
  default:
    console.error("usage: drive.mjs status|pages|find|press|flow|shot [--url substr] [--index n] [--shot path]");
    process.exit(2);
}
