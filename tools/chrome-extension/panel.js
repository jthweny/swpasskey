// Injected on demand (toolbar button). Shows bridge state and the last ceremony,
// and can find and press the page's own "add a security key" control — a visible
// action, not an ambient one, so nothing is clicked without you asking.
(() => {
  const MARK = "__swpasskey_panel__";
  if (window[MARK]) {
    window[MARK].focus();
    return;
  }

  const BRIDGE = "http://localhost:3000";
  const CANDIDATE = /(security\s*key|passkey|security\s*keys|add\s*(a\s*)?(security\s*)?key|create\s*(a\s*)?passkey)/i;
  const REJECT = /(delete|remove|rename|cancel|sign out|log out|revoke)/i;

  const host = document.createElement("div");
  host.style.cssText = "position:fixed;z-index:2147483647;right:18px;bottom:18px;";
  const root = host.attachShadow({ mode: "open" });
  root.innerHTML = `
    <style>
      :host { all: initial; }
      .card {
        width: 320px; font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
        background: #16171a; color: #eceae5; border: 1px solid #2b2d31;
        border-radius: 10px; box-shadow: 0 8px 28px rgba(0,0,0,.45); padding: 12px;
      }
      .head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
      .title { font-weight: 600; letter-spacing: .02em; }
      .badge { padding: 1px 7px; border-radius: 999px; border: 1px solid #3a3d42; font-size: 11px; }
      .ok { color: #8fd0bd; border-color: #2f5d50; }
      .bad { color: #e08b8b; border-color: #8c2f2f; }
      .row { display: flex; justify-content: space-between; gap: 8px; padding: 1px 0; }
      .k { color: #9c9890; }
      .v { word-break: break-all; text-align: right; }
      button {
        font: inherit; width: 100%; margin-top: 8px; padding: 6px 8px; cursor: pointer;
        background: #1d1f23; color: #eceae5; border: 1px solid #3a3d42; border-radius: 6px;
      }
      button:hover:not(:disabled) { border-color: #8fd0bd; }
      button:disabled { opacity: .45; cursor: default; }
      .note { color: #9c9890; margin-top: 8px; }
      .close { width: auto; margin: 0; padding: 0 6px; background: transparent; border: none; color: #9c9890; }
    </style>
    <div class="card">
      <div class="head">
        <span class="title">swpasskey bridge</span>
        <span><span class="badge" id="badge">…</span>
        <button class="close" id="close" title="Close">✕</button></span>
      </div>
      <div class="row"><span class="k">last registration</span><span class="v" id="reg">—</span></div>
      <div class="row"><span class="k">last assertion</span><span class="v" id="asr">—</span></div>
      <button id="find">Find the security-key button</button>
      <button id="press" disabled>Press it</button>
      <div class="note" id="note">Nothing is clicked until you press "Press it".</div>
    </div>`;

  const $ = (id) => root.getElementById(id);
  let candidate = null;

  const api = {
    focus() {
      host.style.opacity = "1";
    },
    close() {
      host.remove();
      delete window[MARK];
    },
  };
  window[MARK] = api;
  $("close").onclick = () => api.close();

  async function refresh() {
    try {
      const res = await fetch(BRIDGE + "/health", { cache: "no-store" });
      const json = await res.json();
      $("badge").textContent = json.ok ? "ready" : "no daemon";
      $("badge").className = "badge " + (json.ok ? "ok" : "bad");
    } catch (e) {
      $("badge").textContent = "offline";
      $("badge").className = "badge bad";
    }
  }
  refresh();
  setInterval(refresh, 3000);

  // The MAIN-world shim announces every ceremony as a JSON string.
  window.addEventListener("__swpasskey_ceremony", (event) => {
    let data;
    try {
      data = JSON.parse(event.detail);
    } catch (e) {
      return;
    }
    if (data.kind === "create") {
      $("reg").textContent = `${data.fmt} · ${data.aaguid || "?"} · x5c ${data.x5c}`;
    } else if (data.kind === "get") {
      $("asr").textContent = `signCount ${data.sign_count} · flags 0x${Number(data.flags).toString(16)}`;
    }
  });

  const visible = (el) => {
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return rect.width > 4 && rect.height > 4 && style.visibility !== "hidden" && style.display !== "none";
  };

  const label = (el) =>
    [el.innerText || el.textContent || "", el.getAttribute("aria-label") || "", el.getAttribute("title") || ""]
      .join(" ")
      .replace(/\s+/g, " ")
      .trim();

  function find() {
    const all = [...document.querySelectorAll('button, a, [role="button"], input[type="button"]')];
    const scored = all
      .filter((el) => !host.contains(el) && visible(el) && !el.disabled)
      .map((el) => {
        const text = label(el);
        let score = 0;
        if (CANDIDATE.test(text)) score += 10;
        if (/add/i.test(text)) score += 4;
        if (/security\s*key/i.test(text)) score += 4;
        if (REJECT.test(text)) score -= 20;
        if (text.length > 80) score -= 2;
        return { el, text, score };
      })
      .filter((c) => c.score > 0)
      .sort((a, b) => b.score - a.score);

    if (candidate) candidate.el.style.outline = "";
    candidate = scored[0] || null;
    if (!candidate) {
      $("press").disabled = true;
      $("note").textContent = "No matching control on this screen. Open the security-key screen first.";
      return;
    }
    candidate.el.style.outline = "2px solid #8fd0bd";
    candidate.el.scrollIntoView({ block: "center", behavior: "smooth" });
    $("press").disabled = false;
    $("note").textContent = `Candidate: "${candidate.text.slice(0, 60)}" — press the button above to click it.`;
  }

  $("find").onclick = find;
  $("press").onclick = () => {
    if (!candidate) return;
    const text = candidate.text.slice(0, 60);
    $("note").textContent = `Clicked "${text}". Watch the bridge terminal.`;
    candidate.el.click();
    $("press").disabled = true;
  };

  document.documentElement.appendChild(host);
  console.log("[swpasskey bridge] panel open");
})();
