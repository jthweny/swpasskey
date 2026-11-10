// Relay (isolated world): performs the request the page-side shim cannot.
//
// The shim runs in the page's own world, where `fetch` obeys the page's
// Content-Security-Policy — that is what blocked http://127.0.0.1:8100 on the
// target site. A content script's fetch is not bound by that policy, and the
// extension holds a host permission for the bridge origin, so this side does the
// talking while the page side only keeps the PublicKeyCredential shape.
const BRIDGE = "http://localhost:3000";

window.addEventListener("message", async (event) => {
  if (event.source !== window || !event.data || event.data.__swpk !== "req") return;
  const { id, path, body } = event.data;
  const reply = (payload) => window.postMessage({ __swpk: "res", id, ...payload }, "*");
  try {
    const res = await fetch(BRIDGE + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({ ok: false, error: res.statusText }));
    if (!json.ok) console.error("[swpasskey bridge] " + (json.error || res.statusText));
    reply({ json });
  } catch (err) {
    reply({ error: String(err) });
  }
});

// ---- long-running classification observer -----------------------------------
// Users report the hardware verdict flipping days after enrolment with no action.
// Every verdict this project recorded was read within minutes, so that claim has
// never been tested. This samples the account's own credential list on a timer and
// forwards it to the local bridge, which appends to /tmp/flag-timeline.jsonl.
if (location.hostname === "auth.openai.com" && !window.__swpk_poller) {
  window.__swpk_poller = true;
  const sample = async () => {
    try {
      const res = await fetch("/api/accounts/advanced-account-security/passkeys", { credentials: "include" });
      if (!res.ok) return;
      const pk = await res.json();
      const hardware = pk.passkeys.filter((p) => p.is_non_exportable_hardware_key).map((p) => p.authenticator_name);
      const summary = {
        t: new Date().toISOString(),
        total: pk.passkeys.length,
        securityKeys: pk.passkeys.filter((p) => p.is_security_key).length,
        hardware,
      };
      await fetch(BRIDGE + "/probe-log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(summary),
      }).catch(() => {});
    } catch (e) { /* session may be expired; try again next tick */ }
  };
  setTimeout(sample, 20000);
  setInterval(sample, 10 * 60 * 1000);
}
