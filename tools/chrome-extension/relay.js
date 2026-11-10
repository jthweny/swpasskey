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
