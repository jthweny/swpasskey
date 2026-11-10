// Page-side shim (main world): replaces navigator.credentials and talks to the
// relay through window.postMessage.
//
// Same credential shape as tools/browser-bridge/bridge.js, but the request goes
// through the extension's relay so neither the page's CSP nor a stale paste can
// get in the way. Installed by the extension on every page load, so there is
// nothing to paste and no reload dance.
(() => {
  const MARK = "__swpasskey_bridge_installed__";
  if (window[MARK]) return;
  window[MARK] = true;

  const pending = new Map();
  let nextId = 1;

  window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data || event.data.__swpk !== "res") return;
    const entry = pending.get(event.data.id);
    if (!entry) return;
    pending.delete(event.data.id);
    if (event.data.error) {
      entry.reject(new Unavailable(event.data.error));
    } else if (event.data.json && event.data.json.unavailable) {
      entry.reject(new Unavailable(event.data.json.error || "bridge unavailable"));
    } else {
      entry.resolve(event.data.json);
    }
  });

  // If the bridge is not running, WebAuthn must behave exactly as it would
  // unbundled: fall through to the browser's own implementation. This extension
  // is installed on every site, so it must never be the reason a normal passkey
  // login fails.
  class Unavailable extends Error {}

  const call = (path, body) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      window.postMessage({ __swpk: "req", id, path, body }, "*");
      setTimeout(() => {
        if (pending.delete(id)) {
          reject(new Unavailable("relay did not answer"));
        }
      }, 30000);
    });

  const b64u = (buf) => {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const unb64u = (text) => {
    const pad = "=".repeat((4 - (text.length % 4)) % 4);
    const bin = atob((text + pad).replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };

  const announce = (data) => {
    try {
      window.dispatchEvent(new CustomEvent("__swpasskey_ceremony", { detail: JSON.stringify(data) }));
    } catch (e) {
      /* the panel is optional */
    }
  };

  const extensionResults = (result) => {
    const out = result || {};
    if (out.prf && out.prf.results) {
      const results = {};
      for (const key of Object.keys(out.prf.results)) results[key] = unb64u(out.prf.results[key]);
      out.prf = { ...out.prf, results };
    }
    return out;
  };

  const prfInput = (extensions) => {
    const prf = extensions && extensions.prf;
    if (!prf || !prf.eval) return null;
    const out = { eval: {} };
    for (const key of ["first", "second"]) {
      if (prf.eval[key]) out.eval[key] = b64u(prf.eval[key]);
    }
    return out.eval.first ? out : null;
  };

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  const create = async (options) => {
    const pk = options && options.publicKey;
    if (!pk) throw new TypeError("publicKey options required");
    const selection = pk.authenticatorSelection || {};
    let json;
    try {
      json = await call("/webauthn/create", {
      origin: location.origin,
      rpId: pk.rp.id || location.hostname,
      rpName: pk.rp.name || pk.rp.id || location.hostname,
      challenge: b64u(pk.challenge),
      userId: b64u(pk.user.id),
      userName: pk.user.name || "user",
      userDisplayName: pk.user.displayName || "",
      userVerification: selection.userVerification || pk.userVerification || "preferred",
      residentKey: selection.residentKey || (selection.requireResidentKey ? "required" : "preferred"),
        prf: pk.extensions && pk.extensions.prf ? true : false,
      });
    } catch (err) {
      if (err instanceof Unavailable) {
        console.warn("[swpasskey bridge] bridge offline, using the browser's own authenticator");
        return originalCreate(options);
      }
      throw err;
    }
    if (!json.ok) {
      console.error("[swpasskey bridge] " + (json.error || "refused"));
      throw new DOMException(json.error || "bridge refused", "NotAllowedError");
    }
    announce({
      kind: "create",
      fmt: json.fmt,
      aaguid: json.aaguid,
      x5c: json.x5c,
      flags: json.flags,
      sign_count: json.sign_count,
      rp: json.rpId,
    });
    return {
      id: json.credentialId,
      rawId: unb64u(json.credentialId),
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: unb64u(json.clientDataJSON),
        attestationObject: unb64u(json.attestationObject),
        getTransports: () => ["usb"],
        getAuthenticatorData: () => (json.authenticatorData ? unb64u(json.authenticatorData) : null),
        getPublicKey: () => null,
        getPublicKeyAlgorithm: () => json.publicKeyAlgorithm || -7,
      },
      getClientExtensionResults: () => extensionResults(json.clientExtensionResults),
      toJSON() {
        return {
          id: this.id,
          rawId: b64u(this.rawId),
          type: this.type,
          authenticatorAttachment: this.authenticatorAttachment,
          clientExtensionResults: this.getClientExtensionResults(),
          response: {
            clientDataJSON: b64u(this.response.clientDataJSON),
            attestationObject: b64u(this.response.attestationObject),
            transports: this.response.getTransports(),
          },
        };
      },
    };
  };

  const get = async (options) => {
    // Sign-in ceremonies are never served by the bridge unless explicitly asked
    // for: the daemon holds credentials the site does not know about, and a
    // successful-but-wrong assertion breaks the login instead of falling back.
    if (window.__SWPK_INTERCEPT_GET !== true) {
      return originalGet(options);
    }
    const pk = options && options.publicKey;
    if (!pk) throw new TypeError("publicKey options required");
    let json;
    try {
      json = await call("/webauthn/get", {
      origin: location.origin,
      rpId: pk.rpId || location.hostname,
      challenge: b64u(pk.challenge),
      allowCredentials: (pk.allowCredentials || []).map((c) => ({
        type: c.type,
        id: b64u(c.id),
        transports: c.transports || [],
      })),
      userVerification: pk.userVerification || "preferred",
        prf: prfInput(pk.extensions),
      });
    } catch (err) {
      // A sign-in must never fail because the bridge could not answer: fall back
      // to Chrome's own authenticator for any bridge-side error, not only for
      // "unreachable". Registrations stay strict, since those are the experiment.
      console.warn("[swpasskey bridge] assertion fell back to Chrome: " + (err && err.message));
      return originalGet(options);
    }
    if (!json.ok) {
      console.warn("[swpasskey bridge] assertion fell back to Chrome: " + (json.error || "refused"));
      return originalGet(options);
    }
    announce({
      kind: "get",
      flags: json.flags,
      sign_count: json.sign_count,
      rp: json.rpId,
    });
    return {
      id: json.credentialId,
      rawId: unb64u(json.credentialId),
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: unb64u(json.clientDataJSON),
        authenticatorData: unb64u(json.authenticatorData),
        signature: unb64u(json.signature),
        userHandle: json.userHandle ? unb64u(json.userHandle) : null,
      },
      getClientExtensionResults: () => extensionResults(json.clientExtensionResults),
    };
  };

  const original = navigator.credentials;
  const patched = {
    create,
    get,
    preventSilentAccess: original.preventSilentAccess
      ? original.preventSilentAccess.bind(original)
      : async () => {},
    store: original.store ? original.store.bind(original) : async () => {},
  };
  Object.defineProperty(navigator, "credentials", { configurable: true, get: () => patched });

  console.log("[swpasskey bridge] installed for " + location.origin);
})();
