// Browser bridge: makes a page's WebAuthn calls go to the local daemon instead of
// to a USB device, so the relying party receives a real CTAP2 attestation
// (our AAGUID, our x5c certificate) from its own page, in its own origin.
//
// Paste this into the DevTools console on the target page, or inject it with
// Playwright/CDP before the page's own scripts run. Everything is local: the
// page talks to http://127.0.0.1:<port>, and the daemon talks CTAP over a Unix
// socket. No HID device, no macOS entitlement.
//
// The page cannot tell the difference at the protocol level: it gets a
// PublicKeyCredential with the right member functions, a clientDataJSON carrying
// its own origin and its own challenge, and an attestationObject signed by the
// daemon's attestation key.
(() => {
  // The page's Content-Security-Policy decides this, not us. OpenAI's
  // connect-src allows http://localhost:3000 and not 127.0.0.1, so that is the
  // default; override with window.__SWPK_BRIDGE for a site with a different rule.
  const BRIDGE = window.__SWPK_BRIDGE || "http://localhost:3000";
  // Captured before patching, so the pass-through path reaches the real thing.
  const nativeGet = navigator.credentials.get.bind(navigator.credentials);

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

  const call = async (path, body) => {
    let res;
    try {
      res = await fetch(BRIDGE + path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch (err) {
      // A CSP or connection failure has no useful message of its own.
      throw new DOMException(
        `bridge unreachable at ${BRIDGE} (${err.message}). Start it on that exact ` +
          `origin: if the page's CSP blocked it, look at connect-src and move the bridge.`,
        "NotAllowedError",
      );
    }
    const json = await res.json().catch(() => ({ ok: false, error: res.statusText }));
    if (!json.ok) {
      // The page's own error handling tends to swallow this; put it in the
      // console where it can be read.
      console.error("[swpasskey bridge] " + (json.error || res.statusText));
      throw new DOMException(json.error || "bridge refused", "NotAllowedError");
    }
    return json;
  };

  // Chrome hands back ArrayBuffers for PRF outputs; keep the shape.
  const extensionResults = (result) => {
    const out = result || {};
    if (out.prf && out.prf.results) {
      const results = {};
      for (const key of Object.keys(out.prf.results)) {
        results[key] = unb64u(out.prf.results[key]);
      }
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

  const create = async (options) => {
    const pk = options && options.publicKey;
    if (!pk) throw new TypeError("publicKey options required");
    const selection = pk.authenticatorSelection || {};
    const json = await call("/webauthn/create", {
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

    const credential = {
      id: json.credentialId,
      rawId: unb64u(json.credentialId),
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: unb64u(json.clientDataJSON),
        attestationObject: unb64u(json.attestationObject),
        // The daemon's getInfo claim, overridable per call for probes.
        getTransports: () =>
          (Array.isArray(window.__SWPK_TRANSPORTS) ? window.__SWPK_TRANSPORTS : null) ||
          (Array.isArray(json.transports) && json.transports.length ? json.transports : ["usb"]),
        getAuthenticatorData: () =>
          json.authenticatorData ? unb64u(json.authenticatorData) : null,
        getPublicKey: () => (json.publicKey ? unb64u(json.publicKey) : null),
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
    return credential;
  };

  const get = async (options) => {
    // Never serve a sign-in by default; see tools/chrome-extension/inject.js.
    if (window.__SWPK_INTERCEPT_GET !== true) {
      return nativeGet(options);
    }
    const pk = options && options.publicKey;
    if (!pk) throw new TypeError("publicKey options required");
    const json = await call("/webauthn/get", {
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
    create: create,
    get: get,
    preventSilentAccess: original.preventSilentAccess
      ? original.preventSilentAccess.bind(original)
      : async () => {},
    store: original.store ? original.store.bind(original) : async () => {},
  };
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    get: () => patched,
  });

  console.log("[swpasskey bridge] WebAuthn routed to " + BRIDGE);
})();
