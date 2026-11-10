# Chrome extension: the bridge, without pasting

Installs the page-side shim on every load, so the workflow is: click the site's
own "add security key" button. No console, no clipboard, no reload dance.

## Install once

1. `chrome://extensions`
2. turn on **Developer mode** (top right)
3. **Load unpacked** → select this directory (`tools/chrome-extension`)

That's it. On every page it prints `[swpasskey bridge] installed for <origin>` in
the console, and `navigator.credentials.create/get` are routed to
`http://localhost:3000`.

## Why two files

| file | world | job |
| --- | --- | --- |
| `inject.js` | `MAIN` | replaces `navigator.credentials`, builds the credential object. Runs in the page's own world, so its `fetch` would obey the page's CSP — which is exactly what blocked it before. |
| `relay.js` | `ISOLATED` | does the fetch. A content script is not bound by the page's `connect-src`, and the extension holds a host permission for the bridge origin. |

The two talk over `window.postMessage`, so the page never sees a cross-origin
request and the CSP never applies.

## Safety: it gets out of the way

The extension is installed on every site, so it must never break a normal passkey.
If the bridge is not running, the shim falls back to the browser's own
implementation, logs one warning, and the site behaves exactly as it would
without the extension:

```
[swpasskey bridge] bridge offline, using the browser's own authenticator
```

That is verified: with the bridge stopped, `create()` returns Chrome's own
rejection (`SecurityError: This is an invalid domain.` on the test page, whose rpId
deliberately does not match its origin) rather than a bridge error.

## The panel: state, and pressing the button for you

Click the toolbar icon (a small panel appears bottom-right; the icon's badge shows
`ok` when the bridge answers, `!` when it does not):

```
swpasskey bridge                          ready  ✕
last registration    packed · f4ce5fc0-… · x5c 1
last assertion       signCount 2 · flags 0x85
[ Find the security-key button ]
[ Press it ]
```

* **Find** scans the page for controls whose text looks like adding a security
  key or passkey (`add a security key`, `create passkey`, …), scores them, draws a
  green outline around the best match, scrolls it into view, and **names it** in
  the note line. Nothing is clicked.
* **Press** clicks that one control, once.

Clicking is deliberately two steps: the panel always tells you which control it
picked before anything happens, so a UI change shows up as a wrong name rather
than a wrong action. It also means an accidental click cannot add a key to an
account you did not mean to touch.

The panel reads the ceremony results from the page-side shim as they happen, so
`last registration` fills in with the format, AAGUID and `x5c` count the site
received — no console, no bridge terminal needed for the headline facts.

## Narrowing it

`manifest.json` matches `<all_urls>`. To restrict it to the site under test:

```json
"matches": ["https://*.openai.com/*"]
```

Reload the extension after editing (the reload arrow on `chrome://extensions`).

## Checking it took

In the page console:

```js
navigator.credentials.create.toString().slice(0, 40)   // our shim, not native
```

Then look at the bridge terminal — one line per ceremony with the AAGUID, format
and `x5c` count. If nothing appears there, the shim did not install (wrong origin
for `matches`) or the page cached an earlier reference to
`navigator.credentials` (reload it).

## What it still cannot hide

The credential reports `authenticatorAttachment: "cross-platform"`,
`getTransports() → ["usb"]` and `credProps.rk: true` because that is what a
plugged-in key reports. There is no USB device; `iohid` never runs. It measures
what the relying party's backend does with the attestation, which is the question
this experiment asks, and nothing more.
