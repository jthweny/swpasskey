# Drive a real Chrome from the command line

Finds the page's own security-key control, presses it, and reports what the
ceremony produced — so a full registration can be run without touching the
console, and without a human clicking through the dialog.

Zero dependencies: Node's built-in `fetch` and `WebSocket` speak the DevTools
protocol directly.

## One-time: a Chrome that can be driven

Chrome refuses `--remote-debugging-port` on the default profile (M136+), and
Google Chrome ignores `--load-extension`. So:

```sh
tools/drive/attach-chrome.sh
```

clones your profile once to `~/.swpasskey-chrome` (cookies come along, they
decrypt with the same login keychain), loads `tools/chrome-extension`, and opens
port 9222 on the clone. Your real profile is untouched. Then log in as usual in
that window — it is a copy, so the session is already there.

## Commands

```sh
node tools/drive/drive.mjs pages                 # tabs and their URLs
node tools/drive/drive.mjs status                # bridge health + attestation subject
node tools/drive/drive.mjs find   --url openai   # score candidate controls, click nothing
node tools/drive/drive.mjs press  --url openai   # click the best candidate
node tools/drive/drive.mjs flow   --url openai --shot /tmp/after.png --console
node tools/drive/drive.mjs shot   --url openai --out /tmp/page.png
```

`--url` is a substring of the tab URL; omit it to use the first page. `flow` is
find + press + wait for the ceremony in `/tmp/bridge.log` + optional screenshot,
and `--console` streams the page's console and exceptions while it runs.

Verified against the probe page with the extension loaded: the driver pressed
"Register security key", the site ran its own flow, and the log showed
`create rp=localhost fmt=packed aaguid=f4ce5fc0-… x5c=1 flags=0x45`.

## What it will not do

It clicks one control, chosen by the same text heuristic as the extension panel,
and it names it before clicking. It does not type, scroll through menus, or retry
a failed flow on its own: a wrong guess shows up as a wrong name, not a wrong
action on your account.
