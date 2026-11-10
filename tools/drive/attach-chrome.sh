#!/bin/sh
# Open a Chrome that this machine's tools can drive, signed in as you.
#
#   tools/drive/attach-chrome.sh
#
# Chrome refuses --remote-debugging-port on the default profile (M136+), and
# Google Chrome ignores --load-extension entirely. So this clones your profile
# once (cookies included; they decrypt with the same login keychain), loads the
# extension from tools/chrome-extension, and opens the debugging port on the copy.
#
# Nothing in your real profile is modified. The clone lives at ~/.swpasskey-chrome.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SRC="$HOME/Library/Application Support/Google/Chrome"
DST="$HOME/.swpasskey-chrome"
PORT=${CDP_PORT:-9222}

CFT=$(ls -d "$HOME"/.agent-browser/browsers/*/"Google Chrome for Testing.app" 2>/dev/null | head -1)
if [ -n "$CFT" ]; then
  BIN="$CFT/Contents/MacOS/Google Chrome for Testing"
else
  BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
  echo "attach-chrome: no Chrome for Testing found; using Google Chrome, which will" >&2
  echo "attach-chrome: ignore --load-extension (load the extension by hand once:" >&2
  echo "attach-chrome: chrome://extensions -> Developer mode -> Load unpacked -> $ROOT/tools/chrome-extension)" >&2
fi

if [ ! -d "$DST" ]; then
  echo "attach-chrome: cloning $SRC -> $DST (once; cookies and logins come along)"
  mkdir -p "$DST"
  # Profile data only: no caches, no crash dumps, no locks.
  rsync -a --quiet \
    --exclude 'Cache*' --exclude 'Code Cache' --exclude 'GPUCache' \
    --exclude 'Service Worker/CacheStorage' --exclude 'Crashpad' \
    --exclude 'Singleton*' --exclude '*.lock' \
    "$SRC/" "$DST/" 2>/dev/null || true
fi

echo "attach-chrome: starting on port $PORT (profile $DST)"
exec "$BIN" \
  --user-data-dir="$DST" \
  --remote-debugging-port="$PORT" \
  --no-first-run --no-default-browser-check \
  ${CFT:+--load-extension="$ROOT/tools/chrome-extension" --disable-extensions-except="$ROOT/tools/chrome-extension"} \
  "$@"
