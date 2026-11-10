# MCP bridge for pi

pi has no built-in MCP — its README says so plainly: *"No MCP. Build CLI tools
with READMEs, or build an extension that adds MCP support."* This is that
extension: it speaks the MCP stdio protocol and registers every server tool as a
pi tool named `mcp__<server>__<tool>`.

## Install

```sh
mkdir -p ~/.pi/agent/extensions
cp -r ~/VirtualYubi/swpasskey/tools/pi-mcp ~/.pi/agent/extensions/
# restart pi
```

Then configure servers in `~/.pi/agent/settings.json`:

```json
{
  "mcpServers": {
    "chrome": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest", "--autoConnect"]
    }
  }
}
```

Check with `/mcp` inside pi: it re-runs the handshake and prints
`chrome: chrome-devtools-mcp — 30 tools, e.g. navigate_page, take_snapshot, click`.

## Chrome, with your session

`--autoConnect` attaches to the Chrome you are already using (Chrome ≥ 144):

1. `chrome://inspect/#remote-debugging` → enable remote debugging, allow the
   incoming connection when Chrome asks.
2. Keep the swpasskey extension installed in that Chrome so WebAuthn is routed to
   the daemon.

No profile clone, no second browser, no `--load-extension` (Google Chrome ignores
that flag anyway).

Other modes, if you prefer them:

| want | args |
| --- | --- |
| attach to a Chrome on a known port | `["-y","chrome-devtools-mcp@latest","--browserUrl=http://127.0.0.1:9222"]` |
| throwaway headless browser | `["-y","chrome-devtools-mcp@latest","--headless","--isolated"]` |

## What it does and does not do

* Discovers tools once per session, at `session_start`; `/mcp` re-checks.
* Strictly stdio JSON-RPC, one JSON object per line — the protocol as specified.
* JSON Schema → typebox conversion covers the shapes MCP servers actually emit
  (string/enum/number/boolean/array/anything); anything exotic falls back to a
  free-form object, so the tool still works with raw arguments.
* Servers are killed on `session_shutdown`.
* Tools are namespaced, so two servers can both have a `click`.

## Verified

The client half was tested against the real server before wiring it into pi:

```
node mcp_probe.mjs npx -y chrome-devtools-mcp@latest --headless --isolated
server: {"name":"chrome-devtools-mcp","version":"0.12.0"} protocol: 2024-11-05
tools: 30
  - navigate_page : Go to a URL, or back, forward, or reload…
  - take_snapshot : Take a text snapshot of the target page based on the a11y tree…
  - click : Clicks on the provided element
  - list_network_requests : Lists the most recent requests for the target page…
```

The pi side (tool registration) is per the extension docs; if a server misbehaves,
`/mcp` reports it instead of failing silently.

## Fallback that needs no MCP

`tools/drive/` does the same browser work directly over CDP with no dependencies
(`node tools/drive/drive.mjs flow --url openai`). Keep it for when a server is
misconfigured or the network is slow.
