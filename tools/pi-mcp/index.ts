/**
 * MCP bridge for pi.
 *
 * pi has no built-in MCP support ("No MCP. Build CLI tools with READMEs, or build
 * an extension that adds MCP support"), so this is that extension: it reads
 * `mcpServers` from settings.json, speaks the MCP stdio protocol itself, and
 * registers every server tool as a pi tool named mcp__<server>__<tool>.
 *
 *   ~/.pi/agent/settings.json
 *   {
 *     "mcpServers": {
 *       "chrome": { "command": "npx", "args": ["-y", "chrome-devtools-mcp@latest", "--autoConnect"] }
 *     }
 *   }
 *
 * Tools are discovered at session start; /mcp re-checks a server and prints what
 * it found. Servers are killed when the session ends.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

type ServerConfig = { command: string; args?: string[]; env?: Record<string, string> };

type McpTool = {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, any>;
    required?: string[];
  };
};

const CONFIG_FILES = [
  join(homedir(), ".pi", "agent", "settings.json"),
  join(homedir(), ".pi", "settings.json"),
  join(process.cwd(), ".pi", "settings.json"),
];

function loadServers(): Record<string, ServerConfig> {
  const out: Record<string, ServerConfig> = {};
  for (const file of CONFIG_FILES) {
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8"));
      const section = parsed.mcpServers ?? parsed.mcp?.servers;
      if (section && typeof section === "object") Object.assign(out, section);
    } catch {
      /* missing or unreadable: fine */
    }
  }
  return out;
}

class McpClient {
  private child: ChildProcessWithoutNullStreams;
  private buffer = "";
  private nextId = 1;
  private waiting = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();
  serverInfo: { name?: string; version?: string } = {};
  tools: McpTool[] = [];

  constructor(name: string, cfg: ServerConfig) {
    this.child = spawn(cfg.command, cfg.args ?? [], {
      env: { ...process.env, ...(cfg.env ?? {}) },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.on("data", (chunk: Buffer) => this.onData(chunk.toString()));
    this.child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString().trim();
      if (text) process.stderr.write(`[mcp:${name}] ${text.slice(0, 500)}\n`);
    });
    this.child.on("exit", (code) => {
      for (const { reject } of this.waiting.values()) reject(new Error(`mcp:${name} exited (${code})`));
      this.waiting.clear();
    });
  }

  private onData(text: string) {
    this.buffer += text;
    for (;;) {
      const nl = this.buffer.indexOf("\n");
      if (nl < 0) break;
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (!line) continue;
      let msg: any;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      const entry = msg.id !== undefined ? this.waiting.get(msg.id) : undefined;
      if (entry) {
        this.waiting.delete(msg.id);
        entry.resolve(msg);
      }
    }
  }

  private request(method: string, params: unknown, timeoutMs = 120000): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.waiting.set(id, { resolve, reject });
      this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      const timer = setTimeout(() => {
        if (this.waiting.delete(id)) reject(new Error(`${method} timed out`));
      }, timeoutMs);
      timer.unref?.();
    });
  }

  private notify(method: string, params: unknown) {
    this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  }

  async connect() {
    const init = await this.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "pi", version: "0.1" },
    });
    if (init.error) throw new Error(init.error.message ?? "initialize failed");
    this.serverInfo = init.result?.serverInfo ?? {};
    this.notify("notifications/initialized", {});
    const list = await this.request("tools/list", {});
    if (list.error) throw new Error(list.error.message ?? "tools/list failed");
    this.tools = list.result?.tools ?? [];
    return this.tools;
  }

  async call(tool: string, args: Record<string, unknown>) {
    const reply = await this.request("tools/call", { name: tool, arguments: args }, 300000);
    if (reply.error) throw new Error(reply.error.message ?? "tools/call failed");
    return reply.result;
  }

  close() {
    try {
      this.child.kill();
    } catch {
      /* already gone */
    }
  }
}

// JSON Schema -> typebox, only as far as MCP servers actually use it.
function schemaOf(tool: McpTool): any {
  const schema = tool.inputSchema;
  if (!schema || schema.type !== "object" || !schema.properties) {
    return Type.Record(Type.String(), Type.Any());
  }
  const props: Record<string, any> = {};
  const required = new Set(schema.required ?? []);
  for (const [key, raw] of Object.entries<any>(schema.properties)) {
    let t: any;
    switch (raw?.type) {
      case "string":
        t = raw.enum ? Type.Unsafe({ type: "string", enum: raw.enum }) : Type.String();
        break;
      case "number":
      case "integer":
        t = Type.Number();
        break;
      case "boolean":
        t = Type.Boolean();
        break;
      case "array":
        t = Type.Array(Type.Any());
        break;
      default:
        t = Type.Any();
    }
    if (raw?.description) t = { ...t, description: raw.description };
    props[key] = required.has(key) ? t : Type.Optional(t);
  }
  return Type.Object(props);
}

function toolName(server: string, tool: string) {
  return `mcp__${server.replace(/[^a-zA-Z0-9]/g, "_")}__${tool.replace(/[^a-zA-Z0-9]/g, "_")}`;
}

export default function (pi: ExtensionAPI) {
  const clients = new Map<string, McpClient>();
  const names = new Map<string, { server: string; tool: string }>();

  const start = async (ctx: any, verbose: boolean) => {
    const servers = loadServers();
    const names = Object.keys(servers);
    if (names.length === 0) {
      if (verbose) {
        ctx.ui.notify(
          "mcp: no servers configured. Add \"mcpServers\" to ~/.pi/agent/settings.json.",
          "warning",
        );
      }
      return;
    }
    for (const name of names) {
      if (clients.has(name)) continue;
      const client = new McpClient(name, servers[name]);
      try {
        const tools = await client.connect();
        clients.set(name, client);
        for (const tool of tools) {
          const full = toolName(name, tool.name);
          names.set(full, { server: name, tool: tool.name });
          pi.registerTool({
            name: full,
            label: `${name}: ${tool.name}`,
            description: tool.description || `${tool.name} on the ${name} MCP server`,
            parameters: schemaOf(tool),
            async execute(_id: string, params: unknown) {
              const live = clients.get(name);
              if (!live) {
                return { content: [{ type: "text", text: `mcp:${name} is not connected` }], details: {} };
              }
              try {
                const result = await live.call(tool.name, (params as Record<string, unknown>) ?? {});
                const blocks = (result?.content ?? [])
                  .map((item: any) => {
                    if (item?.type === "text") return { type: "text" as const, text: String(item.text) };
                    if (item?.type === "image" && item.data) {
                      return {
                        type: "image" as const,
                        data: String(item.data),
                        mimeType: String(item.mimeType ?? "image/png"),
                      };
                    }
                    return { type: "text" as const, text: JSON.stringify(item).slice(0, 4000) };
                  })
                  .filter(Boolean);
                if (blocks.length === 0) blocks.push({ type: "text" as const, text: "(no content)" });
                return {
                  content: blocks,
                  details: {},
                  isError: result?.isError === true,
                };
              } catch (err) {
                return {
                  content: [{ type: "text", text: `mcp:${name}/${tool.name} failed: ${String(err)}` }],
                  details: {},
                  isError: true,
                };
              }
            },
          });
        }
        if (verbose) {
          ctx.ui.notify(
            `mcp: ${name} (${client.serverInfo.name ?? "?"}) → ${tools.length} tools`,
            "info",
          );
        }
      } catch (err) {
        client.close();
        ctx.ui.notify(`mcp: ${name} failed: ${String(err)}`, "error");
      }
    }
  };

  pi.on("session_start", async (_event: unknown, ctx: any) => {
    await start(ctx, false);
  });

  pi.registerCommand("mcp", {
    description: "List MCP servers and tools (re-checks them)",
    handler: async (_args: string, ctx: any) => {
      await start(ctx, true);
      const lines = [...clients.entries()].map(
        ([name, client]) =>
          `${name}: ${client.serverInfo.name ?? "?"} — ${client.tools.length} tools, e.g. ` +
          client.tools.slice(0, 3).map((t) => t.name).join(", "),
      );
      ctx.ui.notify(lines.length ? lines.join("\n") : "mcp: nothing connected", "info");
    },
  });

  pi.on("session_shutdown", async () => {
    for (const client of clients.values()) client.close();
    clients.clear();
  });
}
