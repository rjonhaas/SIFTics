// Drives the MCP server over stdio JSON-RPC.
//
// Lifecycle: started by the orchestrator at boot, kept alive for the case,
// shut down on close. Only the Tool Broker subagent's tool-use emissions
// reach this — the routing layer makes that guarantee.
import { spawn } from "node:child_process";
import { resolve } from "node:path";
export class McpClient {
    config;
    child = null;
    nextId = 1;
    pending = new Map();
    buffer = "";
    tools = [];
    constructor(config) {
        this.config = config;
    }
    async start() {
        const entry = resolve(this.config.serverEntry);
        this.child = spawn("node", [entry], {
            stdio: ["pipe", "pipe", "inherit"],
            env: {
                ...process.env,
                EVIDENCE_MOUNT: this.config.evidenceMount,
                WORKING_DIR: this.config.workingDir,
                READ_ONLY_ENFORCE: "true",
                ...(this.config.evidenceManifest ? { EVIDENCE_MANIFEST: this.config.evidenceManifest } : {}),
            },
        });
        this.child.stdout.on("data", (chunk) => this.consume(chunk.toString("utf8")));
        this.child.on("exit", (code) => {
            for (const p of this.pending.values()) {
                p.reject(new Error(`MCP server exited (code=${code}) before responding`));
            }
            this.pending.clear();
        });
        await this.call("initialize", {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "protocol-sift-orchestrator", version: "0.1.0" },
        });
        this.notify("notifications/initialized", {});
        const list = await this.call("tools/list", {});
        this.tools = (list.result?.tools ?? []);
    }
    async stop() {
        this.child?.kill();
        this.child = null;
    }
    listTools() {
        return this.tools;
    }
    async callTool(name, args) {
        const resp = await this.call("tools/call", { name, arguments: args });
        const text = resp.result?.content?.[0]?.text ?? "";
        let parsed = null;
        try {
            parsed = JSON.parse(text);
        }
        catch { /* leave null */ }
        return { text, isError: Boolean(resp.result?.isError), parsed };
    }
    // ── stdio plumbing ──────────────────────────────────────────────────
    consume(chunk) {
        this.buffer += chunk;
        let nl;
        while ((nl = this.buffer.indexOf("\n")) !== -1) {
            const line = this.buffer.slice(0, nl).trim();
            this.buffer = this.buffer.slice(nl + 1);
            if (!line)
                continue;
            let msg;
            try {
                msg = JSON.parse(line);
            }
            catch {
                continue;
            }
            if (msg.id !== undefined && this.pending.has(msg.id)) {
                const p = this.pending.get(msg.id);
                this.pending.delete(msg.id);
                p.resolve(msg);
            }
        }
    }
    call(method, params) {
        if (!this.child)
            throw new Error("MCP client not started");
        const id = this.nextId++;
        return new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
        });
    }
    notify(method, params) {
        if (!this.child)
            return;
        this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
    }
}
//# sourceMappingURL=mcp_client.js.map