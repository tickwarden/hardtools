#!/usr/bin/env node
// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import crypto from "node:crypto";
import http from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Audit, verifyAuditFile } from "./audit.js";
import { loadPolicy, type Policy, type ProfileName } from "./config.js";
import { createServer, VERSION } from "./server.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name); if (i === -1) return undefined;
  const v = process.argv[i + 1]; return v && !v.startsWith("--") ? v : "true";
}

async function main() {
  if (arg("--version")) { console.log(VERSION); return; }
  if (arg("--verify")) { const r = verifyAuditFile(arg("--verify")!); console.log(JSON.stringify(r)); process.exit(r.ok ? 0 : 2); }

  const profile = arg("--profile") as ProfileName | undefined;
  let policy: Policy = loadPolicy({ profile });
  const httpMode = process.argv.includes("--http");

  if (httpMode && process.env.HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS !== "1") {
    // A remote MCP server's filesystem/shell is the HOST's, not the caller's. Off unless explicitly enabled.
    policy = { ...policy, fs: { ...policy.fs, writeEnabled: false }, shell: { ...policy.shell, enabled: false } };
  }
  const audit = new Audit(policy.audit.dir!, policy.audit.failClosed);
  audit.write({ ev: "start", version: VERSION, profile: policy.profile, transport: httpMode ? "http" : "stdio", roots: policy.roots, shell: policy.shell.enabled, write: policy.fs.writeEnabled });
  console.error(`[hardtools] ${VERSION} profile=${policy.profile} roots=${policy.roots.join(",")} transport=${httpMode ? "http" : "stdio"} audit=${audit.file}`);

  if (!httpMode) {
    await createServer(policy, audit).connect(new StdioServerTransport());
    return;
  }

  const token = process.env.HARDTOOLS_HTTP_TOKEN ?? "";
  if (token.length < 32) { console.error("[hardtools] refusing to start HTTP mode: set HARDTOOLS_HTTP_TOKEN to a random secret of at least 32 chars (e.g. `openssl rand -hex 32`)."); process.exit(1); }
  const host = arg("--host") ?? "127.0.0.1"; const port = Number(arg("--port") ?? 8787);
  const allowedHosts = new Set((process.env.HARDTOOLS_ALLOWED_HOSTS ?? `127.0.0.1:${port},localhost:${port}`).split(",").map(s => s.trim().toLowerCase()).filter(Boolean));
  const tokHash = crypto.createHash("sha256").update(token).digest();
  const hits = new Map<string, { n: number; reset: number }>();

  const srv = http.createServer(async (req, res) => {
    const send = (code: number, msg: string) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify({ error: msg })); };
    try {
      const h = String(req.headers.host ?? "").toLowerCase();
      if (!allowedHosts.has(h)) return send(403, "host not allowed");                 // DNS-rebinding defence
      if (req.headers.origin) return send(403, "browser origins are not allowed");     // this is a machine-to-machine endpoint
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization ?? ""));
      const ok = m && crypto.timingSafeEqual(crypto.createHash("sha256").update(m[1]).digest(), tokHash);
      const ip = req.socket.remoteAddress ?? "?"; const now = Date.now(); const b = hits.get(ip) ?? { n: 0, reset: now + 60_000 };
      if (now > b.reset) { b.n = 0; b.reset = now + 60_000; } b.n++; hits.set(ip, b);
      if (b.n > 120) return send(429, "rate limited");
      if (!ok) return send(401, "unauthorized");
      if (req.url?.split("?")[0] !== "/mcp") return send(404, "not found");
      if (req.method !== "POST") return send(405, "stateless server: POST only");
      const chunks: Buffer[] = []; let size = 0;
      for await (const c of req) { size += (c as Buffer).length; if (size > 1_000_000) return send(413, "body too large"); chunks.push(c as Buffer); }
      let body: unknown; try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return send(400, "invalid JSON"); }
      const server = createServer(policy, audit);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => { void transport.close(); void server.close(); });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (e) { console.error("[hardtools] http error:", (e as Error).message); if (!res.headersSent) send(500, "internal error"); }
  });
  srv.listen(port, host, () => console.error(`[hardtools] HTTP listening on http://${host}:${port}/mcp (put a TLS-terminating reverse proxy/tunnel in front for Claude web)`));
}

main().catch((e) => { console.error("[hardtools] fatal:", (e as Error).message); process.exit(1); });
