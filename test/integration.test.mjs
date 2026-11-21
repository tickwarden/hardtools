// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
function envFor(root, audit, extra = {}) {
  const cfg = path.join(audit, "config.json"); fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: path.join(audit, "log") } }));
  const base = { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, ...extra };
  delete base.HARDTOOLS_PROFILE; return { ...base, ...extra };
}
const text = (r) => r.content.map(c => c.text).join("\n");

test("e2e/stdio: 17 tools, write→read→edit round trip, denials surface as tool errors, audit chain is intact", async () => {
  const root = tmp("ht-e2e-"); const audit = tmp("ht-e2e-audit-");
  const client = new Client({ name: "t", version: "0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry, "--profile", "balanced"], env: envFor(root, audit), stderr: "ignore" }));
  try {
    const tools = (await client.listTools()).tools.map(t => t.name).sort();
    assert.deepEqual(tools, ["ht_add_var", "ht_delete_var", "ht_edit", "ht_empty_trash", "ht_fetch", "ht_glob", "ht_image_search", "ht_list_vars", "ht_mkdir", "ht_move", "ht_read", "ht_search", "ht_share", "ht_shell", "ht_status", "ht_trash", "ht_write"]);
    for (const t of (await client.listTools()).tools) assert.ok(t.annotations, `${t.name} has annotations`);
    const w = await client.callTool({ name: "ht_write", arguments: { path: "hello.txt", content: "hi there\n" } }); assert.ok(!w.isError, text(w));
    const e = await client.callTool({ name: "ht_edit", arguments: { edits: [{ path: "hello.txt", old_str: "hi", new_str: "hello" }] } }); assert.ok(!e.isError, text(e));
    assert.match(text(await client.callTool({ name: "ht_read", arguments: { path: "hello.txt" } })), /hello there/);
    assert.match(text(await client.callTool({ name: "ht_search", arguments: { pattern: "there" } })), /hello\.txt:1:/);
    const bad = await client.callTool({ name: "ht_read", arguments: { path: "/etc/passwd" } }); assert.ok(bad.isError); assert.match(text(bad), /DENIED \[outside_roots\]/);
    const sh = await client.callTool({ name: "ht_shell", arguments: { argv: ["rm", "-rf", "hello.txt"] } }); assert.ok(!sh.isError, text(sh));
    assert.ok(!fs.existsSync(path.join(root, "hello.txt")));
    const st = JSON.parse(text(await client.callTool({ name: "ht_status", arguments: {} })));
    assert.equal(st.profile, "balanced"); assert.equal(st.audit.chain.ok, true); assert.ok(st.audit.chain.entries >= 10);
  } finally { await client.close(); }
  const logs = fs.readdirSync(path.join(audit, "log")); assert.equal(logs.length, 1);
  const v = spawnSync(process.execPath, [entry, "--verify", path.join(audit, "log", logs[0])]);
  assert.equal(v.status, 0, String(v.stdout));
});

test("e2e/stdio: strict profile fails closed when the root is the filesystem root", async () => {
  const audit = tmp("ht-e2e-audit-");
  const r = spawnSync(process.execPath, [entry, "--profile", "strict"], { env: envFor("/", audit), encoding: "utf8", timeout: 10000 });
  assert.equal(r.status, 1); assert.match(r.stderr, /filesystem root/);
});

async function startHttp(root, audit, extra = {}) {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], { env: envFor(root, audit, extra), stdio: ["ignore", "ignore", "pipe"] });
  let err = ""; child.stderr.on("data", d => err += d);
  for (let i = 0; i < 50; i++) { if (/listening/.test(err)) break; if (child.exitCode !== null) break; await new Promise(r => setTimeout(r, 100)); }
  return { port, child, err: () => err };
}
const rawPost = (port, body, headers) => new Promise((resolve, reject) => {
  const data = JSON.stringify(body);
  const req = http.request({ host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "content-length": Buffer.byteLength(data), ...headers } },
    (res) => { let s = ""; res.on("data", d => s += d); res.on("end", () => resolve({ status: res.statusCode, body: s })); });
  req.on("error", reject); req.end(data);
});
const rpc = (port, body, headers = {}) => fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(body) });

test("e2e/http: refuses to start without a strong token", async () => {
  const root = tmp("ht-h-"); const audit = tmp("ht-h-audit-");
  const r = spawnSync(process.execPath, [entry, "--http", "--port", "29999"], { env: envFor(root, audit), encoding: "utf8", timeout: 10000 });
  assert.equal(r.status, 1); assert.match(r.stderr, /HARDTOOLS_HTTP_TOKEN/);
  const r2 = spawnSync(process.execPath, [entry, "--http", "--port", "29998"], { env: envFor(root, audit, { HARDTOOLS_HTTP_TOKEN: "short" }), encoding: "utf8", timeout: 10000 });
  assert.equal(r2.status, 1);
});

test("e2e/http: auth, host check, origin check; shell+write are OFF by default in remote mode", async () => {
  const root = tmp("ht-h-"); const audit = tmp("ht-h-audit-"); const token = "t".repeat(48);
  const { port, child } = await startHttp(root, audit, { HARDTOOLS_HTTP_TOKEN: token });
  try {
    const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };
    assert.equal((await rpc(port, init)).status, 401);
    assert.equal((await rpc(port, init, { authorization: "Bearer wrong" + token })).status, 401);
    assert.equal((await rawPost(port, init, { authorization: `Bearer ${token}`, host: "evil.example" })).status, 403);
    assert.equal((await rawPost(port, init, { authorization: `Bearer ${token}`, origin: "https://evil.example" })).status, 403);
    const ok = await rpc(port, init, { authorization: `Bearer ${token}` }); assert.equal(ok.status, 200); assert.match(await ok.text(), /hardtools/);
    const call = await rpc(port, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "ht_shell", arguments: { argv: ["ls"] } } }, { authorization: `Bearer ${token}` });
    assert.match(await call.text(), /shell_disabled/);
    const w = await rpc(port, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "ht_write", arguments: { path: "x.txt", content: "x" } } }, { authorization: `Bearer ${token}` });
    assert.match(await w.text(), /write_disabled/); assert.ok(!fs.existsSync(path.join(root, "x.txt")));
    const get = await fetch(`http://127.0.0.1:${port}/mcp`, { headers: { authorization: `Bearer ${token}` } }); assert.equal(get.status, 405);
  } finally { child.kill("SIGKILL"); }
});
