// 0.5.1 — oturum açmadan bağlanma: /mcp asla 401 dönmez, OAuth keşfi yayınlanmaz,
// araç listesi public modda sınırlıdır, /c/<key> adresi tam yetki açar.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef";
const KEY = "k".repeat(4) + "0123456789abcdef0123456789abcdef";

const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));

function request(port, { method = "GET", signal, target, headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = ""; res.on("data", (c) => { data += c; }); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

function rpc(port, target, payload) {
  return request(port, {
    method: "POST", target,
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify(payload),
  });
}

const parse = (res) => {
  const line = res.body.split("\n").find(l => l.startsWith("data: "));
  return line ? JSON.parse(line.slice(6)) : JSON.parse(res.body);
};

async function start(t, extraEnv) {
  const root = tmp("ht-pub-root-");
  const audit = tmp("ht-pub-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: true }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, ...extraEnv },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 80; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise(r => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, `sunucu başlamadı: ${err}`);
  return { port, err };
}

test("public mode (open): /mcp never challenges, discovery is 404, tool list is restricted", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PUBLIC: "open" });

  const health = JSON.parse((await request(port, { target: "/healthz" })).body);
  assert.equal(health.ok, true);
  assert.equal(health.public, "open");

  // OAuth keşfi yayınlanmaz: claude.ai "Oturum açma gerekli" göstermez.
  for (const p of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "/authorize", "/register", "/token"]) {
    const r = await request(port, { target: p });
    assert.equal(r.status, 404, `${p} → ${r.status}`);
  }

  // Anahtarsız, başlıksız MCP: 200 ve oturum açma başlığı yok.
  const init = await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal(init.status, 200, init.body);
  assert.equal(init.headers["www-authenticate"], undefined);

  const tools = parse(await rpc(port, "/mcp", { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }));
  const names = tools.result.tools.map(t2 => t2.name).sort();
  assert.ok(names.includes("ht_read"), names.join(","));
  assert.ok(names.includes("ht_user_input"), names.join(","));
  // Sınırlı mod: kabuk/yazma araçları listelenmez.
  for (const forbidden of ["ht_shell", "ht_write", "ht_edit", "ht_transfer_file", "ht_new_shell_env"]) {
    assert.equal(names.includes(forbidden), false, `${forbidden} sızmamalı`);
  }
});

test("public mode (key): /mcp needs the key url, /c/<key> exposes the full tool set", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PUBLIC: "key", HARDTOOLS_PUBLIC_KEY: KEY, HARDTOOLS_PUBLIC_TOOLS: "all" });

  const denied = await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(denied.status, 401);
  assert.equal(denied.headers["www-authenticate"], undefined); // yine OAuth'a yönlendirme yok

  const wrong = await rpc(port, `/c/${"x".repeat(40)}`, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(wrong.status, 401);

  const ok = await rpc(port, `/c/${KEY}`, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal(ok.status, 200, ok.body);

  const tools = parse(await rpc(port, `/c/${KEY}`, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }));
  const names = tools.result.tools.map(t2 => t2.name);
  assert.ok(names.includes("ht_shell"), names.join(","));

  const page = await request(port, { target: "/connect" });
  assert.equal(page.status, 200);
  assert.match(page.body, /\/c\//);
});

test("public mode: the static bearer still works and discovery stays off", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PUBLIC: "open" });
  const r = await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  assert.equal(r.status, 200);
  const withBearer = await request(port, {
    method: "POST", target: "/mcp",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
  });
  assert.equal(withBearer.status, 200);
  const names = parse(withBearer).result.tools.map((t2) => t2.name);
  assert.ok(names.includes("ht_shell"), "statik bearer tam yetkiyi korur");
});
