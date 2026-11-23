// 0.5.2 — public modlar:
//   open         -> tüm araçlar, GİRİŞ ZORUNLU (statik bearer veya OAuth; keşif yayınlanır)
//   open + liste -> girişsiz, sadece izin verilen araçlar (OAuth keşfi 404)
//   key          -> /c/<key> adresi tam yetki açar, giriş istenmez
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

async function start(t, extraEnv, { token = TOKEN } = {}) {
  const root = tmp("ht-pub-root-");
  const audit = tmp("ht-pub-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: true }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, ...(token ? { HARDTOOLS_HTTP_TOKEN: token } : {}), HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, ...extraEnv },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 80; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise(r => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, `sunucu başlamadı: ${err}`);
  return { port, err };
}

test("public mode (open): full tool set stays behind the login gate", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PUBLIC: "open" });

  const health = JSON.parse((await request(port, { target: "/healthz" })).body);
  assert.equal(health.ok, true);
  assert.equal(health.public, "open");
  assert.equal(health.login, "required", "open + tam araç seti = giriş zorunlu");

  // Giriş gerektiği için OAuth keşfi yayınlanır: claude.ai "Oturum açma gerekli" gösterebilir.
  const meta = await request(port, { target: "/.well-known/oauth-protected-resource" });
  assert.equal(meta.status, 200, "keşif yayınlanmalı: " + meta.body);

  // Kimliksiz istek reddedilir ve istemciye girişe giden başlık verilir.
  const anon = await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal(anon.status, 401);
  assert.match(String(anon.headers["www-authenticate"] ?? ""), /^Bearer .*resource_metadata=/, "OAuth'a yönlendiren başlık gelmeli");

  // Statik bearer ile TÜM araçlar açık.
  const withBearer = await request(port, {
    method: "POST", target: "/mcp",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
  });
  assert.equal(withBearer.status, 200, withBearer.body);
  const names = parse(withBearer).result.tools.map((t2) => t2.name);
  for (const wanted of ["ht_read", "ht_write", "ht_edit", "ht_shell", "ht_transfer_file", "ht_new_shell_env", "ht_add_var"]) {
    assert.ok(names.includes(wanted), `${wanted} açık olmalı; gelenler: ${names.join(",")}`);
  }
});

test("public mode (open + safe list): login-free read-only connector keeps the old behaviour", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PUBLIC: "open", HARDTOOLS_PUBLIC_TOOLS: "safe" });

  const health = JSON.parse((await request(port, { target: "/healthz" })).body);
  assert.equal(health.login, "none");

  // Girişsiz modda OAuth keşfi yayınlanmaz: claude.ai giriş ekranı açmaz.
  for (const p of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "/authorize", "/register", "/token"]) {
    const r = await request(port, { target: p });
    assert.equal(r.status, 404, `${p} → ${r.status}`);
  }

  const init = await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal(init.status, 200, init.body);
  assert.equal(init.headers["www-authenticate"], undefined);

  const names = parse(await rpc(port, "/mcp", { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })).result.tools.map((t2) => t2.name).sort();
  assert.ok(names.includes("ht_read"), names.join(","));
  assert.ok(names.includes("ht_user_input"), names.join(","));
  for (const forbidden of ["ht_shell", "ht_write", "ht_edit", "ht_transfer_file", "ht_new_shell_env"]) {
    assert.equal(names.includes(forbidden), false, `${forbidden} sızmamalı`);
  }
});

test("public mode (open + custom list): only the listed tools, still no login", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PUBLIC: "open", HARDTOOLS_PUBLIC_TOOLS: "ht_read,ht_status" });
  const names = parse(await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })).result.tools.map((t2) => t2.name).sort();
  assert.deepEqual(names, ["ht_read", "ht_status"]);
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

  const names = parse(await rpc(port, `/c/${KEY}`, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })).result.tools.map((t2) => t2.name);
  assert.ok(names.includes("ht_shell"), names.join(","));

  const page = await request(port, { target: "/connect" });
  assert.equal(page.status, 200);
  assert.match(page.body, /\/c\//);
});

test("public mode: open without any token still refuses anonymous access (no accidental open door)", async (t) => {
  const { port, err } = await start(t, { HARDTOOLS_PUBLIC: "open" }, { token: "" });
  assert.match(err, /neither HARDTOOLS_HTTP_TOKEN nor GitHub OAuth/);

  const init = await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(init.status, 401, "token yoksa anonim istek geçmemeli");

  const fake = await request(port, {
    method: "POST", target: "/mcp",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer x" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
  });
  assert.equal(fake.status, 401, "uydurma bearer kimlik kazandırmamalı");
});

test("public mode (open + safe + key): /mcp kısıtlı, /c/<key> tam yetkili", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PUBLIC: "open", HARDTOOLS_PUBLIC_TOOLS: "safe", HARDTOOLS_PUBLIC_KEY: KEY });

  const anon = parse(await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })).result.tools.map((x) => x.name);
  assert.equal(anon.includes("ht_shell"), false, "/mcp adsız kimlik kısıtlı kalmalı");
  assert.ok(anon.includes("ht_read"), anon.join(","));

  const keyed = parse(await rpc(port, `/c/${KEY}`, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })).result.tools.map((x) => x.name);
  assert.ok(keyed.includes("ht_shell"), "anahtar kimliği tam set almalı: " + keyed.join(","));
});

test("public mode (open + all + ANON=1): tam araç seti girişsiz, keşif yine 404", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PUBLIC: "open", HARDTOOLS_PUBLIC_TOOLS: "all", HARDTOOLS_PUBLIC_ANON: "1" });
  const health = JSON.parse((await request(port, { target: "/healthz" })).body);
  assert.equal(health.login, "none");
  const init = await rpc(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal(init.status, 200, init.body);
  const names = parse(await rpc(port, "/mcp", { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })).result.tools.map((x) => x.name);
  assert.ok(names.includes("ht_shell") && names.includes("ht_write") && names.includes("ht_delete_var"), names.join(","));
  assert.equal((await request(port, { target: "/.well-known/oauth-protected-resource" })).status, 404);
});
