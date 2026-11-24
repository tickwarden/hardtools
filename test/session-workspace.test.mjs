// 0.5.8 — oturum bazlı çalışma alanı: her kimlik kendi /work kökünü alır.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const KEY = "k".repeat(4) + "0123456789abcdef0123456789abcdef";
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));

function request(port, { method = "GET", target, headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = ""; res.on("data", (c) => { data += c; }); res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}
const rpc = (port, target, payload) => request(port, {
  method: "POST", target, body: JSON.stringify(payload),
  headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
});
const parse = (res) => {
  const line = res.body.split("\n").find((l) => l.startsWith("data: "));
  return line ? JSON.parse(line.slice(6)) : JSON.parse(res.body);
};
const call = async (port, target, name, args) => parse(await rpc(port, target, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }));

async function start(t, env = {}) {
  const root = tmp("ht-sess-root-");
  const audit = tmp("ht-sess-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`,
      HARDTOOLS_PUBLIC: "open", HARDTOOLS_PUBLIC_KEY: KEY, HARDTOOLS_PUBLIC_TOOLS: "safe", HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1", ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 80; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, err);
  return { port, root };
}

test("oturum kökleri ayrı: /c/<anahtar> ile yazılan dosya anonim oturumda görünmez", async (t) => {
  const { port, root } = await start(t);

  const w = await call(port, `/c/${KEY}`, "ht_write", { path: "gizli.txt", content: "sadece bu oturum" });
  assert.equal(w.result?.isError, undefined, JSON.stringify(w).slice(0, 200));

  // aynı sunucu, farklı kimlik (anonim /mcp)
  const r = await call(port, "/mcp", "ht_read", { path: "gizli.txt" });
  const text = JSON.stringify(r);
  assert.match(text, /isError|not found|yok|ENOENT/i, "anonim oturum dosyayı görmemeli: " + text.slice(0, 200));

  // iki ayrı kök dizini oluştu
  const userDirs = fs.readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory() && d.name.startsWith("u-"));
  assert.equal(userDirs.length >= 1, true, "kimlik başına kök açılmalı: " + userDirs.map((d) => d.name).join(","));
});

test("HARDTOOLS_PER_SESSION_WORKSPACE=0 ile eski paylaşılan kök korunur", async (t) => {
  const { port, root } = await start(t, { HARDTOOLS_PER_SESSION_WORKSPACE: "0" });
  await call(port, `/c/${KEY}`, "ht_write", { path: "ortak.txt", content: "herkes" });
  const r = await call(port, "/mcp", "ht_read", { path: "ortak.txt" });
  assert.equal(JSON.stringify(r).includes("ortak.txt") || !JSON.stringify(r).includes("isError"), true);
  assert.equal(fs.existsSync(path.join(root, "ortak.txt")), true, "paylaşılan kökte olmalı");
});
