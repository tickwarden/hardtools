// 0.5.9 — oturum (sohbet) bazlı çalışma alanı: her MCP oturumu kendi /work kökünü alır.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const KEY = "s".repeat(4) + "0123456789abcdef0123456789abcdef";
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));

function request(port, { method = "GET", target, headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = ""; res.on("data", (c) => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}
const parse = (res) => {
  const line = res.body.split("\n").find((l) => l.startsWith("data: "));
  return line ? JSON.parse(line.slice(6)) : JSON.parse(res.body);
};
async function rpc(port, target, payload, sid) {
  const res = await request(port, { method: "POST", target, body: JSON.stringify(payload),
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(sid ? { "mcp-session-id": sid } : {}) } });
  return { ...res, json: parse(res) };
}
const tool = async (port, target, name, args, sid) => (await rpc(port, target, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, sid)).json;
const init = (port, target) => rpc(port, target, { jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });

async function start(t, env = {}) {
  const root = tmp("ht-sess-root-");
  const audit = tmp("ht-sess-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  // Boş port bul: rastgele seçim paralel testlerle çakışabiliyor (flaky).
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
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

test("iki ayrı sohbet (initialize) ayrı kök alır; aynı sohbet aynı kökte kalır", async (t) => {
  const { port } = await start(t);
  const target = `/c/${KEY}`;

  const a = await init(port, target);
  const sidA = a.headers["mcp-session-id"];
  assert.ok(sidA, "initialize bir oturum kimliği döndürmeli: " + JSON.stringify(a.headers));
  await tool(port, target, "ht_shell", { argv: ["node","-e","require('fs').writeFileSync('sohbet-a.txt','A')"] }, sidA);

  const b = await init(port, target);
  const sidB = b.headers["mcp-session-id"];
  assert.ok(sidB && sidB !== sidA, "her sohbet ayrı oturum kimliği: " + sidB);

  const seenByB = JSON.stringify(await tool(port, target, "ht_shell", { argv: ["cat","sohbet-a.txt"] }, sidB));
  assert.match(seenByB, /isError|not found|ENOENT|yok/i, "B sohbeti A'nın dosyasını görmemeli: " + seenByB.slice(0, 160));

  const stillA = JSON.stringify(await tool(port, target, "ht_shell", { argv: ["cat","sohbet-a.txt"] }, sidA));
  assert.match(stillA, /sohbet-a\.txt/, "A kendi dosyasını görmeli: " + stillA.slice(0, 160));

  const statusOf = async (sid) => JSON.parse((await tool(port, target, "ht_status", {}, sid)).result.content[0].text);
  const stA = await statusOf(sidA), stB = await statusOf(sidB);
  assert.match(stA.session, /^s-/, "ht_status oturum kimliğini göstermeli");
  assert.notEqual(stA.session, stB.session, "iki sohbet iki ayrı oturum olmalı");
  assert.notEqual(stA.roots[0], stB.roots[0], "iki sohbet iki ayrı kök olmalı");
});

test("oturum kimliği yoksa hesap köküne düşer (geriye dönük uyum)", async (t) => {
  const { port, root } = await start(t);
  const target = `/c/${KEY}`;
  await tool(port, target, "ht_shell", { argv: ["node","-e","require('fs').writeFileSync('kimliksiz.txt','x')"] });
    const dirs = fs.readdirSync(root).filter((d) => d.startsWith("a-"));
  assert.equal(dirs.length, 1, "hesap kökü: " + fs.readdirSync(root).join(","));
  assert.equal(fs.existsSync(path.join(root, dirs[0], "kimliksiz.txt")), true);
});

test("HARDTOOLS_PER_SESSION_WORKSPACE=0 ile eski paylaşılan kök korunur", async (t) => {
  const { port, root } = await start(t, { HARDTOOLS_PER_SESSION_WORKSPACE: "0" });
  const target = `/c/${KEY}`;
  const a = await init(port, target);
  await tool(port, target, "ht_shell", { argv: ["node","-e","require('fs').writeFileSync('ortak.txt','herkes')"] }, a.headers["mcp-session-id"]);
  assert.equal(fs.existsSync(path.join(root, "ortak.txt")), true, "paylaşılan kökte olmalı");
});
