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
  const stateDir = path.join(audit, "state");
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
  return { port, root, stateDir };
}

test("varsayılan: bir hesabın tüm sohbetleri aynı hesap kökünü paylaşır", async (t) => {
  const { port, root } = await start(t);
  const target = `/c/${KEY}`;

  const a = await init(port, target);
  const sidA = a.headers["mcp-session-id"];
  await tool(port, target, "ht_write", { path: "sohbet-a.txt", content: "A" }, sidA);

  const b = await init(port, target);
  const sidB = b.headers["mcp-session-id"];

  // 1.5.37: yeni sohbet aynı hesap kökünde çalışır → önceki sohbetin dosyasını görür.
  const seenByB = JSON.stringify(await tool(port, target, "ht_read", { path: "sohbet-a.txt" }, sidB));
  assert.match(seenByB, /sohbet-a\.txt/, "B sohbeti A'nın dosyasını görmeli: " + seenByB.slice(0, 160));

  // Dosya taban kökte değil, hesap kökünde (a-…) olmalı: hesaplar ayrı kalır.
  assert.equal(fs.existsSync(path.join(root, "sohbet-a.txt")), false, "taban kökte dosya olmamalı");
  const acc = fs.readdirSync(root).filter((d) => d.startsWith("a-"));
  assert.equal(acc.length, 1, "tek hesap kökü: " + fs.readdirSync(root).join(","));
  assert.equal(fs.existsSync(path.join(root, acc[0], "sohbet-a.txt")), true, "dosya hesap kökünde olmalı");

  const statusOf = async (sid) => JSON.parse((await tool(port, target, "ht_status", {}, sid)).result.content[0].text);
  const stA = await statusOf(sidA), stB = await statusOf(sidB);
  assert.equal(stA.roots[0], stB.roots[0], "iki sohbet aynı kökü kullanmalı");
  assert.match(stA.roots[0], /a-[0-9a-f]{16}$/, "kök hesap kökü olmalı: " + stA.roots[0]);
});

test("HARDTOOLS_PER_SESSION_WORKSPACE=1 ile sohbet başına ayrı kök (katı izolasyon)", async (t) => {
  const { port } = await start(t, { HARDTOOLS_PER_SESSION_WORKSPACE: "1" });
  const target = `/c/${KEY}`;
  const a = await init(port, target);
  const sidA = a.headers["mcp-session-id"];
  await tool(port, target, "ht_write", { path: "sohbet-a.txt", content: "A" }, sidA);
  const b = await init(port, target);
  const sidB = b.headers["mcp-session-id"];
  const seenByB = JSON.stringify(await tool(port, target, "ht_read", { path: "sohbet-a.txt" }, sidB));
  assert.match(seenByB, /isError|not found|ENOENT|yok/i, "katı modda B, A'nın dosyasını görmemeli: " + seenByB.slice(0, 160));
});

test("oturum kimliği yoksa hesap köküne düşer (geriye dönük uyum)", async (t) => {
  const { port, root } = await start(t);
  const target = `/c/${KEY}`;
  await tool(port, target, "ht_write", { path: "kimliksiz.txt", content: "x" });
    const dirs = fs.readdirSync(root).filter((d) => d.startsWith("a-"));
  assert.equal(dirs.length, 1, "hesap kökü: " + fs.readdirSync(root).join(","));
  assert.equal(fs.existsSync(path.join(root, dirs[0], "kimliksiz.txt")), true);
});

test("hesaplar birbirinden ayrı: iki yerel hesap aynı dosyayı görmez", async (t) => {
  const { port, root, stateDir } = await start(t, { HARDTOOLS_LOCAL_SIGNUP: "open" });
  const reg = async (user) => {
    const r = await request(port, { method: "POST", target: "/local/register",
      headers: { "content-type": "application/x-www-form-urlencoded" }, body: `user=${user}&password=${"Guclu-Parola-77y"}` });
    return r.status;
  };
  assert.equal(await reg("ali"), 303);
  assert.equal(await reg("veli"), 303);
  const accounts = JSON.parse(fs.readFileSync(path.join(stateDir, "local-accounts.json"), "utf8")).items;
  const key = (u) => accounts.find((a) => a.user === u).connector;

  const ali = await init(port, `/lc/${key("ali")}`);
  await tool(port, `/lc/${key("ali")}`, "ht_write", { path: "ali.txt", content: "ali" }, ali.headers["mcp-session-id"]);
  const veli = await init(port, `/lc/${key("veli")}`);
  const seen = JSON.stringify(await tool(port, `/lc/${key("veli")}`, "ht_read", { path: "ali.txt" }, veli.headers["mcp-session-id"]));
  assert.match(seen, /isError|not found|ENOENT|yok/i, "veli, ali'nin dosyasını görmemeli: " + seen.slice(0, 200));
  const aliAgain = JSON.stringify(await tool(port, `/lc/${key("ali")}`, "ht_read", { path: "ali.txt" }, ali.headers["mcp-session-id"]));
  assert.match(aliAgain, /ali\.txt/, "ali kendi dosyasını görmeli: " + aliAgain.slice(0, 200));
  const dirs = fs.readdirSync(root).filter((d) => d.startsWith("a-"));
  assert.equal(dirs.length, 2, "iki hesap iki kök: " + fs.readdirSync(root).join(","));
});
