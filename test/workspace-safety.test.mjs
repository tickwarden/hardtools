// 1.5.31: çalışma alanı güvenliği ve sürekliliği için koruma testleri.
//   - hesap kökü kullanıcıya bağlı: yeni sohbet kökü hesap kökünün kopyasıyla tohumlanır,
//     ama sohbetler birbirinin dosyasını görmez,
//   - ht_workspace: başka hesabın dizini listelenmez ve devralınamaz; sahibi bilinmeyen dizin
//     ilk devralan hesaba kilitlenir,
//   - ht_shell: kabuk iskeleti dışarıdan silinse bile kendini onarır (bwrap varsa).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const KEY = "k".repeat(4) + "0123456789abcdef0123456789abcdef";
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));

function request(port, { method = "GET", target = "/", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = ""; res.on("data", (c) => { data += c; }); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

async function start(t, env = { shell: false }) {
  const root = tmp("ht-safety-root-");
  const state = tmp("ht-safety-state-");
  const audit = tmp("ht-safety-audit-");
  const cfg = path.join(audit, "config.json");
  // Kabuk yalnızca isteyen testte açılır: bwrap yoksa sunucu bilerek açılmaz (fail-closed).
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: Boolean(env.shell) } }));
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_STATE: state,
      HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, HARDTOOLS_PUBLIC: "open", HARDTOOLS_PUBLIC_KEY: KEY,
      HARDTOOLS_PUBLIC_TOOLS: "all", HARDTOOLS_PUBLIC_ANON: "1", HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1", ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 100; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, err);
  return { port, root, state, audit };
}

const rpcFactory = (port) => async (payload, sid) => {
  const r = await request(port, { method: "POST", target: `/c/${KEY}`,
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(sid ? { "mcp-session-id": sid } : {}) },
    body: JSON.stringify(payload) });
  const line = r.body.split("\n").find((l) => l.startsWith("data: "));
  return { status: r.status, headers: r.headers, json: JSON.parse(line ? line.slice(6) : r.body) };
};
const init = (rpc) => rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
const call = (rpc, name, args, sid) => rpc({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: args } }, sid);
const textOf = (r) => JSON.stringify(r.json?.result?.content?.[0]?.text ?? r.json);

test("hesap kökü kalıcı: aynı hesabın sohbetleri ortak kökü paylaşır (1.5.37 varsayılanı)", async (t) => {
  const { port, root } = await start(t);
  const rpc = rpcFactory(port);
  // Oturum kimliği yok → hesap kökü (kalıcı alan).
  await call(rpc, "ht_write", { path: "kalici.txt", content: "oncesi" });
  const accDirs = fs.readdirSync(root).filter((d) => d.startsWith("a-"));
  assert.equal(accDirs.length, 1, "tek hesap kökü: " + fs.readdirSync(root).join(","));
  assert.ok(fs.existsSync(path.join(root, accDirs[0], "kalici.txt")), "yazma hesap köküne düşmeli");
  // Yeni sohbet: kendi u- kökünü alır ama hesap kökündeki iş tohumlanır (yeniden başlatma sonrası devam).
  const a = await init(rpc);
  const sidA = a.headers["mcp-session-id"];   // ortak modda oturum kimliği verilmez (stateless)
  assert.match(textOf(await call(rpc, "ht_read", { path: "kalici.txt" }, sidA)), /oncesi/, "tohumlanan dosya görünmeli");
  // Varsayılan (1.5.37): aynı hesabın sohbetleri ortak kökü paylaşır → B, A'nın yazdığını görür.
  await call(rpc, "ht_write", { path: "sadece-a.txt", content: "A" }, sidA);
  const b = await init(rpc);
  const sidB = b.headers["mcp-session-id"];
  assert.match(textOf(await call(rpc, "ht_read", { path: "sadece-a.txt" }, sidB)), /sadece-a\.txt/, "B, A'nın dosyasını görmeli");
  assert.match(textOf(await call(rpc, "ht_read", { path: "sadece-a.txt" }, sidA)), /sadece-a\.txt/, "A kendi dosyasını görmeli");
  const acc = fs.readdirSync(root).filter((d) => d.startsWith("a-"));
  assert.equal(acc.length, 1, "tek hesap kökü: " + fs.readdirSync(root).join(","));
  assert.ok(fs.existsSync(path.join(root, acc[0], "sadece-a.txt")), "dosya hesap kökünde olmalı");
});

test("ht_workspace: başka hesabın dizini görünmez/devralınamaz; sahipsiz dizini yalnız operatör devralır", async (t) => {
  const { port, root, state, audit } = await start(t);
  const rpc = rpcFactory(port);
  const other = path.join(root, "u-00000000000000ff");
  fs.mkdirSync(other, { recursive: true });
  fs.writeFileSync(path.join(other, "gizli.txt"), "x");
  fs.writeFileSync(path.join(other, ".ht-owner"), JSON.stringify({ owner: "grant:baska", user: "baska-hesap" }));
  const legacy = path.join(root, "u-1111111111111111");
  fs.mkdirSync(legacy, { recursive: true });
  fs.writeFileSync(path.join(legacy, "eski-is.txt"), "y");

  const list = textOf(await call(rpc, "ht_workspace", { action: "list" }));
  assert.doesNotMatch(list, /u-00000000000000ff/, "başka hesabın dizini listelenmemeli");
  assert.doesNotMatch(list, /u-1111111111111111/, "sahibi bilinmeyen dizin normal kullanıcıya görünmemeli");
  const denied = textOf(await call(rpc, "ht_workspace", { action: "adopt", dir: "u-00000000000000ff" }));
  assert.match(denied, /denied_path|başka bir hesaba ait/, "başka hesabın dizini devralınamaz");

  // Operatör (statik bearer) sahipsiz dizini görür ve devralır → dizin o hesaba kilitlenir.
  const stop = { killed: false };
  t.after(() => { if (!stop.killed) stop.killed = true; });
  const TOKEN = "o".repeat(4) + "0123456789abcdef0123456789abcdef";
  const probe = http.createServer(); await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port2 = probe.address().port; await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port2), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_STATE: state, HARDTOOLS_CONFIG: audit + "/config.json",
      HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port2}`, HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1" },
    stdio: ["ignore", "ignore", "pipe"] });
  let err2 = ""; child.stderr.on("data", (d) => { err2 += d; });
  t.after(() => child.kill("SIGKILL"));
  for (let i = 0; i < 100; i++) { if (/listening/.test(err2) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  assert.match(err2, /listening/, err2);
  const opRpc = async (payload) => {
    const r = await request(port2, { method: "POST", target: "/mcp",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify(payload) });
    const line = r.body.split("\n").find((l) => l.startsWith("data: "));
    return { status: r.status, json: JSON.parse(line ? line.slice(6) : r.body) };
  };
  const opList = JSON.stringify((await opRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "ht_workspace", arguments: { action: "list" } } })).json);
  assert.match(opList, /u-1111111111111111/, "operatör sahipsiz dizini görmeli: " + opList.slice(0, 160));
  assert.doesNotMatch(opList, /u-00000000000000ff/, "operatör de başka hesabın dizinini görmemeli");
  const claimed = JSON.stringify((await opRpc({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "ht_workspace", arguments: { action: "adopt", dir: "u-1111111111111111" } } })).json);
  assert.match(claimed, /taşındı/, "sahipsiz dizin operatörce devralınabilmeli: " + claimed.slice(0, 160));
  const marker = JSON.parse(fs.readFileSync(path.join(legacy, ".ht-owner"), "utf8"));
  assert.match(marker.owner, /^adopted-by:/, "devralan hesap işaretlenmeli");
});

test("ht_shell: silinen kabuk iskeleti kendini onarır", { skip: spawnSync("bash", ["-c", "command -v bwrap"], { encoding: "utf8" }).status !== 0 ? "Linux bubblewrap not installed" : false }, async (t) => {
  const { port, root } = await start(t, { shell: true });
  const rpc = rpcFactory(port);
  const a = await init(rpc);
  const sid = a.headers["mcp-session-id"];
  const first = await call(rpc, "ht_shell", { command: "echo ilk" }, sid);
  assert.match(textOf(first), /ilk/, "kabuk çalışmalı: " + textOf(first).slice(0, 200));
  const roots = fs.readdirSync(root).filter((d) => d.startsWith("u-"));
  assert.equal(roots.length, 1, "tek sohbet kökü");
  // İskeleti dışarıdan sil (devralma/temizlik sonrası durum).
  fs.rmSync(path.join(root, roots[0], ".hardtools"), { recursive: true, force: true });
  const second = await call(rpc, "ht_shell", { command: "echo ikinci" }, sid);
  const out = textOf(second);
  assert.doesNotMatch(out, /Can't find source path|bwrap:/i, "iskelet yeniden kurulmalı, bwrap hatası olmamalı: " + out.slice(0, 200));
  assert.match(out, /ikinci/, "kabuk iskelet silindikten sonra da çalışmalı");
  assert.ok(fs.existsSync(path.join(root, roots[0], ".hardtools", "tmp")), "iskelet yeniden kurulmalı");
});
