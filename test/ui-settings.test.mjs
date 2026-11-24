// 0.5.11 — ortak arayüz (tema + tek gönderim), ayar sayfası, araç yönetimi, arka plan komut.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const TOKEN = "a".repeat(64);

function req(port, { method = "GET", target, headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = ""; res.on("data", (c) => { data += c; }); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    r.on("error", reject); if (body !== null) r.write(body); r.end();
  });
}

async function httpServer(t, env = {}) {
  const root = tmp("ht-ui-root-"), audit = tmp("ht-ui-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const probe = http.createServer(); await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port; await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`,
      HARDTOOLS_STATE_DIR: path.join(audit, "state"), HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1", ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 80; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, err);
  return { port, root, audit };
}

const mcp = async (port, token, name, args = {}) => {
  const c = new Client({ name: "t", version: "1" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  try {
    const tools = (await c.listTools()).tools.map(t => t.name);
    const r = name ? await c.callTool({ name, arguments: args }) : null;
    return { tools, text: r ? r.content[0].text : "", isError: r?.isError };
  } finally { await c.close(); }
};

test("tüm tarayıcı sayfaları ortak arayüzü kullanır: koyu/kör mod + tek gönderim koruması + CSS", async (t) => {
  const { port } = await httpServer(t);
  for (const target of ["/settings", "/settings/login"]) {
    const r = await req(port, { target });
    assert.equal(r.status, 200, target + " " + r.body.slice(0, 120));
    assert.match(r.body, /data-theme-set="dark"/, target + ": koyu mod düğmesi");
    assert.match(r.body, /data-theme-set="light"/, target + ": kör mod düğmesi");
    assert.match(r.body, /:root\[data-theme="light"\]/, target + ": tema CSS'i");
    assert.match(r.body, /İşleniyor/, target + ": tek gönderim koruması");
    assert.match(r.body, /btn\.disabled=true/, target + ": buton disable mantığı");
    assert.match(String(r.headers["content-security-policy"]), /default-src 'none'/);
  }
});

test("ayar sayfası: giriş, kaydetme, araç kapatma ve çıkış", async (t) => {
  const { port } = await httpServer(t);

  const denied = await req(port, { method: "POST", target: "/settings/save", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "tool=ht_read" });
  assert.equal(denied.status, 200);
  assert.match(denied.body, /GitHub ile giriş/, "oturum yoksa giriş sayfası");

  const login = await req(port, { method: "POST", target: "/settings/token", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: TOKEN }).toString() });
  assert.equal(login.status, 303);
  const cookie = String(login.headers["set-cookie"]).split(";")[0];
  assert.match(cookie, /^ht_s=/);

  const pageOk = await req(port, { target: "/settings", headers: { cookie } });
  assert.equal(pageOk.status, 200);
  assert.match(pageOk.body, /Araçlar/);
  assert.match(pageOk.body, /ht_shell/);

  // ht_shell'i kapat: formdan yalnızca açık kalanlar gelir
  const keep = ["ht_read", "ht_status"];
  const save = await req(port, {
    method: "POST", target: "/settings/save", headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams([["tool", keep[0]], ["tool", keep[1]], ["networkEnabled", "1"], ["addUrl", "api.github.com"], ["addCommand", "git"]]).toString(),
  });
  assert.equal(save.status, 303);

  const after = await mcp(port, TOKEN);
  assert.ok(!after.tools.includes("ht_shell"), "kapatılan araç listelenmemeli: " + after.tools.join(","));
  assert.ok(after.tools.includes("ht_read"));

  // çıkış: çerez silinir, iptal raporlanır
  const out = await req(port, { method: "POST", target: "/settings/logout", headers: { cookie } });
  assert.equal(out.status, 200);
  assert.match(out.body, /Çıkış yapıldı/);
  assert.match(String(out.headers["set-cookie"]), /Max-Age=0/);
});

test("ht_list_all_tools ve ht_manage_tool araçları açıp kapatır", async (t) => {
  const { port } = await httpServer(t);
  const first = await mcp(port, TOKEN, "ht_list_all_tools", {});
  const listed = JSON.parse(first.text);
  assert.ok(listed.total >= 24, "katalog: " + listed.total);
  assert.equal(listed.disabled, 0);

  const off = JSON.parse((await mcp(port, TOKEN, "ht_manage_tool", { tool: "ht_fetch", enabled: false })).text);
  assert.equal(off.changed, true);
  assert.deepEqual(off.disabled, ["ht_fetch"]);

  const hidden = await mcp(port, TOKEN);
  assert.ok(!hidden.tools.includes("ht_fetch"), "kapalı araç listelenmemeli");
  assert.ok(hidden.tools.includes("ht_manage_tool"), "yönetim aracı her zaman açık");

  const back = JSON.parse((await mcp(port, TOKEN, "ht_manage_tool", { tool: "ht_fetch", enabled: true })).text);
  assert.deepEqual(back.disabled, []);
  assert.ok((await mcp(port, TOKEN)).tools.includes("ht_fetch"));

  const protectedTool = await mcp(port, TOKEN, "ht_manage_tool", { tool: "ht_manage_tool", enabled: false });
  assert.equal(protectedTool.isError, true);
});

test("ht_shell is_bg=true: arka planda çalışır, çıktı dosyasına yazar (stdio)", async () => {
  const root = tmp("ht-bg-root-"), audit = tmp("ht-bg-audit-");
  const client = new Client({ name: "t", version: "0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry, "--profile", "open"], env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_AUDIT_DIR: audit, HARDTOOLS_SHELL_ENABLED: "1" }, stderr: "ignore" }));
  try {
    const r = await client.callTool({ name: "ht_shell", arguments: { argv: ["sh", "-c", "sleep 0.4; echo arka-plan-tamam"], is_bg: true } });
    const info = JSON.parse(r.content[0].text);
    assert.equal(info.status, "started");
    assert.match(info.output_file, /^\/work\/home\/tmp\/hardtools-bg-out-.+-\d+\.txt$/);
    const local = path.join(root, "home", "tmp", path.basename(info.output_file));
    let out = "";
    for (let i = 0; i < 60; i++) { if (fs.existsSync(local)) { out = fs.readFileSync(local, "utf8"); if (out.includes("# bitti:")) break; } await new Promise((r2) => setTimeout(r2, 100)); }
    assert.match(out, /arka-plan-tamam/, "çıktı dosyaya yazılmalı");
    assert.match(out, /# bitti: exit=0/, "bitiş satırı yazılmalı");
  } finally { await client.close(); }
});

test("allowlist: izinli komut çalışır, izinsiz komut reddedilir", async () => {
  const root = tmp("ht-al-root-"), audit = tmp("ht-al-audit-");
  const mk = async (env) => {
    const c = new Client({ name: "t", version: "0" });
    await c.connect(new StdioClientTransport({ command: process.execPath, args: [entry, "--profile", "open"], env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_AUDIT_DIR: audit, HARDTOOLS_SHELL_ENABLED: "1", ...env }, stderr: "ignore" }));
    return c;
  };
  const plain = await mk({});
  await plain.close();
  // allowlist politika dosyasıyla
  const cfg = path.join(audit, "allow.json");
  fs.mkdirSync(audit, { recursive: true });
  fs.writeFileSync(cfg, JSON.stringify({ shell: { enabled: true, allowCommands: ["echo"] } }));
  const c = await mk({ HARDTOOLS_CONFIG: cfg });
  try {
    const ok = await c.callTool({ name: "ht_shell", arguments: { argv: ["echo", "selam"] } });
    assert.ok(!ok.isError, ok.content[0].text);
    const bad = await c.callTool({ name: "ht_shell", arguments: { argv: ["ls"] } });
    assert.equal(bad.isError, true);
    assert.match(bad.content[0].text, /command_not_allowed/);
  } finally { await c.close(); }
});

test("bot kapısı: tarayıcıdan aynı origin POST kabul, yabancı origin 403", async (t) => {
  const { port } = await httpServer(t);
  const origin = `http://127.0.0.1:${port}`;
  // aynı origin + geçersiz token: 403 değil, doğrulama hatası dönmeli
  const own = await req(port, { method: "POST", target: "/oauth/human",
    headers: { origin, "content-type": "application/x-www-form-urlencoded" }, body: "h=uydurma&answer=4&website=" });
  assert.notEqual(own.status, 403, "aynı origin'den gelen form reddedilmemeli: " + own.body);
  assert.match(own.body, /İnsan doğrulaması|süresi doldu/i);

  const evil = await req(port, { method: "POST", target: "/oauth/human",
    headers: { origin: "https://kotu.example", "content-type": "application/x-www-form-urlencoded" }, body: "h=x&answer=4" });
  assert.equal(evil.status, 403);
  assert.match(evil.body, /browser origins are not allowed/);
});

test("ayar formu da aynı origin'den gönderilebilir", async (t) => {
  const { port } = await httpServer(t);
  const origin = `http://127.0.0.1:${port}`;
  const login = await req(port, { method: "POST", target: "/settings/token", headers: { origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: TOKEN }).toString() });
  assert.equal(login.status, 303, login.body);
  const cookie = String(login.headers["set-cookie"]).split(";")[0];
  const save = await req(port, { method: "POST", target: "/settings/save", headers: { origin, cookie, "content-type": "application/x-www-form-urlencoded" }, body: "tool=ht_read" });
  assert.equal(save.status, 303, save.body);
});
