// 1.5.36: sayfa bağlantılarının kırık olmaması + çıkış akışının gerçekten çalışması.
// Kullanıcının gördüğü hata: "çıkış yap" bağlantısı /settings/logout'a gidiyordu ama o yol yalnız
// POST kabul ettiği için 405 "Yalnız POST" dönüyordu — oturum kapanmıyordu.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const TOKEN = "l".repeat(4) + "0123456789abcdef0123456789abcdef";
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const enc = (o) => new URLSearchParams(o).toString();

function request(port, { method = "GET", target = "/", headers = {}, body = null } = {}) {
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

async function boot(t, env = {}) {
  const root = tmp("ht-link-root-");
  const audit = tmp("ht-link-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const stateDir = path.join(audit, "state");
  const baseEnv = { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_STATE_DIR: stateDir };
  spawnSync(process.execPath, [entry, "--local-user", "add", "sahip", "--password", "Ilk-Parola-42x"], { env: baseEnv, encoding: "utf8", input: "" });
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...baseEnv, HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, HARDTOOLS_LOCAL_SIGNUP: "first", HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "", HARDTOOLS_OAUTH_ALLOWED_LOGINS: "", ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 100; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => { child.kill("SIGKILL"); fs.rmSync(root, { recursive: true, force: true }); });
  assert.match(err, /listening/, err);
  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  assert.equal(login.status, 303);
  const cookie = login.headers["set-cookie"][0].split(";")[0];
  return { port, cookie, root, stateDir };
}

const PAGES = ["/", "/local", "/settings", "/workspaces", "/connect", "/device", "/operator"];

test("tüm sayfalardaki dahili bağlantılar 404/405 vermez", async (t) => {
  const { port, cookie } = await boot(t);
  const seen = new Set();
  for (const page of PAGES) {
    const r = await request(port, { target: page, headers: { cookie } });
    assert.equal(r.status, 200, `${page} → ${r.status}`);
    for (const m of r.body.matchAll(/href="(\/[^"#?]*)/g)) seen.add(m[1]);
  }
  assert.ok(seen.size > 3, "bağlantılar bulunmalı: " + [...seen].join(","));
  for (const link of seen) {
    const r = await request(port, { target: link, headers: { cookie } });
    assert.ok(r.status < 400, `${link} → ${r.status} (kırık bağlantı)`);
  }
});

test("çıkış: bağlantı onay sayfası verir, POST oturumu gerçekten kapatır", async (t) => {
  const { port, cookie } = await boot(t);
  // Panelde çıkış düğmesi POST formu olmalı (eski hâlde GET bağlantısı 405 alıyordu).
  const panel = await request(port, { target: "/", headers: { cookie } });
  assert.match(panel.body, /<form method="post" action="\/settings\/logout"/, "panelde çıkış POST formu olmalı");
  assert.doesNotMatch(panel.body, /<a href="\/settings\/logout"/, "GET bağlantısı kalmamalı");

  const page = await request(port, { target: "/settings/logout", headers: { cookie } });
  assert.equal(page.status, 200, "GET çıkış 405 değil onay sayfası olmalı");
  assert.match(page.body, /Çıkış yap/);

  const out = await request(port, { method: "POST", target: "/settings/logout", headers: { ...FORM, cookie } });
  assert.equal(out.status, 200);
  assert.match(out.headers["set-cookie"][0], /Max-Age=0/, "çerez silinmeli");

  // Eski çerez artık kimlik vermez.
  const after = await request(port, { target: "/workspaces", headers: { cookie } });
  assert.doesNotMatch(after.body, /<title>Çalışma alanları/, "çıkıştan sonra oturum geçersiz olmalı");
  const local = await request(port, { target: "/local", headers: { cookie } });
  assert.doesNotMatch(local.body, /Giriş: sahip/);
  assert.match(local.body, /action="\/local\/login"/, "giriş formu geri gelmeli");
});

test("MCP bağlantı adresi: yanlış anahtar 401, yenilenen anahtar eskisini geçersiz kılar", async (t) => {
  const { port, cookie } = await boot(t);
  const page = await request(port, { target: "/local", headers: { cookie } });
  const key = /\/lc\/([A-Za-z0-9_-]{16,})/.exec(page.body)?.[1];
  assert.ok(key, "kişisel bağlantı anahtarı gösterilmeli");

  const rpc = async (target) => request(port, { method: "POST", target, headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } }) });
  assert.equal((await rpc(`/lc/${key}`)).status, 200, "doğru anahtarla MCP açılmalı");
  assert.equal((await rpc(`/lc/${"A".repeat(43)}`)).status, 401, "yanlış anahtar 401");

  const rot = await request(port, { method: "POST", target: "/local/connector", headers: { ...FORM, cookie } });
  assert.equal(rot.status, 303);
  const page2 = await request(port, { target: "/local", headers: { cookie } });
  const key2 = /\/lc\/([A-Za-z0-9_-]{16,})/.exec(page2.body)?.[1];
  assert.ok(key2 && key2 !== key, "anahtar yenilenmeli");
  assert.equal((await rpc(`/lc/${key}`)).status, 401, "eski anahtar geçersiz olmalı");
  assert.equal((await rpc(`/lc/${key2}`)).status, 200, "yeni anahtar çalışmalı");
});
