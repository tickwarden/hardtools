// 1.5.40: ht_operator — yönetici panelinin yaptığı HER ŞEYİ sohbetten yapan araç.
// Kabul kriterleri (kullanıcı isteği):
//   - HARDTOOLS_OPERATOR_TOKEN olmadan çalışmaz (anahtar yoksa araç hiç duyurulmaz).
//   - action=login → tek kullanımlık bağlantı; kullanıcı UI'da anahtarı yazınca oturum açılır.
//   - action=set → ayar günceller + hesap işlemleri; action=get → hesap verisi / davet kodu
//     (kod SENSRÜLÜ yazılır); action=logout → çıkış; yıkıcı işlemler `confirm` ister.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const TOKEN = "o".repeat(4) + "0123456789abcdef0123456789abcdef";
const OP = "operator-anahtar-0123456789";
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const enc = (o) => new URLSearchParams(o).toString();
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));

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
const parse = (res) => {
  const line = res.body.split("\n").find((l) => l.startsWith("data: "));
  return line ? JSON.parse(line.slice(6)) : JSON.parse(res.body);
};
async function rpc(port, target, payload, sid) {
  const res = await request(port, { method: "POST", target, body: JSON.stringify(payload),
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream",
      authorization: `Bearer ${TOKEN}`, ...(sid ? { "mcp-session-id": sid } : {}) } });
  return { ...res, json: parse(res) };
}
const init = (port, target) => rpc(port, target, { jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
const listTools = async (port, target) => (await rpc(port, target, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })).json.result?.tools ?? [];
/** ht_operator çağrısı; metin sonucunu döner. */
async function op(port, target, args, sid) {
  const j = (await rpc(port, target, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "ht_operator", arguments: args } }, sid)).json;
  return j.result?.content?.[0]?.text ?? JSON.stringify(j);
}

async function start(t, env = {}) {
  const root = tmp("ht-opt-root-");
  const audit = tmp("ht-opt-audit-");
  const stateDir = path.join(audit, "state");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_STATE_DIR: stateDir,
      HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1",
      HARDTOOLS_LOCAL_SIGNUP: "first", HARDTOOLS_OPERATOR_TOKEN: OP, ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 120; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, err);
  return { port, root, target: "/mcp", stateDir, audit };
}

/** login bağlantısını tarayıcı gibi tamamlar (anahtarı yazar) → panel çerezi döner. */
async function browserLogin(port, link, key = OP) {
  const post = await request(port, { method: "POST", target: new URL(link).pathname, headers: FORM, body: enc({ token: key }) });
  const raw = [].concat(post.headers["set-cookie"] ?? [])[0] ?? "";
  return { ...post, cookie: /^ht_op=([^;]+)/.exec(raw)?.[1] ?? "" };
}
const revealOf = async (port, text) => {
  const url = /(http:\/\/127\.0\.0\.1:\d+\/operator\/r\/[A-Za-z0-9_-]+)/.exec(text)?.[1];
  assert.ok(url, "tek seferlik bağlantı metinde olmalı: " + text.slice(0, 200));
  const page = await request(port, { target: new URL(url).pathname });
  return { url, status: page.status, value: /id="rv"[^>]*value="([^"]*)"/.exec(page.body)?.[1] ?? "", body: page.body };
};

test("anahtar tanımlı değilse ht_operator hiç duyurulmaz", async (t) => {
  const { port, target } = await start(t, { HARDTOOLS_OPERATOR_TOKEN: "" });
  const names = (await listTools(port, target)).map((x) => x.name);
  assert.ok(!names.includes("ht_operator"), "anahtarsız araç listelenmemeli: " + names.join(","));
});

test("anahtar tanımlıysa araç var; oturum yokken get veri sızdırmaz", async (t) => {
  const { port, target } = await start(t);
  const names = (await listTools(port, target)).map((x) => x.name);
  assert.ok(names.includes("ht_operator"), "araç listelenmeli");
  const txt = await op(port, target, { action: "get" });
  assert.match(txt, /login/, "giriş yolu gösterilmeli");
  assert.match(txt, /HARDTOOLS_OPERATOR_TOKEN/);
  assert.doesNotMatch(txt, /hesap_sayisi/, "oturumsuz veri dönmemeli");
});

test("login: tek kullanımlık bağlantı, yanlış anahtar reddi, doğru anahtarla 30 dk oturum", async (t) => {
  const { port, target } = await start(t);
  const txt = await op(port, target, { action: "login" });
  const link = /(http:\/\/127\.0\.0\.1:\d+\/operator\/link\/[A-Za-z0-9_-]+)/.exec(txt)?.[1];
  assert.ok(link, "bağlantı üretilmeli: " + txt.slice(0, 200));
  const page = await request(port, { target: new URL(link).pathname });
  assert.equal(page.status, 200);
  assert.match(page.body, /HARDTOOLS_OPERATOR_TOKEN/, "UI'da anahtar alanı olmalı");
  const bad = await browserLogin(port, link, "yanlis-anahtar-00000");
  assert.match(bad.body, /Anahtar yanlış/);
  assert.equal(bad.headers["set-cookie"], undefined);
  // Oturum hâlâ yok.
  assert.match(await op(port, target, { action: "get" }), /login/);
  const good = await browserLogin(port, link);
  assert.equal(good.status, 303);
  assert.equal(good.headers.location, "/operator?tool=1");
  // Bağlantı tek kullanımlık.
  const reuse = await browserLogin(port, link);
  assert.notEqual(reuse.status, 303, "aynı bağlantı ikinci kez çalışmamalı");
  const after = await op(port, target, { action: "get" });
  assert.match(after, /hesap_sayisi/, "oturum açıldıktan sonra get çalışmalı");
  assert.equal(reuse.status, 410);
});

test("get: hesap listesi + tek hesap detayı, MCP anahtarı sensürlü", async (t) => {
  const { port, target } = await start(t);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  await browserLogin(port, /(http:\/\/\S+)/.exec(await op(port, target, { action: "login" }))[1]);
  const list = await op(port, target, { action: "get" });
  assert.match(list, /sahip/);
  assert.match(list, /hesap_sayisi/);
  assert.doesNotMatch(list, /"connector"/, "ham anahtar dönmemeli");
  const one = await op(port, target, { action: "get", user: "sahip" });
  assert.match(one, /mcp_adresi/);
  assert.match(one, /•/, "MCP adresi sensürlü olmalı");
  const none = await op(port, target, { action: "get", user: "yokboyle" });
  assert.match(none, /Hesap yok/);
});

test("get invite=true: davet kodu sensürlü yazılır, tamamı yalnızca tek seferlik bağlantıda", async (t) => {
  const { port, target } = await start(t);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  await browserLogin(port, /(http:\/\/\S+)/.exec(await op(port, target, { action: "login" }))[1]);
  const txt = await op(port, target, { action: "get", invite: true, ttl_minutes: 30 });
  assert.match(txt, /Davet kodu üretildi/);
  assert.match(txt, /•/, "kod sensürlü gösterilmeli");
  assert.doesNotMatch(txt, /[A-Z0-9]{4}-[A-Z0-9]{4}/, "kodun tamamı sohbete yazılmamalı");
  const rev = await revealOf(port, txt);
  assert.equal(rev.status, 200);
  assert.match(rev.value, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/, "bağlantıda tam kod olmalı: " + rev.value);
  // Kod gerçekten çalışıyor.
  const reg = await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ code: rev.value, user: "davetli", password: "Kontrol-Davet-9x" }) });
  assert.equal(reg.status, 303, reg.body.slice(0, 200));
});

test("set: hesap aç (parola sensürlü + bağlantı), üretilen parolayla giriş", async (t) => {
  const { port, target } = await start(t);
  await browserLogin(port, /(http:\/\/\S+)/.exec(await op(port, target, { action: "login" }))[1]);
  const txt = await op(port, target, { action: "set", user: "araclaacilan", password: "" });
  assert.match(txt, /Hesap açıldı/);
  assert.match(txt, /•/, "parola sensürlü olmalı");
  const rev = await revealOf(port, txt);
  const m = /^araclaacilan \/ (\S+)$/.exec(rev.value);
  assert.ok(m, "bağlantıda 'kullanıcı / parola' olmalı: " + rev.value);
  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "araclaacilan", password: m[1] }) });
  assert.equal(login.status, 303, "üretilen parolayla giriş çalışmalı");
});

test("set: parola sıfırlama onay ister; onaylanınca eski parola düşer", async (t) => {
  const { port, target } = await start(t);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "sifirlanacak", password: "Eski-Parola-11" }) });
  await browserLogin(port, /(http:\/\/\S+)/.exec(await op(port, target, { action: "login" }))[1]);
  const noConfirm = await op(port, target, { action: "set", user: "sifirlanacak", password: "Yeni-Parola-22" });
  assert.match(noConfirm, /onay/i);
  const done = await op(port, target, { action: "set", user: "sifirlanacak", password: "Yeni-Parola-22", confirm: "sifirlanacak" });
  assert.match(done, /Parola sıfırlandı/);
  const bad = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "sifirlanacak", password: "Eski-Parola-11" }) });
  assert.match(bad.body, /yanlış/i, "eski parola geçersiz olmalı");
  const good = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "sifirlanacak", password: "Yeni-Parola-22" }) });
  assert.equal(good.status, 303);
});

test("set: silme onay ister; onaylanınca hesap ve MCP adresi kapanır", async (t) => {
  const { port, target } = await start(t);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "silinecek", password: "Sil-Parola-31" }) });
  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "silinecek", password: "Sil-Parola-31" }) });
  const cookie = /^ht_s=([^;]+)/.exec([].concat(login.headers["set-cookie"] ?? [])[0] ?? "")?.[1] ?? "";
  const connector = /\/lc\/([A-Za-z0-9_-]{16,})/.exec((await request(port, { target: "/local", headers: { cookie: `ht_s=${cookie}` } })).body)?.[1];
  await browserLogin(port, /(http:\/\/\S+)/.exec(await op(port, target, { action: "login" }))[1]);
  const noConfirm = await op(port, target, { action: "set", user: "silinecek" });
  assert.match(noConfirm, /onay|zaten var/i);
  const done = await op(port, target, { action: "set", user: "silinecek", confirm: "silinecek" });
  assert.match(done, /silindi/);
  const mcp = await request(port, { method: "POST", target: `/lc/${connector}`, headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
  assert.equal(mcp.status, 401, "silinen hesabın MCP adresi 401 dönmeli");
  assert.match(await op(port, target, { action: "get", user: "silinecek" }), /Hesap yok/);
});

test("set: kilit açma ve bağlantı anahtarı yenileme", async (t) => {
  const { port, target } = await start(t);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "kilitli", password: "Kilit-Parola-41" }) });
  // 8 hatalı deneme hesabı kilitler.
  for (let i = 0; i < 9; i++) await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "kilitli", password: "yanlis-parola-000" }) });
  const lockedTry = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "kilitli", password: "Kilit-Parola-41" }) });
  assert.match(lockedTry.body, /Çok fazla hatalı deneme/, "hesap kilitlenmeli");
  await browserLogin(port, /(http:\/\/\S+)/.exec(await op(port, target, { action: "login" }))[1]);
  const unlock = await op(port, target, { action: "set", user: "kilitli", unlock: true });
  assert.match(unlock, /Kilidi açıldı/);
  const ok = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "kilitli", password: "Kilit-Parola-41" }) });
  assert.equal(ok.status, 303, "kilit açıldıktan sonra giriş çalışmalı");
  const login2 = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "kilitli", password: "Kilit-Parola-41" }) });
  const cookie = /^ht_s=([^;]+)/.exec([].concat(login2.headers["set-cookie"] ?? [])[0] ?? "")?.[1] ?? "";
  const oldConn = /\/lc\/([A-Za-z0-9_-]{16,})/.exec((await request(port, { target: "/local", headers: { cookie: `ht_s=${cookie}` } })).body)?.[1];
  const noConfirm = await op(port, target, { action: "set", user: "kilitli", rotate_connector: true });
  assert.match(noConfirm, /confirm|onay/i);
  const rot = await op(port, target, { action: "set", user: "kilitli", rotate_connector: true, confirm: "kilitli" });
  assert.match(rot, /yenilendi/);
  const newConn = /^kilitli \/|lc\//.test(rot) ? await (async () => {
    const rev = await revealOf(port, rot);
    return rev.value;
  })() : "";
  assert.match(newConn, /^[A-Za-z0-9_-]{16,}$/, "yeni anahtar bağlantıda olmalı");
  const oldHit = await request(port, { method: "POST", target: `/lc/${oldConn}`, headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
  assert.equal(oldHit.status, 401, "eski anahtar çalışmamalı");
  const newHit = await request(port, { method: "POST", target: `/lc/${newConn}`, headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
  assert.notEqual(newHit.status, 401, "yeni anahtar çalışmalı");
});

test("set: kayıt modu (open/off/env) panel ve /local ile aynı sonucu verir", async (t) => {
  const { port, target } = await start(t);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  await browserLogin(port, /(http:\/\/\S+)/.exec(await op(port, target, { action: "login" }))[1]);
  const open = await op(port, target, { action: "set", signup: "open" });
  assert.match(open, /open/);
  const form = await request(port, { target: "/local" });
  assert.match(form.body, /name="code"|action="\/local\/register"/);
  const offNoConfirm = await op(port, target, { action: "set", signup: "off" });
  assert.match(offNoConfirm, /onay/i, "kaydı kapatmak onay istemeli");
  const off = await op(port, target, { action: "set", signup: "off", confirm: "off" });
  assert.match(off, /off/);
  const reg = await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "baskasi", password: "Baskasi-Parola-5x" }) });
  assert.notEqual(reg.status, 303, "kayıt kapalıyken hesap açılmamalı");
  const env = await op(port, target, { action: "set", signup: "env" });
  assert.match(env, /ortam/);
});

test("token alanıyla yetki: oturum olmadan tek çağrı", async (t) => {
  const { port, target } = await start(t);
  const denied = await op(port, target, { action: "get", token: "yanlis-anahtar-0000" });
  assert.match(denied, /anahtarı yanlış/);
  const ok = await op(port, target, { action: "get", token: OP });
  assert.match(ok, /hesap_sayisi/, "doğru anahtarla oturumsuz çağrı çalışmalı");
});

test("logout onay ister ve oturumu kapatır", async (t) => {
  const { port, target } = await start(t);
  await browserLogin(port, /(http:\/\/\S+)/.exec(await op(port, target, { action: "login" }))[1]);
  assert.match(await op(port, target, { action: "get" }), /hesap_sayisi/);
  const noConfirm = await op(port, target, { action: "logout" });
  assert.match(noConfirm, /confirm/);
  const done = await op(port, target, { action: "logout", confirm: "logout" });
  assert.match(done, /kapatıldı/);
  assert.match(await op(port, target, { action: "get" }), /login/, "çıkıştan sonra giriş istenmeli");
});

test("panel paritesi: panelden çıkış araç oturumunu da kapatır, kayıt modu panelde görünür", async (t) => {
  const { port, target } = await start(t);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  const loginTxt = await op(port, target, { action: "login" });
  const link = /(http:\/\/\S+)/.exec(loginTxt)[1];
  const { cookie } = await browserLogin(port, link);
  assert.match(await op(port, target, { action: "get" }), /hesap_sayisi/);
  const panel = await request(port, { target: "/operator", headers: { cookie: `ht_op=${cookie}` } });
  assert.match(panel.body, /Araç oturumu/, "panelde araç oturumu görünmeli");
  assert.match(panel.body, /Kayıt modu/, "panelde kayıt modu kartı olmalı");
  await request(port, { method: "POST", target: "/operator/logout", headers: { ...FORM, cookie: `ht_op=${cookie}` } });
  assert.match(await op(port, target, { action: "get" }), /login/, "panelden çıkış araç oturumunu da kapatmalı");
});
