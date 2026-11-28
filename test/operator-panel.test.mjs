// 1.5.39: yönetici paneli (/operator) regresyon testleri.
// Kullanıcı sorusu: "flyctl olmadan, arayüzden davet kodu almak mümkün mü?" Fly.io panosunda
// web terminal yok, bu yüzden davet kodu üretmek/parola sıfırlamak tarayıcıdan yapılabilsin
// diye panel eklendi. Buradaki testler panelin hem İŞLEVSEL hem GÜVENLİ olduğunu doğrular:
// anahtarsız erişim yok, çapraz origin yok, deneme sınırı var, çerez HMAC imzalı.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const TOKEN = "m".repeat(4) + "0123456789abcdef0123456789abcdef";
const OP = "operator-anahtar-0123456789"; // 16+ karakter
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

function layout() {
  const root = tmp("ht-op-root-");
  const audit = tmp("ht-op-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  return { root, audit, cfg, stateDir: path.join(audit, "state") };
}

async function start(t, l, env = {}) {
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: {
      ...process.env, HARDTOOLS_ROOTS: l.root, HARDTOOLS_CONFIG: l.cfg, HARDTOOLS_STATE_DIR: l.stateDir,
      HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`,
      HARDTOOLS_LOCAL_SIGNUP: "first", HARDTOOLS_OPERATOR_TOKEN: OP, ...env,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 120; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, err);
  return port;
}

/** Panel girişi: çerez döner. */
async function opLogin(port, token = OP) {
  const r = await request(port, { method: "POST", target: "/operator/login", headers: FORM, body: enc({ token }) });
  const raw = [].concat(r.headers["set-cookie"] ?? [])[0] ?? "";
  return { ...r, cookie: /^ht_op=([^;]+)/.exec(raw)?.[1] ?? "" };
}

/** POST + yönlendirmeyi izle, üretilen değeri (kod/parola) ?reveal= sayfasından oku. */
async function opAction(port, cookie, action, fields) {
  const r = await request(port, { method: "POST", target: `/operator/${action}`, headers: { ...FORM, cookie: `ht_op=${cookie}` }, body: enc(fields) });
  if (r.status !== 303) return { ...r, reveal: "" };
  const page = await request(port, { target: r.headers.location, headers: { cookie: `ht_op=${cookie}` } });
  return { ...r, reveal: /value="([^"]+)"[^>]*>/.exec(page.body)?.[1] ?? "" };
}

const auditTail = (l) => {
  try {
    return fs.readFileSync(path.join(l.audit, "audit.jsonl"), "utf8").trim().split("\n").map((x) => JSON.parse(x));
  } catch {
    try {
      const files = fs.readdirSync(l.audit).filter((f) => f.endsWith(".jsonl"));
      return files.flatMap((f) => fs.readFileSync(path.join(l.audit, f), "utf8").trim().split("\n").filter(Boolean).map((x) => JSON.parse(x)));
    } catch { return []; }
  }
};

test("yönetici anahtarı yokken panel kapalı: form yok, hesap bilgisi sızmıyor, talimat var", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l, { HARDTOOLS_OPERATOR_TOKEN: "" });
  const r = await request(port, { target: "/operator" });
  assert.equal(r.status, 200);
  assert.match(r.body, /HARDTOOLS_OPERATOR_TOKEN/, "anahtarın nasıl tanımlanacağı yazılmalı");
  assert.match(r.body, /Secrets/, "browser-only yol (Fly panosu → Secrets) anlatılmalı");
  assert.doesNotMatch(r.body, /name="token"/, "anahtar tanımlı değilken giriş formu gösterilmemeli");
  assert.doesNotMatch(r.body, /name="user"/, "hesap işlemi formu gösterilmemeli");
});

test("çok kısa anahtar paneli açmaz (yanlış yapılandırma güvenli tarafa düşer)", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l, { HARDTOOLS_OPERATOR_TOKEN: "kisa" });
  const r = await request(port, { target: "/operator" });
  assert.match(r.body, /paneli kapalı/i);
  const login = await request(port, { method: "POST", target: "/operator/login", headers: FORM, body: enc({ token: "kisa" }) });
  assert.equal(login.status, 200, "kısa anahtarla giriş yönlendirme üretmemeli");
  assert.equal(login.headers["set-cookie"], undefined, "çerez verilmemeli");
});

test("doğru anahtar → oturum çerezi (HttpOnly, HMAC imzalı) ve panel içeriği", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l);
  const r = await opLogin(port);
  assert.equal(r.status, 303);
  assert.equal(r.headers.location, "/operator");
  const raw = [].concat(r.headers["set-cookie"] ?? [])[0] ?? "";
  assert.match(raw, /HttpOnly/); assert.match(raw, /SameSite=Lax/); assert.match(raw, /Max-Age=3600/);
  const cookieValue = r.cookie.split(".")[0];
  assert.match(cookieValue, /^\d{13}$/, "çerez son kullanma + imza biçiminde olmalı");
  const page = await request(port, { target: "/operator", headers: { cookie: `ht_op=${r.cookie}` } });
  assert.match(page.body, /Davet kodu üret/);
  assert.match(page.body, /Hesap aç \(kodsuz\)/);
  assert.match(page.body, /yönetici çıkışı/);
  assert.doesNotMatch(page.body, /name="token"/, "giriş yapmışken anahtar formu gösterilmemeli");
});

test("yanlış anahtar reddedilir; 6 denemeden sonra doğru anahtar da kilitlenir", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l);
  const bad = await opLogin(port, "yanlis-anahtar-000000");
  assert.equal(bad.status, 200);
  assert.match(bad.body, /anahtar yanlış/);
  assert.equal(bad.headers["set-cookie"], undefined);
  for (let i = 0; i < 5; i++) await opLogin(port, "yanlis-anahtar-000000");
  const now = await opLogin(port, OP);
  assert.equal(now.status, 200, "kilitliyken doğru anahtar da yönlendirmemeli");
  assert.match(now.body, /çok fazla hatalı deneme/);
  assert.equal(now.headers["set-cookie"], undefined, "kilitliyken çerez verilmemeli");
  assert.ok(auditTail(l).some((e) => e.ev === "operator_login_failed"), "hatalı denemeler denetime yazılmalı");
});

test("panelden üretilen davet kodu /local üzerinden gerçekten hesap açar (tek kullanımlık)", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l);
  // "first" modunda İLK hesap kodsuz açılır (kurulumu kilitlememek için); kodu ikinci hesapta dene.
  const first = await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "ilkhesap", password: "Ilk-Hesap-71x" }) });
  assert.equal(first.status, 303, "ilk hesap kodsuz açılmalı");
  const { cookie } = await opLogin(port);
  const inv = await opAction(port, cookie, "invite", { ttl: "1440" });
  assert.equal(inv.status, 303);
  assert.match(inv.reveal, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/, `kod okunamadı: ${inv.reveal}`);
  const reg = await request(port, {
    method: "POST", target: "/local/register", headers: FORM,
    body: enc({ code: inv.reveal.toLowerCase(), user: "panelden", password: "Panel-Kod-91x" }),
  });
  assert.equal(reg.status, 303, "kayıt başarılı olmalı: " + reg.body.slice(0, 200));
  // Kod tek kullanımlık: ikinci hesap aynı kodla açılamaz.
  const again = await request(port, {
    method: "POST", target: "/local/register", headers: FORM,
    body: enc({ code: inv.reveal, user: "ikinci", password: "Panel-Kod-92y" }),
  });
  assert.equal(again.status, 200, "tüketilmiş kodla kayıt yönlendirme üretmemeli");
  assert.match(again.body, /geçersiz|kullanılmış|süresi/i, "kod ikinci kez kabul edilmemeli");
  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "panelden", password: "Panel-Kod-91x" }) });
  assert.equal(login.status, 303, "yeni hesapla giriş çalışmalı");
});

test("kodsuz hesap açma: parola üretilir, bir kez gösterilir, giriş çalışır", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l);
  const { cookie } = await opLogin(port);
  const add = await opAction(port, cookie, "add", { user: "operatorekledi", password: "" });
  assert.equal(add.status, 303);
  const m = /^operatorekledi \/ (\S+)$/.exec(add.reveal);
  assert.ok(m, `üretilen parola okunamadı: ${add.reveal}`);
  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "operatorekledi", password: m[1] }) });
  assert.equal(login.status, 303, "üretilen parolayla giriş yapılabilmeli");
  // Aynı ad ikinci kez açılamaz.
  const dup = await opAction(port, cookie, "add", { user: "operatorekledi", password: "Baska-Parola-77" });
  assert.match(dup.body, /zaten var/);
});

test("parola sıfırlama: eski parola düşer, yeni parola çalışır, eski oturum çerezi geçersiz", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "sifirla", password: "Eski-Parola-11" }) });
  const old = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "sifirla", password: "Eski-Parola-11" }) });
  const oldCookie = /^ht_s=([^;]+)/.exec([].concat(old.headers["set-cookie"] ?? [])[0] ?? "")?.[1] ?? "";
  assert.ok(oldCookie);
  const { cookie } = await opLogin(port);
  const res = await opAction(port, cookie, "passwd", { user: "sifirla" });
  assert.equal(res.status, 303);
  const pw = /^sifirla \/ (\S+)$/.exec(res.reveal)?.[1] ?? "";
  assert.ok(pw, `yeni parola okunamadı: ${res.reveal}`);
  const stale = await request(port, { target: "/local", headers: { cookie: `ht_s=${oldCookie}` } });
  assert.match(stale.body, /name="password"/, "parola değişince eski çerez düşmeli (giriş formu görünmeli)");
  const badOld = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "sifirla", password: "Eski-Parola-11" }) });
  assert.match(badOld.body, /yanlış/i, "eski parola artık geçersiz");
  const goodNew = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "sifirla", password: pw }) });
  assert.equal(goodNew.status, 303, "yeni parola ile giriş çalışmalı");
});

test("hesap silme: giriş ve MCP adresi kapanır", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l);
  await request(port, { method: "POST", target: "/local/register", headers: FORM, body: enc({ user: "silinecek", password: "Sil-Parola-31" }) });
  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "silinecek", password: "Sil-Parola-31" }) });
  const cookie = /^ht_s=([^;]+)/.exec([].concat(login.headers["set-cookie"] ?? [])[0] ?? "")?.[1] ?? "";
  const home = await request(port, { target: "/local", headers: { cookie: `ht_s=${cookie}` } });
  const connector = /\/lc\/([A-Za-z0-9_-]{16,})/.exec(home.body)?.[1] ?? "";
  assert.ok(connector, "bağlantı adresi görünmeli");
  const before = await request(port, { method: "POST", target: `/lc/${connector}`, headers: { ...FORM, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
  assert.notEqual(before.status, 401, "silinmeden önce adres çalışmalı");
  const { cookie: op } = await opLogin(port);
  const del = await request(port, { method: "POST", target: "/operator/del", headers: { ...FORM, cookie: `ht_op=${op}` }, body: enc({ user: "silinecek" }) });
  assert.match(del.body, /silindi/);
  const after = await request(port, { method: "POST", target: `/lc/${connector}`, headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
  assert.equal(after.status, 401, "silinen hesabın adresi 401 dönmeli");
  const relogin = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "silinecek", password: "Sil-Parola-31" }) });
  assert.match(relogin.body, /yanlış/i, "silinen hesapla giriş yapılamamalı");
});

test("yetkisiz ve çapraz origin istekleri reddedilir", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l);
  // Çerezsiz doğrudan işlem.
  const noAuth = await request(port, { method: "POST", target: "/operator/invite", headers: FORM, body: enc({ ttl: "30" }) });
  assert.equal(noAuth.status, 200);
  assert.match(noAuth.body, /yönetici oturumu yok/);
  assert.equal(noAuth.headers.location, undefined);
  // Başka siteden gönderim (Origin başka).
  const { cookie } = await opLogin(port);
  const cross = await request(port, {
    method: "POST", target: "/operator/invite",
    headers: { ...FORM, cookie: `ht_op=${cookie}`, origin: "https://kotu-site.example" }, body: enc({ ttl: "30" }),
  });
  assert.match(cross.body, /başka bir siteden/);
  assert.equal(cross.headers.location, undefined, "çapraz origin isteği kod üretmemeli");
  // Çalınmış/bozulmuş çerez kabul edilmez.
  const forged = await request(port, { method: "POST", target: "/operator/invite", headers: { ...FORM, cookie: "ht_op=9999999999999.sahte" }, body: enc({ ttl: "30" }) });
  assert.match(forged.body, /yönetici oturumu yok/);
});

test("yönetici çıkışı çerezi düşürür", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l);
  const { cookie } = await opLogin(port);
  await request(port, { method: "POST", target: "/operator/logout", headers: { ...FORM, cookie: `ht_op=${cookie}` } });
  const page = await request(port, { target: "/operator", headers: { cookie: `ht_op=${cookie}` } });
  assert.match(page.body, /name="token"/, "çıkıştan sonra giriş formu görünmeli");
});

test("panel tüm sayfalardan erişilebilir; /local listesi CLI'ya mahkûm değil", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l, { HARDTOOLS_LOCAL_SIGNUP: "open" });
  const local = await request(port, { target: "/local" });
  assert.match(local.body, /href="\/operator"/, "/local sayfasından panele bağlantı olmalı");
  assert.doesNotMatch(local.body, /--local-user invite/, "kayıt kapalıyken CLI'ya yönlendirme kalmamalı");
  const home = await request(port, { target: "/" });
  assert.equal(home.status, 200);
});
