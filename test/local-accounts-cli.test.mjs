// 1.5.36: "Kullanıcı adı veya parola yanlış" hatasında kilitlenme regresyon testleri.
// Kullanıcı canlıda yeni hesap açamıyordu: kayıt "first" modunda ilk hesaptan sonra kapanıyor,
// parola sıfırlama ve hesap açma için hiçbir yol yoktu. Artık:
//   - operatör CLI'ı (--local-user list|invite|add|passwd|del),
//   - tek kullanımlık davet kodu ile kayıt,
//   - oturum içinden parola değiştirme var.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const TOKEN = "k".repeat(4) + "0123456789abcdef0123456789abcdef";
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

/** Denetim/durum dizinleri paylaşılan geçici bir kurulum. */
function layout() {
  const root = tmp("ht-cli-root-");
  const audit = tmp("ht-cli-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  return { root, audit, cfg, stateDir: path.join(audit, "state") };
}

function cli(l, args, stdin) {
  const r = spawnSync(process.execPath, [entry, "--local-user", ...args], {
    env: { ...process.env, HARDTOOLS_CONFIG: l.cfg, HARDTOOLS_STATE_DIR: l.stateDir, HARDTOOLS_ROOTS: l.root },
    input: stdin ?? "", encoding: "utf8",
  });
  return { code: r.status, out: (r.stdout ?? "").trim(), err: (r.stderr ?? "").trim() };
}

async function start(t, l, env = {}) {
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: l.root, HARDTOOLS_CONFIG: l.cfg, HARDTOOLS_STATE_DIR: l.stateDir,
      HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, HARDTOOLS_LOCAL_SIGNUP: "first", ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 100; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, err);
  return port;
}

test("CLI: hesap aç, listele, parola sıfırla, sil", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));

  const add = cli(l, ["add", "operator", "--password-stdin"], "Ilk-Parola-42x\n");
  assert.equal(add.code, 0, add.err);
  assert.match(add.out, /Hesap açıldı: operator/);
  assert.ok(fs.existsSync(path.join(l.stateDir, "local-accounts.json")), "hesap dosyaya yazılmalı");
  assert.ok(!fs.readFileSync(path.join(l.stateDir, "local-accounts.json"), "utf8").includes("Ilk-Parola-42x"), "düz metin parola yazılmamalı");

  const list = cli(l, ["list"]);
  assert.equal(list.code, 0, list.err);
  assert.match(list.out, /operator/);

  const dup = cli(l, ["add", "operator", "--password-stdin"], "Baska-Parola-77y\n");
  assert.equal(dup.code, 1);
  assert.match(dup.err, /zaten var/);

  const weak = cli(l, ["add", "zayif", "--password-stdin"], "kisa\n");
  assert.equal(weak.code, 1);
  assert.match(weak.err, /Parola politikası/);

  const pw = cli(l, ["passwd", "operator", "--password-stdin"], "Yeni-Parola-99z\n");
  assert.equal(pw.code, 0, pw.err);

  // Yeni parola gerçekten geçerli olmalı: sunucu üzerinden giriş.
  const port = await start(t, l);
  const ok = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "operator", password: "Yeni-Parola-99z" }) });
  assert.equal(ok.status, 303, "yeni parola ile giriş başarılı olmalı");
  const old = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user: "operator", password: "Ilk-Parola-42x" }) });
  assert.equal(old.status, 200);
  assert.match(old.body, /Kullanıcı adı veya parola yanlış/);

  const del = cli(l, ["del", "operator"]);
  assert.equal(del.code, 0, del.err);
  assert.match(cli(l, ["list"]).out, /Yerel hesap yok/);
});

test("davet kodu: kayıt kapalıyken hesap açmanın tek yolu ve tek kullanımlık", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  assert.equal(cli(l, ["add", "sahip", "--password-stdin"], "Ilk-Parola-42x\n").code, 0);

  const inv = cli(l, ["invite", "--ttl", "30"]);
  assert.equal(inv.code, 0, inv.err);
  const code = inv.out.split("\n")[0].trim();
  assert.match(code, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/, `kod biçimi: ${code}`);
  assert.match(cli(l, ["list"]).out, /Bekleyen davet kodu: 1/);

  const port = await start(t, l);
  // Kayıt artık gizlenmiyor: davet kodu alanı görünür.
  const page = await request(port, { target: "/local" });
  assert.equal(page.status, 200);
  assert.match(page.body, /name="code"/, "kayıt kapalıyken davet kodu alanı gösterilmeli");
  // 1.5.39: kod artık tarayıcıdaki yönetici panelinden de üretilir; sayfa oraya yönlendirmeli.
  assert.match(page.body, /yönetici panelinden/i, "kodun nereden alınacağı yazılmalı");

  const noCode = await request(port, { method: "POST", target: "/local/register", headers: FORM,
    body: enc({ user: "davetli", password: "Guclu-Parola-11a" }) });
  assert.equal(noCode.status, 200);
  assert.match(noCode.body, /davet koduna bağlı/);

  const bad = await request(port, { method: "POST", target: "/local/register", headers: FORM,
    body: enc({ user: "davetli", password: "Guclu-Parola-11a", code: "AAAA-AAAA" }) });
  assert.equal(bad.status, 200);
  assert.match(bad.body, /geçersiz/);

  const good = await request(port, { method: "POST", target: "/local/register", headers: FORM,
    body: enc({ user: "davetli", password: "Guclu-Parola-11a", code: code }) });
  assert.equal(good.status, 303, good.body.slice(0, 200));
  assert.ok(good.headers["set-cookie"], "kayıt sonrası oturum çerezi verilmeli");

  const reuse = await request(port, { method: "POST", target: "/local/register", headers: FORM,
    body: enc({ user: "ikinci", password: "Guclu-Parola-22b", code: code }) });
  assert.equal(reuse.status, 200, "kod tek kullanımlık olmalı");
  assert.match(reuse.body, /geçersiz/);

  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "davetli", password: "Guclu-Parola-11a" }) });
  assert.equal(login.status, 303, "davetle açılan hesap giriş yapabilmeli");
});

test("oturum içinden parola değiştirme; eski parola geçersiz olur", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  assert.equal(cli(l, ["add", "kullanici", "--password-stdin"], "Ilk-Parola-42x\n").code, 0);
  const port = await start(t, l);

  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "kullanici", password: "Ilk-Parola-42x" }) });
  assert.equal(login.status, 303);
  const cookie = login.headers["set-cookie"][0].split(";")[0];

  const page = await request(port, { target: "/local", headers: { cookie } });
  assert.match(page.body, /Parola değiştir/, "giriş yapmış kullanıcı parola kartını görmeli");

  const wrong = await request(port, { method: "POST", target: "/local/password", headers: { ...FORM, cookie },
    body: enc({ current: "yanlis-parola-1A", next: "Yeni-Parola-77y" }) });
  assert.equal(wrong.status, 200);
  assert.match(wrong.body, /yanlış/);

  const changed = await request(port, { method: "POST", target: "/local/password", headers: { ...FORM, cookie },
    body: enc({ current: "Ilk-Parola-42x", next: "Yeni-Parola-77y" }) });
  assert.equal(changed.status, 200);
  assert.match(changed.body, /Parola değişti/);

  const oldPw = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "kullanici", password: "Ilk-Parola-42x" }) });
  assert.equal(oldPw.status, 200, "eski parola artık geçersiz");
  const newPw = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "kullanici", password: "Yeni-Parola-77y" }) });
  assert.equal(newPw.status, 303, "yeni parola ile giriş yapılmalı");
});

test("giriş hatası çıkmaz sokak değil: kullanıcı ne yapacağını görür", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l, { HARDTOOLS_LOCAL_SIGNUP: "open" });
  const r = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "olmayan", password: "Guclu-Parola-33c" }) });
  assert.equal(r.status, 200);
  assert.match(r.body, /Kullanıcı adı veya parola yanlış/);
  assert.match(r.body, /Hesap aç/, "hata sayfasında hesap açma yolu görünmeli");
  assert.match(r.body, /action="\/local\/register"/);
});

test("sunucu çalışırken CLI değişiklikleri anında geçerli (yeniden başlatma gerekmez)", async (t) => {
  // Canlıda tam bu kırılıyordu: CLI ile üretilen davet kodu çalışan sunucuda "geçersiz" dönüyordu,
  // çünkü sunucu hesap dosyasını yalnızca açılışta okuyordu.
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  const port = await start(t, l); // henüz hesap yok

  assert.equal(cli(l, ["add", "sahip", "--password-stdin"], "Ilk-Parola-42x\n").code, 0);
  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  assert.equal(login.status, 303, "CLI ile açılan hesap yeniden başlatmadan giriş yapabilmeli");

  const code = cli(l, ["invite"]).out.split("\n")[0].trim();
  const reg = await request(port, { method: "POST", target: "/local/register", headers: FORM,
    body: enc({ user: "davetli", password: "Guclu-Parola-11a", code }) });
  assert.equal(reg.status, 303, "çalışan sunucu yeni davet kodunu görmeli: " + reg.body.match(/Hata:[^<]*/)?.[0]);

  // CLI ile parola sıfırlama da anında etkili olmalı.
  assert.equal(cli(l, ["passwd", "sahip", "--password-stdin"], "Yeni-Parola-99z\n").code, 0);
  const reset = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Yeni-Parola-99z" }) });
  assert.equal(reset.status, 303, "sıfırlanan parola anında geçerli olmalı");

  // CLI ile silme de anında etkili olmalı.
  assert.equal(cli(l, ["del", "sahip"]).code, 0);
  const gone = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Yeni-Parola-99z" }) });
  assert.equal(gone.status, 200, "silinen hesap giriş yapamamalı");
});

test("UX: giriş hatası akışı kaybetmez ve giriş yapmış kullanıcıya form gösterilmez", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  assert.equal(cli(l, ["add", "sahip", "--password-stdin"], "Ilk-Parola-42x\n").code, 0);
  const port = await start(t, l);
  const next = "/authorize?response_type=code&client_id=abc";

  // 1) OAuth akışından gelen kullanıcı parolayı yanlış yazar: next korunmalı, akış kopmamalı.
  const bad = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "yanlis-Parola-1A", next }) });
  assert.equal(bad.status, 200);
  assert.match(bad.body, /Kullanıcı adı veya parola yanlış/);
  assert.ok(bad.body.includes('name="next" value="/authorize?response_type=code&amp;client_id=abc"'),
    "hata sayfasındaki form next parametresini taşımalı");
  assert.match(bad.body, /Hesap aç/, "hata sayfası çıkmaz sokak olmamalı");

  // 2) Doğru giriş: devam sayfası /authorize adresini taşır.
  const ok = await request(port, { method: "POST", target: "/local/login",
    headers: { ...FORM, accept: "text/html,application/xhtml+xml" },
    body: enc({ user: "sahip", password: "Ilk-Parola-42x", next }) });
  assert.equal(ok.status, 200);
  assert.match(ok.body, /http-equiv="refresh"/);
  assert.match(ok.body, /\/authorize\?response_type=code/);

  // 3) Giriş yapmış kullanıcı /local'de giriş formunu değil kimlik kartını görür.
  const cookie = (await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) })).headers["set-cookie"][0].split(";")[0];
  const page = await request(port, { target: "/local", headers: { cookie } });
  assert.equal(page.status, 200);
  assert.match(page.body, /Giriş: sahip/);
  assert.match(page.body, /\/lc\//, "kişisel bağlantı adresi gösterilmeli");
  assert.doesNotMatch(page.body, /action="\/local\/login"/, "giriş formu tekrar gösterilmemeli");
  assert.match(page.body, /action="\/local\/password"/);
  assert.match(page.body, /settings\/logout/);
  assert.match(page.body, /action="\/local\/connector"/);
});

test("güvenlik: oturum çerezi imzalı, süreli ve başka hesaba geçirilemez", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  assert.equal(cli(l, ["add", "sahip", "--password-stdin"], "Ilk-Parola-42x\n").code, 0);
  assert.equal(cli(l, ["add", "diger", "--password-stdin"], "Baska-Parola-77y\n").code, 0);
  const port = await start(t, l);

  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  const raw = login.headers["set-cookie"][0];
  assert.match(raw, /HttpOnly/); assert.match(raw, /SameSite=Lax/);
  const cookie = raw.split(";")[0];

  // İmza bozulursa oturum kabul edilmez.
  const tampered = cookie.slice(0, -3) + (cookie.endsWith("AAA") ? "BBB" : "AAA");
  const bad = await request(port, { target: "/local", headers: { cookie: tampered } });
  assert.doesNotMatch(bad.body, /Giriş: sahip/, "bozuk imzalı çerez kullanılmamalı");

  // Kullanıcı adı değiştirilmiş çerez de kabul edilmez.
  const rename = cookie.replace(/^ht_s=/, "");
  const parts = rename.split(".");
  const forgedUser = Buffer.from("diger").toString("base64url");
  const forged = `ht_s=${forgedUser}.${parts[1]}.${parts[2]}`;
  const forgedPage = await request(port, { target: "/local", headers: { cookie: forged } });
  assert.doesNotMatch(forgedPage.body, /Giriş: diger/, "imzasız kullanıcı değişimi kabul edilmemeli");

  // Silinen hesabın çerezi işe yaramaz.
  assert.equal(cli(l, ["del", "sahip"]).code, 0);
  const afterDel = await request(port, { target: "/local", headers: { cookie } });
  assert.doesNotMatch(afterDel.body, /Giriş: sahip/, "silinen hesabın oturumu düşmeli");
});

test("güvenlik: parola değişince eski oturumlar düşer, silinen hesap erişimini kaybeder", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  assert.equal(cli(l, ["add", "sahip", "--password", "Ilk-Parola-42x"]).code, 0);
  const port = await start(t, l);

  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  const oldCookie = login.headers["set-cookie"][0].split(";")[0];
  assert.match((await request(port, { target: "/workspaces", headers: { cookie: oldCookie } })).body, /<title>Çalışma alanları/);

  // Parola değişince eski çerez geçersizleşir (çalınmış oturum yaşamaz).
  await new Promise((r) => setTimeout(r, 1100)); // iat saniye çözünürlüğünde
  const changed = await request(port, { method: "POST", target: "/local/password", headers: { ...FORM, cookie: oldCookie },
    body: enc({ current: "Ilk-Parola-42x", next: "Yeni-Parola-77y" }) });
  assert.match(changed.body, /Parola değişti/);
  const afterChange = await request(port, { target: "/workspaces", headers: { cookie: oldCookie } });
  assert.doesNotMatch(afterChange.body, /<title>Çalışma alanları/, "parola değişiminden önceki çerez geçersiz olmalı");

  // Yeni çerez çalışır.
  const fresh = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Yeni-Parola-77y" }) });
  const newCookie = fresh.headers["set-cookie"][0].split(";")[0];
  assert.match((await request(port, { target: "/workspaces", headers: { cookie: newCookie } })).body, /<title>Çalışma alanları/);

  // Operatör hesabı silince çerez de düşer.
  assert.equal(cli(l, ["del", "sahip"]).code, 0);
  const afterDelete = await request(port, { target: "/workspaces", headers: { cookie: newCookie } });
  assert.doesNotMatch(afterDelete.body, /<title>Çalışma alanları/, "silinen hesabın oturumu düşmeli");
});

test("kilitleme: 8 hatalı denemeden sonra kilit; operatör sıfırlaması kilidi açar", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  assert.equal(cli(l, ["add", "sahip", "--password", "Ilk-Parola-42x"]).code, 0);
  const port = await start(t, l);
  for (let i = 0; i < 8; i++) {
    await request(port, { method: "POST", target: "/local/login", headers: FORM,
      body: enc({ user: "sahip", password: `yanlis-Parola-${i}A` }) });
  }
  const locked = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Ilk-Parola-42x" }) });
  assert.equal(locked.status, 200);
  assert.match(locked.body, /Çok fazla hatalı deneme/, "doğru parola bile kilitliyken reddedilmeli");

  // Operatör parolayı sıfırlar: kilit de anında açılır (CLI başka süreçte çalışıyor).
  assert.equal(cli(l, ["passwd", "sahip", "--password", "Yeni-Parola-99z"]).code, 0);
  const ok = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "sahip", password: "Yeni-Parola-99z" }) });
  assert.equal(ok.status, 303, "sıfırlama sonrası giriş açılmalı");
});

test("giriş: Türkçe karakterli parola, büyük harfli kullanıcı adı ve boşluklu davet kodu", async (t) => {
  const l = layout();
  t.after(() => fs.rmSync(l.root, { recursive: true, force: true }));
  // Türkçe karakterli parola (ı, ş, ğ, ü) ve büyük harfli kullanıcı adı.
  assert.equal(cli(l, ["add", "Cagri", "--password", "Şifre-Çok-Güçlü-42"]).code, 0);
  const port = await start(t, l);
  const login = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "  CAGRI ", password: "Şifre-Çok-Güçlü-42" }) });
  assert.equal(login.status, 303, "büyük harf + boşluklu ad ve Türkçe parola ile giriş yapılmalı");

  const wrongCase = await request(port, { method: "POST", target: "/local/login", headers: FORM,
    body: enc({ user: "cagri", password: "Şifre-Çok-Güçlü-43" }) });
  assert.match(wrongCase.body, /Kullanıcı adı veya parola yanlış/);

  // Davet kodu küçük harf, boşluk ve tiresiz yazılsa da kabul edilir.
  const code = cli(l, ["invite"]).out.split("\n")[0].trim();
  const sloppy = " " + code.toLowerCase().replace("-", " ") + " ";
  const reg = await request(port, { method: "POST", target: "/local/register", headers: FORM,
    body: enc({ user: "yeni", password: "Baska-Parola-77y", code: sloppy }) });
  assert.equal(reg.status, 303, `esnek kod kabul edilmeli: ${reg.body.match(/Hata:[^<]*/)?.[0]}`);
});
