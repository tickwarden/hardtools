// 1.5.31: son turlarda canlıda kırılan üç sınıf hata için kalıcı koruma testleri.
//   1) Sayfa metinlerine HTML etiketi sızması (heading() esc'liyor, çağıran etiket geçmişti).
//   2) İç bağlantıların 404 vermesi (/settings → /connect).
//   3) Kök taşıma işlemlerinin kabuk iskeletini (.hardtools) taşıyıp bwrap'ı kırması.
// Ayrıca yerel hesap akışı (kayıt → çerez → /lc/<anahtar> ile MCP) uçtan uca doğrulanır.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const TOKEN = "s".repeat(4) + "0123456789abcdef0123456789abcdef";
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

async function start(t, env = {}) {
  const root = tmp("ht-pages-root-");
  const state = tmp("ht-pages-state-");
  const audit = tmp("ht-pages-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_STATE: state,
      HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1", ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 100; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, err);
  return { port, root, state, audit };
}

/** Statik token ile sayfa çerezi al. */
async function pageCookie(port) {
  const r = await request(port, { method: "POST", target: "/settings/token",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "token=" + TOKEN });
  assert.ok(r.headers["set-cookie"], "çerez verilmeli: " + JSON.stringify(r.headers));
  return r.headers["set-cookie"][0].split(";")[0];
}

const PAGES = ["/", "/settings", "/local", "/workspaces"];

test("sayfa metinlerine HTML etiketi sızmaz, dahili bağlantılar 404 vermez", async (t) => {
  const { port } = await start(t);
  const cookie = await pageCookie(port);
  const links = new Set();
  for (const target of PAGES) {
    const r = await request(port, { target, headers: { cookie } });
    assert.equal(r.status, 200, `${target} → ${r.status}`);
    // Kaçış hatası: yazılan metinde etiket görünüyorsa burada &lt;b&gt; / &lt;code&gt; olarak yakalanır.
    assert.doesNotMatch(r.body, /&lt;(b|code|strong|em)&gt;/, `${target}: kaçışlı etiket sızmış`);
    // Kopyalama düğmesi ve pano betiği her sayfada hazır olmalı (webview yedeğiyle).
    assert.match(r.body, /data-copy|navigator\.clipboard|execCommand/, `${target}: kopyalama betiği yok`);
    for (const m of r.body.matchAll(/href="(\/[^"#?]*)"/g)) links.add(m[1]);
  }
  assert.ok(links.size > 0, "hiç dahili bağlantı bulunamadı");
  for (const href of links) {
    // /settings/logout yalnızca POST kabul eder; GET 405 döner (kırık bağlantı değil).
    if (/logout$/.test(href)) continue;
    const r = await request(port, { target: href, headers: { cookie } });
    assert.ok(r.status < 400, `dahili bağlantı kırık: ${href} → ${r.status}`);
  }
  // GitHub akışındaki sayfalar da yerel hesap yolunu göstermeli (GitHub bozulduğunda çıkış yolu).
  const device = await request(port, { target: "/device" });
  assert.equal(device.status, 200, "/device → " + device.status);
  assert.match(device.body, /href="\/local"/, "cihaz onayı sayfasında yerel hesap bağlantısı olmalı");
  assert.match(device.body, /Yerel hesapla gir/, "yerel hesap düğmesi görünmeli");

  // Bildirilen somut kırık: /connect sayfası giriş zorunlu modda da açılmalı.
  const connect = await request(port, { target: "/connect", headers: { cookie } });
  assert.equal(connect.status, 200, "/connect giriş zorunlu modda 404 vermemeli");
  assert.match(connect.body, /\/mcp/, "/connect MCP adresini göstermeli");
});

test("panel MCP adresini kopyalanabilir verir; giriş sayfası yerel hesap sunar", async (t) => {
  const { port } = await start(t);
  const panel = await request(port, { target: "/" });
  assert.equal(panel.status, 200);
  assert.match(panel.body, /value="http:\/\/127\.0\.0\.1:\d+\/mcp"/, "panel MCP adresini göstermeli");
  assert.match(panel.body, /data-copy="#mcp"/, "kopyalama düğmesi olmalı");
  const login = await request(port, { target: "/settings" });
  assert.match(login.body, /GitHub ile giriş/, "GitHub girişi korunmalı");
  assert.match(login.body, /action="\/local\/login"/, "giriş sayfasında yerel hesap formu olmalı");
});

test("yerel hesap: kayıt → çerez → /lc/<anahtar> ile MCP", async (t) => {
  const { port } = await start(t);
  const reg = await request(port, { method: "POST", target: "/local/register",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: `http://127.0.0.1:${port}` },
    body: "user=testci&password=Guclu-Parola-42x" });
  assert.equal(reg.status, 303, `kayıt yönlendirmeli: ${reg.body.slice(0, 200)}`);
  const cookie = reg.headers["set-cookie"][0].split(";")[0];
  const panel = await request(port, { target: "/", headers: { cookie } });
  const m = /value="http:\/\/127\.0\.0\.1:\d+(\/lc\/[A-Za-z0-9_-]{16,})"/.exec(panel.body);
  assert.ok(m, "panelde kişisel bağlantı adresi olmalı");
  const rpc = async (payload) => {
    const r = await request(port, { method: "POST", target: m[1],
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify(payload) });
    const line = r.body.split("\n").find((l) => l.startsWith("data: "));
    return { status: r.status, json: JSON.parse(line ? line.slice(6) : r.body) };
  };
  const init = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal(init.status, 200, JSON.stringify(init.json).slice(0, 200));
  const write = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "ht_write", arguments: { path: "yerel.txt", content: "x" } } });
  assert.match(JSON.stringify(write.json), /yerel\.txt/, "yerel hesapla yazma çalışmalı");
  // Aynı origin olmayan form reddedilir (login CSRF).
  const cross = await request(port, { method: "POST", target: "/local/login",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://kotu.example" }, body: "user=testci&password=Guclu-Parola-42x" });
  assert.match(cross.body, /başka bir siteden/, "yabancı origin reddedilmeli");
  // İkinci hesap: varsayılan "first" modunda davet kodu olmadan açılamaz (1.5.36).
  const second = await request(port, { method: "POST", target: "/local/register",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: `http://127.0.0.1:${port}` }, body: "user=ikinci&password=Baska-Parola-7k" });
  assert.match(second.body, /davet/, "varsayılan modda ikinci hesap davet kodu ister");
  assert.equal(second.headers["set-cookie"], undefined, "davetsiz kayıtta oturum çerezi verilmemeli");
  const ikinci = await request(port, { method: "POST", target: "/local/login",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "user=ikinci&password=Baska-Parola-7k" });
  assert.match(ikinci.body, /Kullanıcı adı veya parola yanlış/, "davetsiz hesap oluşmamalı");
});

test("adoptInto kabuk iskeletini ve atık dizinlerini taşımaz", async () => {
  const { adoptInto, measure } = await import(path.resolve("dist/workspaces.js"));
  const base = tmp("ht-adopt-");
  const src = path.join(base, "u-0123456789abcdef"), dst = path.join(base, "a-fedcba9876543210");
  fs.mkdirSync(path.join(src, ".hardtools", "tmp"), { recursive: true });
  fs.mkdirSync(path.join(src, ".ht-trash"), { recursive: true });
  fs.mkdirSync(path.join(src, ".recycle"), { recursive: true });
  fs.mkdirSync(path.join(src, "proje"), { recursive: true });
  fs.writeFileSync(path.join(src, "proje", "a.txt"), "x");
  fs.writeFileSync(path.join(src, "notlar.txt"), "y");
  fs.mkdirSync(dst, { recursive: true });
  const r = adoptInto(src, dst);
  assert.equal(r.moved, 2, JSON.stringify(r));
  assert.ok(fs.existsSync(path.join(src, ".hardtools", "tmp")), "kaynakta iskelet kalmalı (bwrap bağları)");
  assert.ok(!fs.existsSync(path.join(dst, ".hardtools")), "hedefe iskelet taşınmamalı");
  assert.ok(!fs.existsSync(path.join(dst, ".ht-trash")), "atık dizini taşınmamalı");
  assert.ok(!fs.existsSync(path.join(dst, ".recycle")), "geri dönüşüm kutusu taşınmamalı");
  assert.ok(fs.existsSync(path.join(dst, "proje", "a.txt")), "kullanıcı dosyası taşınmalı");
  // Ölçüm: iskelet kullanıcı verisi sayılmaz ama ayrı raporlanır (yanıltıcı "0 B" olmasın).
  fs.mkdirSync(path.join(dst, ".hardtools", "tmp"), { recursive: true });
  fs.writeFileSync(path.join(dst, ".hardtools", "tmp", "buyuk.bin"), Buffer.alloc(4096));
  const m = measure(dst);
  assert.equal(m.files, 2, JSON.stringify(m));
  assert.ok(m.scratchBytes >= 4096, "iskelet ayrı sayılmalı: " + JSON.stringify(m));
  fs.rmSync(base, { recursive: true, force: true });
});

test("ht_new_shell_env iskeleti geri dönüşüm kutusuna taşımaz", async () => {
  const { loadPolicy } = await import(path.resolve("dist/config.js"));
  const { createEnv } = await import(path.resolve("dist/envs.js"));
  const root = tmp("ht-env-root-");
  const envsDir = tmp("ht-env-dir-");
  process.env.HARDTOOLS_ENVS_DIR = envsDir;
  try {
    fs.mkdirSync(path.join(root, ".hardtools", "tmp"), { recursive: true });
    fs.writeFileSync(path.join(root, "eski.txt"), "eski");
    const policy = loadPolicy({ profile: "balanced", roots: [root], configPath: null, override: {} });
    policy.shellWorker = undefined;
    const info = createEnv(policy, { rotate: true });
    assert.ok(fs.existsSync(path.join(root, ".hardtools", "tmp")), "eski kökte iskelet kalmalı");
    const recycled = info.recycled ?? "";
    assert.ok(!recycled || !fs.existsSync(path.join(recycled, ".hardtools")), "geri dönüşüm kutusunda iskelet olmamalı");
  } finally {
    delete process.env.HARDTOOLS_ENVS_DIR;
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(envsDir, { recursive: true, force: true });
  }
});

test("yerel hesaplar: parola politikası, doğrulama, kilit ve anahtar yenileme", async () => {
  const { LocalAccounts, passwordProblem } = await import(path.resolve("dist/localauth.js"));
  const dir = tmp("ht-local-accounts-");
  const store = path.join(dir, "local-accounts.json");
  const la = new LocalAccounts({ store });
  assert.match(passwordProblem("ali", "ali-parola") ?? "", /kullanıcı adını içermemeli/);
  assert.match(passwordProblem("ali", "kisa") ?? "", /en az/);
  assert.equal(passwordProblem("ali", "Guclu-Parola-42x"), null);
  assert.equal(la.canRegister(), true, "ilk hesap açılabilmeli");
  const created = la.create("ali", "Guclu-Parola-42x");
  assert.equal(created.ok, true, JSON.stringify(created));
  assert.equal(la.canRegister(), false, "varsayılan modda ikinci hesap kapalı");
  assert.equal(la.verify("ali", "yanlis-parola-1A").ok, false);
  assert.equal(la.verify("ali", "Guclu-Parola-42x").ok, true);
  const conn = la.connectorFor("ali");
  assert.equal(la.userForConnector(conn), "ali");
  const rotated = la.rotateConnector("ali");
  assert.notEqual(rotated, conn, "anahtar yenilenince eski adres çalışmamalı");
  assert.equal(la.userForConnector(conn), null);
  // Disk kalıcılığı: yeniden açıldığında hesap ve parola korunur.
  const again = new LocalAccounts({ store });
  assert.equal(again.verify("ali", "Guclu-Parola-42x").ok, true);
  // Kilit: 8 hatalı denemeden sonra doğru parola bile bekletilir.
  for (let i = 0; i < 8; i++) again.verify("ali", "yanlis-parola-" + i + "A");
  assert.match(again.verify("ali", "Guclu-Parola-42x").error ?? "", /Çok fazla hatalı deneme/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("yerel hesapla /authorize akışı tamamlanır (panele değil, istemciye döner)", async (t) => {
  // GitHub device flow yapılandırılmış gibi davranır: yerel çerez varsa GitHub'a hiç gidilmemeli.
  const { port } = await start(t, { HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "Iv1.testclient", HARDTOOLS_OAUTH_ALLOWED_LOGINS: "kimse" });
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";
  const reg = await request(port, { method: "POST", target: "/register",
    headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [redirectUri], client_name: "test" }) });
  assert.equal(reg.status, 201, reg.body.slice(0, 200));
  const clientId = JSON.parse(reg.body).client_id;
  const crypto = await import("node:crypto");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const authorize = "/authorize?" + new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    code_challenge: challenge, code_challenge_method: "S256", state: "st-1", resource: `http://127.0.0.1:${port}/mcp`,
  }).toString();

  // 1) Kayıt formu next'i taşımalı ve giriş sonrası oraya dönmeli.
  const page = await request(port, { target: `/local?next=${encodeURIComponent(authorize)}` });
  assert.match(page.body, /name="next"/, "next alanı forma taşınmalı");
  const reg2 = await request(port, { method: "POST", target: "/local/register",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: `http://127.0.0.1:${port}`, accept: "text/html,application/xhtml+xml" },
    body: "user=oauthci&password=Guclu-Parola-77z&next=" + encodeURIComponent(authorize) });
  // CSP `form-action 'self'` yönlendirme zincirini de denetlediği için 303 yerine devam sayfası döner.
  assert.equal(reg2.status, 200, reg2.body.slice(0, 200));
  assert.match(reg2.body, /http-equiv="refresh"/, "devam sayfası meta refresh içermeli");
  assert.match(reg2.body, /\/authorize\?response_type=code/, "devam sayfası /authorize adresini taşımalı (panele değil)");
  const cookie = reg2.headers["set-cookie"][0].split(";")[0];

  // 2) Açık yönlendirme yok: başka siteye next kabul edilmez.
  const evil = await request(port, { method: "POST", target: "/local/login",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: `http://127.0.0.1:${port}` },
    body: "user=oauthci&password=Guclu-Parola-77z&next=" + encodeURIComponent("https://kotu.example/x") });
  assert.equal(evil.status, 303);
  assert.equal(evil.headers.location, "/", "dış adres reddedilmeli");

  // 3) Çerezle /authorize: GitHub'a gitmeden istemciye kod döner.
  const auth = await request(port, { target: authorize, headers: { cookie } });
  assert.equal(auth.status, 302, `authorize → ${auth.status}`);
  const loc = new URL(auth.headers.location);
  assert.equal(loc.origin + loc.pathname, redirectUri, "istemcinin callback adresine dönmeli");
  const code = loc.searchParams.get("code");
  assert.ok(code, "izin kodu üretilmeli");
  assert.equal(loc.searchParams.get("state"), "st-1");

  // 4) Kod → token → MCP: uçtan uca bağlantı çalışıyor.
  const tok = await request(port, { method: "POST", target: "/token",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier,
      client_id: clientId, redirect_uri: redirectUri }).toString() });
  assert.equal(tok.status, 200, tok.body.slice(0, 300));
  const access = JSON.parse(tok.body).access_token;
  assert.ok(access, "access_token dönmeli");
  const mcp = await request(port, { method: "POST", target: "/mcp",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${access}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } }) });
  assert.equal(mcp.status, 200, mcp.body.slice(0, 300));
});

test("CSP form-action: form sonrası istemciye geçiş 302 değil devam sayfasıyla olur", async (t) => {
  // GitHub yapılandırılmamış sunucu: /authorize token formunu gösterir.
  const token = "z".repeat(4) + "0123456789abcdef0123456789abcdef";
  const { port } = await start(t, { HARDTOOLS_HTTP_TOKEN: token, HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "", HARDTOOLS_OAUTH_ALLOWED_LOGINS: "" });
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";
  const reg = await request(port, { method: "POST", target: "/register",
    headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [redirectUri] }) });
  const clientId = JSON.parse(reg.body).client_id;
  const crypto = await import("node:crypto");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const body = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    code_challenge: challenge, code_challenge_method: "S256", state: "st-2", access_token: token }).toString();

  const r = await request(port, { method: "POST", target: "/authorize",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "text/html,application/xhtml+xml" }, body });
  // Programatik istemci (Accept: */*) 302 sözleşmesini korur.
  const api = await request(port, { method: "POST", target: "/authorize",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body });
  assert.equal(api.status, 302, `API istemcisi 302 almalı: ${api.status}`);
  // 302 + Location olsaydı Chrome "form-action 'self'" ihlali verip gönderimi kesiyordu.
  assert.equal(r.status, 200, `POST /authorize → ${r.status}`);
  assert.equal(r.headers.location, undefined, "form sonrası 302 yönlendirme olmamalı");
  assert.match(r.body, /http-equiv="refresh"/, "devam sayfası meta refresh içermeli");
  assert.match(r.body, new RegExp(redirectUri.replace(/[.]/g, "\\.")), "devam sayfası istemci adresini taşımalı");
  assert.match(r.body, /code=/, "izin kodu devam adresinde olmalı");
});

test("izin formu Origin: null üretmez; kendi origin'i kabul, çapraz origin reddedilir", async (t) => {
  // Chrome, <meta name="referrer" content="no-referrer"> olan sayfadan form gönderirken
  // `Origin: null` yollar ve sunucu bunu haklı olarak 403 ile reddeder — izin formu kırılıyordu.
  // Form sayfaları artık meta referrer = same-origin kullanır; koruma katı kalır.
  const token = "y".repeat(4) + "0123456789abcdef0123456789abcdef";
  const { port } = await start(t, { HARDTOOLS_HTTP_TOKEN: token, HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "", HARDTOOLS_OAUTH_ALLOWED_LOGINS: "" });
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";
  const reg = await request(port, { method: "POST", target: "/register",
    headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [redirectUri] }) });
  const clientId = JSON.parse(reg.body).client_id;
  const crypto = await import("node:crypto");
  const challenge = crypto.createHash("sha256").update(crypto.randomBytes(32).toString("base64url")).digest("base64url");
  const q = { response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    code_challenge: challenge, code_challenge_method: "S256", state: "st-3" };
  const body = new URLSearchParams({ ...q, access_token: token }).toString();
  const headers = { "content-type": "application/x-www-form-urlencoded", accept: "text/html,application/xhtml+xml" };
  const ownOrigin = `http://127.0.0.1:${port}`;

  // Form sayfası tarayıcıya "same-origin" demeli; "no-referrer" olsaydı POST Origin: null taşırdı.
  const consent = await request(port, { method: "GET", target: "/authorize?" + new URLSearchParams(q).toString() });
  assert.equal((consent.headers["referrer-policy"] ?? "").toLowerCase(), "same-origin");
  assert.doesNotMatch(consent.body, /name="referrer" content="no-referrer"/, "meta referrer form POST'unu null yapmamalı");

  const own = await request(port, { method: "POST", target: "/authorize", headers: { ...headers, origin: ownOrigin }, body });
  assert.equal(own.status, 200, `kendi formumuz kabul edilmeli: ${own.status} ${own.body.slice(0, 120)}`);
  assert.match(own.body, /code=/, "izin kodu üretilmeli");

  const nul = await request(port, { method: "POST", target: "/authorize", headers: { ...headers, origin: "null" }, body });
  assert.equal(nul.status, 403, "Origin: null reddedilmeye devam etmeli");

  const evil = await request(port, { method: "POST", target: "/authorize", headers: { ...headers, origin: "https://evil.example" }, body });
  assert.equal(evil.status, 403, "çapraz origin reddedilmeli");
  assert.doesNotMatch(evil.body, /code=/, "çapraz origin'e kod sızmamalı");

  // Cihaz onayı formu da aynı düzeltmeden pay almalı.
  const device = await request(port, { method: "GET", target: "/device" });
  assert.equal((device.headers["referrer-policy"] ?? "").toLowerCase(), "same-origin");
  assert.doesNotMatch(device.body, /name="referrer" content="no-referrer"/);
});
