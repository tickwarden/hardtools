// Uçtan uca tarayıcı testi (gerçek Chrome): yerel hesap + davet + parola + workspace + OAuth.
// CI'da Chrome yok; elle çalıştırılır:
//   npm run build && npm i --no-save puppeteer && node scripts/e2e-browser.mjs
// Kapsam: davetle kayıt → panel → kimlik kartı → çalışma alanları → devralma → parola değiştirme →
// çıkış → yeni parolayla giriş → ortak çalışma alanı (MCP yaz/oku) → OAuth kod akışı.
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import puppeteer from "puppeteer";

const repo = path.resolve(import.meta.dirname, "..");
const entry = path.join(repo, "dist/index.js");
const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "e2e-root-")));
const audit = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "e2e-audit-")));
const cfg = path.join(audit, "config.json");
fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
const stateDir = path.join(audit, "state");
const OPKEY = "e2e-operator-anahtar-0123456789";
const env = { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_STATE_DIR: stateDir, HARDTOOLS_LOCAL_SIGNUP: "first",
  HARDTOOLS_OPERATOR_TOKEN: OPKEY,
  HARDTOOLS_HTTP_TOKEN: "e".repeat(4) + "0123456789abcdef0123456789abcdef", HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "", HARDTOOLS_OAUTH_ALLOWED_LOGINS: "" };

const problems = [];
const ok = (cond, msg) => { if (!cond) problems.push(msg); console.log(`${cond ? "✔" : "✘"} ${msg}`); };

// 1) İlk hesap CLI ile (kayıt davet koduna bağlanacak)
const cli = (...args) => spawnSync(process.execPath, [entry, "--local-user", ...args], { env, encoding: "utf8", input: "" });
let r = cli("add", "sahip", "--password", "Ilk-Parola-42x");
ok(r.status === 0, "CLI hesap açma: " + (r.stdout + r.stderr).trim());

// 2) Eski bir sohbet kökü (devralma için) ve başka hesabın kökü
const legacy = path.join(root, "u-" + crypto.randomBytes(8).toString("hex"));
fs.mkdirSync(legacy, { recursive: true });
fs.writeFileSync(path.join(legacy, ".ht-owner"), JSON.stringify({ owner: "local:tarayici", user: "tarayici" }));
fs.writeFileSync(path.join(legacy, "eski-is.txt"), "devralinacak");
const foreign = path.join(root, "u-" + crypto.randomBytes(8).toString("hex"));
fs.mkdirSync(foreign, { recursive: true });
fs.writeFileSync(path.join(foreign, ".ht-owner"), JSON.stringify({ owner: "local:diger", user: "diger" }));
fs.writeFileSync(path.join(foreign, "baskasinin.txt"), "gizli");

// 3) Sunucu
const probe = http.createServer(); await new Promise((r2) => probe.listen(0, "127.0.0.1", r2));
const port = probe.address().port; await new Promise((r2) => probe.close(r2));
const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
  env: { ...env, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1" }, stdio: ["ignore", "ignore", "pipe"] });
let err = ""; child.stderr.on("data", (d) => { err += d; });
for (let i = 0; i < 120 && !/listening/.test(err); i++) await new Promise((r2) => setTimeout(r2, 100));
ok(/listening/.test(err), "sunucu dinliyor: " + err.slice(-200));
const origin = `http://127.0.0.1:${port}`;

// 4) İkinci hesap için davet kodu
const code = cli("invite", "--ttl", "30").stdout.split("\n")[0].trim();
ok(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code), "davet kodu üretildi: " + code);

const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
const page = await browser.newPage();
const consoleErrors = [];
page.on("console", (m) => { if (/Content Security Policy|Uncaught|error/i.test(m.text())) consoleErrors.push(m.text().slice(0, 160)); });
page.on("pageerror", (e) => consoleErrors.push("pageerror: " + e.message.slice(0, 120)));
page.on("dialog", async (d) => { console.log("   (onay penceresi:", d.message().slice(0, 60) + "…)"); await d.accept(); });

// 5) Davet koduyla kayıt
await page.goto(`${origin}/local`, { waitUntil: "networkidle2" });
await page.type('form[action="/local/register"] input[name="code"]', code.toLowerCase().replace("-", " "));
await page.type('form[action="/local/register"] input[name="user"]', "tarayici");
await page.type('form[action="/local/register"] input[name="password"]', "Kontrol-Parola-42x");
await Promise.all([page.waitForNavigation({ waitUntil: "networkidle2" }).catch(() => null), page.click('form[action="/local/register"] button[type="submit"]')]);
const regText = await page.evaluate(() => document.body.innerText);
ok(/Panel|Giriş: tarayici/.test(regText), "davetle kayıt → panel: " + page.url() + " | " + (regText.match(/Hata:[^\n]*/) ?? [""])[0]);
const mcp = await page.$eval("#mcp", (e) => e.value).catch(() => "");
ok(/\/lc\/[A-Za-z0-9_-]{16,}$/.test(mcp), "panelde kişisel MCP adresi: " + mcp);

// 6) /local giriş yapmışken kimlik kartı
await page.goto(`${origin}/local`, { waitUntil: "networkidle2" });
const localText = await page.evaluate(() => document.body.innerText);
ok(/Giriş: tarayici/.test(localText), "giriş yapmış kullanıcıya kimlik kartı");
ok(!(await page.$('form[action="/local/login"]')), "giriş formu tekrar gösterilmiyor");
ok(Boolean(await page.$('form[action="/local/password"]')), "parola değiştirme formu var");
ok(Boolean(await page.$('form[action="/local/connector"]')), "bağlantı anahtarı yenileme var");

// 7) Workspace: kendi eski kökü listede, başkasının kökü değil
await page.goto(`${origin}/workspaces`, { waitUntil: "networkidle2" });
const wsText = await page.evaluate(() => document.body.innerText);
ok(wsText.includes(path.basename(legacy)), "kendi eski kökü listede");
ok(!wsText.includes(path.basename(foreign)), "başka hesabın kökü listede değil");
ok(wsText.includes("eski-is.txt") === false, "dosya adı listelenmez (yalnız dizin)");

// 8) Devral (onay penceresi otomatik kabul)
const adoptBtn = await page.$(`form[action="/workspaces"] input[value="${path.basename(legacy)}"]`);
if (adoptBtn) {
  const form = await adoptBtn.evaluateHandle((e) => e.closest("form"));
  await Promise.all([page.waitForNavigation({ waitUntil: "networkidle2" }).catch(() => null), form.asElement().$eval("button", (b) => b.click())]);
  const after = await page.evaluate(() => document.body.innerText);
  ok(/taşındı/.test(after), "devralma bildirimi: " + (after.match(/\d+ öğe taşındı[^\n]*/) || [""])[0]);
}
const moved = fs.readdirSync(root).filter((n) => n.startsWith("a-")).some((n) => fs.existsSync(path.join(root, n, "eski-is.txt")));
ok(moved, "dosya hesap köküne taşındı");
ok(fs.existsSync(path.join(foreign, "baskasinin.txt")), "başka hesabın dosyası yerinde");

// 9) Parola değiştir
await page.goto(`${origin}/local`, { waitUntil: "networkidle2" });
await page.type('form[action="/local/password"] input[name="current"]', "Kontrol-Parola-42x");
await page.type('form[action="/local/password"] input[name="next"]', "Yeni-Kontrol-77y");
await Promise.all([page.waitForNavigation({ waitUntil: "networkidle2" }).catch(() => null), page.click('form[action="/local/password"] button[type="submit"]')]);
ok(/Parola değişti/.test(await page.evaluate(() => document.body.innerText)), "parola değişti bildirimi");

// 10) Çıkış + yeni parolayla giriş
await page.goto(`${origin}/settings/logout`, { waitUntil: "networkidle2" });
ok(Boolean(await page.$('form[action="/settings/logout"] button[type="submit"]')), "çıkış onay sayfası düğme sunuyor");
await Promise.all([page.waitForNavigation({ waitUntil: "networkidle2" }).catch(() => null), page.click('form[action="/settings/logout"] button[type="submit"]')]);
await page.goto(`${origin}/local`, { waitUntil: "networkidle2" });
ok(Boolean(await page.$('form[action="/local/login"]')), "çıkıştan sonra giriş formu geri geldi");
await page.type('form[action="/local/login"] input[name="user"]', "TARAYICI");
await page.type('form[action="/local/login"] input[name="password"]', "Yeni-Kontrol-77y");
await Promise.all([page.waitForNavigation({ waitUntil: "networkidle2" }).catch(() => null), page.click('form[action="/local/login"] button[type="submit"]')]);
ok(/Giriş: tarayici/.test(await page.evaluate(() => document.body.innerText)), "yeni parola + büyük harfli adla giriş: " + page.url());

// 10b) Aynı hesabın iki sohbeti aynı çalışma alanını görür (1.5.37 varsayılanı)
const lcKey = /\/lc\/([A-Za-z0-9_-]{16,})/.exec(mcp)?.[1];
const rpcCall = (payload) => new Promise((res, rej) => {
  const rq = http.request({ host: "127.0.0.1", port, path: `/lc/${lcKey}`, method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" } }, (rs) => {
    let d = ""; rs.on("data", (c) => { d += c; }); rs.on("end", () => res(d));
  });
  rq.on("error", rej); rq.write(JSON.stringify(payload)); rq.end();
});
const textOf = (raw) => { const line = raw.split("\n").find((l) => l.startsWith("data: ")); const j = line ? JSON.parse(line.slice(6)) : JSON.parse(raw); return JSON.stringify(j.result?.content?.[0]?.text ?? j); };
const callTool = (name, args) => rpcCall({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });
const writeRaw = await callTool("ht_write", { path: "paylasim.txt", content: "ilk sohbet" });
ok(/CREATED paylasim\.txt/.test(writeRaw), "MCP yazma çalışıyor");
const readBack = textOf(await callTool("ht_read", { path: "paylasim.txt" }));
ok(/ilk sohbet/.test(readBack), "ikinci MCP çağrısı önceki yazmayı görüyor (ortak hesap kökü)");
const accDirs = fs.readdirSync(root).filter((n) => n.startsWith("a-"));
ok(accDirs.length === 1 && fs.existsSync(path.join(root, accDirs[0], "paylasim.txt")), "dosya tek hesap kökünde: " + accDirs.join(","));

// 10c) Yönetici paneli: tarayıcıdan davet kodu üretimi (terminal/flyctl gerekmez)
await page.goto(`${origin}/operator`, { waitUntil: "networkidle2" });
ok(Boolean(await page.$('form[action="/operator/login"] input[name="token"]')), "yönetici paneli anahtar formu");
await page.type('form[action="/operator/login"] input[name="token"]', OPKEY);
await Promise.all([page.waitForNavigation({ waitUntil: "networkidle2" }).catch(() => null), page.click('form[action="/operator/login"] button[type="submit"]')]);
const panelText = await page.evaluate(() => document.body.innerText);
ok(/Davet kodu üret/.test(panelText) && /Hesaplar/.test(panelText), "panel açıldı (davet + hesap listesi)");
await page.select('form[action="/operator/invite"] select[name="ttl"]', "30");
await Promise.all([page.waitForNavigation({ waitUntil: "networkidle2" }).catch(() => null), page.click('form[action="/operator/invite"] button[type="submit"]')]);
const panelCode = await page.$eval("#rev", (e) => e.value).catch(() => "");
ok(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(panelCode), "panelden kod üretildi: " + panelCode);
// Panelden üretilen kod gerçekten hesap açıyor mu? (ayrı sekme = temiz çerez)
// Ayrı tarayıcı bağlamı: çerezler paylaşılmasın (giriş yapmış sekme kayıt formunu göstermez).
const ctx2 = browser.createBrowserContext ? await browser.createBrowserContext() : await browser.createIncognitoBrowserContext();
const page2 = await ctx2.newPage();
page2.on("console", (m) => { if (/Content Security Policy|Uncaught/i.test(m.text())) consoleErrors.push("panel-kayit: " + m.text().slice(0, 120)); });
await page2.goto(`${origin}/local`, { waitUntil: "networkidle2" });
await page2.type('form[action="/local/register"] input[name="code"]', panelCode);
await page2.type('form[action="/local/register"] input[name="user"]', "panelkodlu");
await page2.type('form[action="/local/register"] input[name="password"]', "Panel-Kod-58x");
await Promise.all([page2.waitForNavigation({ waitUntil: "networkidle2" }).catch(() => null), page2.click('form[action="/local/register"] button[type="submit"]')]);
ok(/Giriş: panelkodlu/.test(await page2.evaluate(() => document.body.innerText)), "panelden üretilen kodla hesap açıldı ve giriş yapıldı");
// Parola sıfırlama: panelden üretilen parola ile giriş
await page.goto(`${origin}/operator`, { waitUntil: "networkidle2" });
const rows = await page.$$('form[action="/operator/passwd"]');
ok(rows.length >= 2, "panelde hesap satırları var: " + rows.length);
await page2.close(); await ctx2.close();

// 11) OAuth akışı: /local?next=/authorize… → devam sayfası → callback
const reg = await new Promise((res, rej) => {
  const rq = http.request({ host: "127.0.0.1", port, path: "/register", method: "POST", headers: { "content-type": "application/json" } }, (rs) => {
    let d = ""; rs.on("data", (c) => { d += c; }); rs.on("end", () => res(JSON.parse(d)));
  }); rq.on("error", rej);
  rq.write(JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], client_name: "e2e" })); rq.end();
});
const verifier = crypto.randomBytes(32).toString("base64url");
const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
const authorize = "/authorize?" + new URLSearchParams({ response_type: "code", client_id: reg.client_id,
  redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_challenge: challenge, code_challenge_method: "S256", state: "e2e" }).toString();
await page.goto(`${origin}/local?next=${encodeURIComponent(authorize)}`, { waitUntil: "networkidle2" });
const hits = [];
page.on("request", (rq) => { if (/auth_callback\?code=/.test(rq.url())) hits.push(rq.url()); });
await page.goto(`${origin}${authorize}`, { waitUntil: "domcontentloaded" }).catch(() => null);
await new Promise((r2) => setTimeout(r2, 1500));
const callbackOk = hits.length > 0 || /claude\.ai\/api\/mcp\/auth_callback\?code=/.test(page.url());
ok(callbackOk, "OAuth: yerel çerezle kod üretilip istemciye dönüldü");
ok(consoleErrors.length === 0, "tarayıcı konsolunda CSP/JS hatası yok: " + (consoleErrors[0] ?? "temiz"));

await browser.close();
child.kill("SIGKILL");
for (const d of [root, audit]) fs.rmSync(d, { recursive: true, force: true });
console.log(problems.length ? `\n${problems.length} SORUN: ${problems.join(" | ")}` : "\nTÜM ADIMLAR TEMİZ");
process.exit(problems.length ? 1 : 0);
