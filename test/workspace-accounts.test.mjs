// 1.5.36: /workspaces sayfası ile model aracının AYNI sahiplik doğrulamasını kullanması.
// Önceki hâlde sayfadaki "Devral" işlemi yalnız dizin adı biçimini denetliyordu: bir kullanıcı
// listede görmese bile `adopt=<başka hesabın a-…>` gönderip o hesabın dosyalarını kendi köküne
// taşıyabiliyordu (hesaplar arası veri sızması). Bu dosya o sınıfı kilitler.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const TOKEN = "w".repeat(4) + "0123456789abcdef0123456789abcdef";
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const enc = (o) => new URLSearchParams(o).toString();
const hex = () => crypto.randomBytes(8).toString("hex");

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

async function setup(t) {
  const root = tmp("ht-ws-root-");
  const audit = tmp("ht-ws-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const stateDir = path.join(audit, "state");
  const env = { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_STATE_DIR: stateDir };
  const cli = (...args) => spawnSync(process.execPath, [entry, "--local-user", ...args], { env, encoding: "utf8", input: "" });
  assert.equal(cli("add", "sahip", "--password-stdin", "--password", "Ilk-Parola-42x").status !== 2, true);
  cli("del", "sahip");
  assert.equal(cli("add", "sahip", "--password", "Ilk-Parola-42x").status, 0);
  assert.equal(cli("add", "diger", "--password", "Baska-Parola-77y").status, 0);

  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_STATE_DIR: stateDir,
      HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`, HARDTOOLS_LOCAL_SIGNUP: "first", HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1" },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 100; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, err);

  const login = async (user, password) => {
    const r = await request(port, { method: "POST", target: "/local/login", headers: FORM, body: enc({ user, password }) });
    assert.equal(r.status, 303, `${user} giriş: ${r.body.slice(0, 160)}`);
    return r.headers["set-cookie"][0].split(";")[0];
  };
  return { root, stateDir, cli, port, login, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

/** Kök altında, sahibi işaretlenmiş eski bir oturum dizini üret. */
function legacyRoot(root, user, files) {
  const dir = path.join(root, `u-${hex()}`);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, ".ht-owner"), JSON.stringify({ owner: `local:${user}`, user, at: Date.now() }));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  return path.basename(dir);
}

test("workspaces: liste yalnız kendi köklerini gösterir", async (t) => {
  const s = await setup(t);
  t.after(s.cleanup);
  const mine = legacyRoot(s.root, "sahip", { "benim.txt": "a" });
  const other = legacyRoot(s.root, "diger", { "gizli.txt": "b" });

  const cookie = await s.login("sahip", "Ilk-Parola-42x");
  const page = await request(s.port, { target: "/workspaces", headers: { cookie } });
  assert.equal(page.status, 200);
  assert.ok(page.body.includes(mine), "kendi dizini listede olmalı");
  assert.ok(!page.body.includes(other), "başka hesabın dizini listede olmamalı");
  assert.ok(!page.body.includes("gizli.txt"));
  assert.match(page.body, /Devral/);
});

test("workspaces: başka hesabın dizini devralınamaz (hesaplar arası sızma yok)", async (t) => {
  const s = await setup(t);
  t.after(s.cleanup);
  const other = legacyRoot(s.root, "diger", { "gizli.txt": "cok-gizli" });
  const cookie = await s.login("sahip", "Ilk-Parola-42x");

  const r = await request(s.port, { method: "POST", target: "/workspaces", headers: { ...FORM, cookie },
    body: enc({ adopt: other }) });
  assert.equal(r.status, 200);
  assert.match(r.body, /başka bir hesaba ait/, `devralma reddedilmeli: ${r.body.match(/<p class="[eo]">[^<]*/)?.[0]}`);
  assert.match(r.body, /<p class="e">/, "hata satırı hata biçiminde gösterilmeli");

  assert.ok(fs.existsSync(path.join(s.root, other, "gizli.txt")), "kaynak dosya yerinde kalmalı");
  // Hedef kökte dosya olmamalı.
  const roots = fs.readdirSync(s.root).filter((n) => n.startsWith("a-"));
  for (const rr of roots) {
    const found = fs.existsSync(path.join(s.root, rr, "gizli.txt"));
    assert.equal(found, false, `başka hesabın dosyası kopyalanmamalı (${rr})`);
  }
});

test("workspaces: kendi eski kökü devralınır, var olanın üzerine yazılmaz", async (t) => {
  const s = await setup(t);
  t.after(s.cleanup);
  const old = legacyRoot(s.root, "sahip", { "eski.txt": "eski", "cakisan.txt": "eski-sürüm" });
  const cookie = await s.login("sahip", "Ilk-Parola-42x");

  // Önce hesap kökünde çakışan bir dosya oluştur.
  const ok1 = await request(s.port, { target: "/workspaces", headers: { cookie } });
  assert.equal(ok1.status, 200);
  const accRoot = fs.readdirSync(s.root).find((n) => n.startsWith("a-"));
  assert.ok(accRoot, "hesap kökü oluşmalı");
  fs.writeFileSync(path.join(s.root, accRoot, "cakisan.txt"), "yeni-sürüm");

  const r = await request(s.port, { method: "POST", target: "/workspaces", headers: { ...FORM, cookie },
    body: enc({ adopt: old }) });
  assert.equal(r.status, 200);
  assert.match(r.body, /taşındı/, `devralma çalışmalı: ${r.body.match(/<p class="[eo]">[^<]*/)?.[0]}`);
  // Dosyalar gerçekten yer değiştirdi mi?
  const all = fs.readdirSync(s.root).filter((n) => n.startsWith("a-") || n.startsWith("u-"));
  const find = (name) => all.filter((d) => fs.existsSync(path.join(s.root, d, name)));
  assert.equal(find("eski.txt").length, 1, "devralınan dosya tam olarak bir yerde olmalı");
  const holder = find("eski.txt")[0];
  assert.ok(holder.startsWith("a-"), "dosya hesap köküne taşınmalı");
  assert.equal(fs.readFileSync(path.join(s.root, holder, "eski.txt"), "utf8"), "eski");
  assert.equal(fs.readFileSync(path.join(s.root, holder, "cakisan.txt"), "utf8"), "yeni-sürüm", "var olan dosya korunmalı");
});

test("workspaces: geçersiz dizin adı, kişisel olmayan dizin ve çapraz origin reddedilir", async (t) => {
  const s = await setup(t);
  t.after(s.cleanup);
  const cookie = await s.login("sahip", "Ilk-Parola-42x");

  for (const bad of ["../../etc", "/etc", "a-xyz", "u-0000000000000000/../..", "notadir"]) {
    const r = await request(s.port, { method: "POST", target: "/workspaces", headers: { ...FORM, cookie },
      body: enc({ adopt: bad }) });
    assert.equal(r.status, 200);
    assert.match(r.body, /Hata|geçersiz|listede yok|dışında/, `reddedilmeli: ${bad}`);
  }

  const cross = await request(s.port, { method: "POST", target: "/workspaces",
    headers: { ...FORM, cookie, origin: "https://kotu.example" }, body: enc({ adopt: "u-0123456789abcdef" }) });
  assert.match(cross.body, /başka bir siteden/, "çapraz origin formu reddedilmeli");

  const empty = await request(s.port, { method: "POST", target: "/workspaces", headers: { ...FORM, cookie }, body: "" });
  assert.match(empty.body, /seçilmedi/);
});

test("workspaces: girişsiz erişim giriş sayfasına düşer", async (t) => {
  const s = await setup(t);
  t.after(s.cleanup);
  const r = await request(s.port, { target: "/workspaces" });
  assert.equal(r.status, 200);
  assert.match(r.body, /giriş|Giriş/);
  assert.doesNotMatch(r.body, /Devral/);
});
