// GitHub ile giriş: /authorize yönlendirmesi, imzalı state, allowlist ve yapılandırma
// hatalarının davranışı. Gerçek GitHub hesabı gerekmez.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef";
const VERIFIER = crypto.randomBytes(32).toString("base64url").slice(0, 43);
const CHALLENGE = crypto.createHash("sha256").update(VERIFIER, "ascii").digest("base64url");
const CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";

function request(port, { method = "GET", target = "/", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body !== null) req.write(JSON.stringify(body));
    req.end();
  });
}

async function startServer(t, extraEnv) {
  const root = tmp("ht-gh-root-");
  const audit = tmp("ht-gh-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: true }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: {
      ...process.env,
      HARDTOOLS_ROOTS: root,
      HARDTOOLS_CONFIG: cfg,
      HARDTOOLS_HTTP_TOKEN: TOKEN,
      HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`,
      ...extraEnv
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  let err = "";
  child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 80; i++) {
    if (/listening/.test(err) || child.exitCode !== null) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  t.after(() => child.kill("SIGKILL"));
  return { port, child, output: () => err };
}

async function registeredClient(port) {
  const res = await request(port, {
    method: "POST", target: "/register",
    headers: { "content-type": "application/json" },
    body: { redirect_uris: [CLAUDE_CALLBACK], client_name: "github-test" }
  });
  assert.equal(res.status, 201, res.body);
  return JSON.parse(res.body).client_id;
}

const authorizePath = (clientId) => "/authorize?" + new URLSearchParams({
  response_type: "code", client_id: clientId, redirect_uri: CLAUDE_CALLBACK,
  state: "claude-state", code_challenge: CHALLENGE, code_challenge_method: "S256"
}).toString();

test("github login: /authorize redirects to github.com with a signed state", async (t) => {
  const { port } = await startServer(t, {
    HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "Iv1.testclient",
    HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET: "test-secret",
    HARDTOOLS_OAUTH_ALLOWED_LOGINS: "tlegends231"
  });
  const clientId = await registeredClient(port);
  const res = await request(port, { target: authorizePath(clientId) });
  assert.equal(res.status, 302, res.body);
  const location = new URL(String(res.headers.location));
  assert.equal(location.origin, "https://github.com");
  assert.equal(location.pathname, "/login/oauth/authorize");
  assert.equal(location.searchParams.get("client_id"), "Iv1.testclient");
  assert.equal(location.searchParams.get("redirect_uri"), `http://127.0.0.1:${port}/oauth/github/callback`);
  assert.match(String(location.searchParams.get("scope")), /read:user/);
  assert.equal(location.searchParams.get("allow_signup"), "false");
  assert.ok((location.searchParams.get("state") ?? "").length > 40, "state imzalı olmalı");
  assert.equal(res.headers["referrer-policy"], "no-referrer");
  // Token formu artık gösterilmiyor.
  assert.equal(res.body, "");
});

test("github login: tampered or missing state never reaches GitHub or Claude", async (t) => {
  const { port } = await startServer(t, {
    HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "Iv1.testclient",
    HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET: "test-secret",
    HARDTOOLS_OAUTH_ALLOWED_LOGINS: "tlegends231"
  });
  const clientId = await registeredClient(port);
  const redirect = await request(port, { target: authorizePath(clientId) });
  const state = new URL(String(redirect.headers.location)).searchParams.get("state");
  const tampered = state.slice(0, -2) + (state.endsWith("AA") ? "BB" : "AA");

  for (const candidate of [tampered, "", "not-a-state"]) {
    const res = await request(port, { target: `/oauth/github/callback?code=abc&state=${encodeURIComponent(candidate)}` });
    assert.equal(res.status, 400, `state reddedilmeliydi: ${candidate.slice(0, 8)}`);
    assert.match(res.body, /geçersiz|süresi dolmuş/);
    assert.equal(res.headers.location, undefined, "başarısız doğrulamada yönlendirme olmamalı");
  }
});

test("github login: an invalid provider code fails closed without a redirect", async (t) => {
  const { port } = await startServer(t, {
    HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "Iv1.testclient",
    HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET: "test-secret",
    HARDTOOLS_OAUTH_ALLOWED_LOGINS: "tlegends231"
  });
  const clientId = await registeredClient(port);
  const redirect = await request(port, { target: authorizePath(clientId) });
  const state = new URL(String(redirect.headers.location)).searchParams.get("state");
  const res = await request(port, { target: `/oauth/github/callback?code=definitely-not-a-real-code&state=${encodeURIComponent(state)}` });
  // Gerçek GitHub çağrısı başarısız olur: ya 400 döner ya da ağ yoksa test atlanır.
  if (res.status === 400) {
    assert.match(res.body, /erişim anahtarı alınamadı|reddedildi|geçersiz/);
    assert.equal(res.headers.location, undefined);
  } else {
    t.skip(`GitHub'a ulaşılamadı (durum ${res.status})`);
  }
});

test("github login: without configuration the token form stays available", async (t) => {
  const { port } = await startServer(t, {});
  const clientId = await registeredClient(port);
  const res = await request(port, { target: authorizePath(clientId) });
  assert.equal(res.status, 200);
  assert.match(res.body, /access token/);
  assert.match(res.body, /fly secrets|BAGLAN\.html/, "token'ın nereden alınacağı yazmalı");
  assert.match(res.body, /HARDTOOLS_HTTP_TOKEN/);
  const callback = await request(port, { target: "/oauth/github/callback?code=x&state=y" });
  assert.equal(callback.status, 404, "yapılandırma yoksa callback kapalı olmalı");
});

test("github login: a client id alone means device flow, a secret alone is ignored, an empty allowlist refuses to start", async (t) => {
  // Yalnız CLIENT_ID: device flow (tarayıcı GitHub'a değil, kod gösterim sayfasına gider).
  const deviceOnly = await startServer(t, { HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "Iv1.testclient", HARDTOOLS_OAUTH_ALLOWED_LOGINS: "tlegends231" });
  const clientId = await registeredClient(deviceOnly.port);
  const page = await request(deviceOnly.port, { target: authorizePath(clientId) });
  // Sahte client_id ile gerçek GitHub'a gidilir: ya kod sayfası (200) ya da GitHub reddi (502);
  // her hâlde token formu gösterilmez.
  assert.ok([200, 502].includes(page.status), `beklenmeyen durum: ${page.status}`);
  assert.doesNotMatch(page.body, /access token/);
  assert.match(deviceOnly.output(), /device flow, no client secret/);

  // Yalnız CLIENT_SECRET: yok sayılır, token formu kalır.
  const secretOnly = await startServer(t, { HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET: "orphan-secret" });
  const cid2 = await registeredClient(secretOnly.port);
  const form = await request(secretOnly.port, { target: authorizePath(cid2) });
  assert.equal(form.status, 200, "sır tek başına giriş açmamalı");
  assert.match(form.body, /access token/);
  assert.match(secretOnly.output(), /ignoring HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET without/);

  // Boş izin listesi: açılış reddedilir.
  const audit = tmp("ht-gh-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port)], {
    env: {
      ...process.env, HARDTOOLS_ROOTS: tmp("ht-gh-root-"), HARDTOOLS_CONFIG: cfg,
      HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}`,
      HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "Iv1.testclient"
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  let err = "";
  child.stderr.on("data", (d) => { err += d; });
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve("timeout"), 5000);
    child.on("exit", (exitCode) => { clearTimeout(timer); resolve(exitCode); });
  });
  assert.equal(code, 1, "boş allowlist ile açılış reddedilmeli");
  assert.match(err, /ALLOWED_LOGINS/);
});
