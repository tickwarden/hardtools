// GitHub device flow (istemci sırrı olmadan giriş). Sahte bir GitHub sunucusuna karşı
// uçtan uca: /authorize → kod gösterimi → yoklama → Claude'a kod → /token → /mcp.
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
    if (body !== null) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

/** Sahte GitHub: device code + token yoklaması + /user (+/user/emails). */
function fakeGithub(t, { login = "tlegends231", email = null, emails = [], mode = "pending-then-ok" } = {}) {
  const state = { polls: 0, mode, accessToken: "gho_testtoken", deviceCode: "dev-" + crypto.randomBytes(6).toString("hex") };
  const server = http.createServer((req, res) => {
    const send = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/login/device/code") {
      return send(200, { device_code: state.deviceCode, user_code: "CC89-D30A", verification_uri: `http://127.0.0.1:${server.address().port}/login/device`, expires_in: 900, interval: 5 });
    }
    if (url.pathname === "/login/oauth/access_token") {
      state.polls += 1;
      if (state.mode === "deny") return send(200, { error: "access_denied" });
      if (state.mode === "pending-then-ok" && state.polls === 1) return send(200, { error: "authorization_pending" });
      if (state.mode === "always-pending") return send(200, { error: "authorization_pending" });
      return send(200, { access_token: state.accessToken, token_type: "bearer", scope: "read:user,user:email" });
    }
    if (url.pathname === "/user") {
      if (req.headers.authorization !== `Bearer ${state.accessToken}`) return send(401, { message: "bad creds" });
      return send(200, { login, email });
    }
    if (url.pathname === "/user/emails") {
      if (req.headers.authorization !== `Bearer ${state.accessToken}`) return send(401, { message: "bad creds" });
      return send(200, emails);
    }
    send(404, { message: "not found" });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
    t.after(() => server.close());
    resolve({ server, state, base: `http://127.0.0.1:${server.address().port}` });
  }));
}

async function startServer(t, ghBase, extraEnv = {}) {
  const root = tmp("ht-ghd-root-");
  const audit = tmp("ht-ghd-audit-");
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
      HARDTOOLS_OAUTH_GITHUB_CLIENT_ID: "Iv1.deviceflow",
      HARDTOOLS_OAUTH_ALLOWED_LOGINS: "tlegends231",
      HARDTOOLS_OAUTH_GITHUB_WEB_BASE: ghBase,
      HARDTOOLS_OAUTH_GITHUB_API_BASE: ghBase,
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
  assert.match(err, /listening/, `sunucu başlamadı: ${err}`);
  assert.match(err, /device flow, no client secret/);
  return { port, output: () => err };
}

async function registeredClient(port) {
  const res = await request(port, {
    method: "POST", target: "/register",
    headers: { "content-type": "application/json" },
    body: { redirect_uris: [CLAUDE_CALLBACK], client_name: "device-flow-test" }
  });
  assert.equal(res.status, 201, res.body);
  return JSON.parse(res.body).client_id;
}

const authorizePath = (clientId) => "/authorize?" + new URLSearchParams({
  response_type: "code", client_id: clientId, redirect_uri: CLAUDE_CALLBACK,
  state: "claude-state", code_challenge: CHALLENGE, code_challenge_method: "S256"
}).toString();

const ticketOf = (html) => {
  const m = /\/oauth\/github\/poll\?t=([A-Za-z0-9_-]+)/.exec(html);
  assert.ok(m, "bekleme sayfası yoklama bağlantısı içermeli");
  return decodeURIComponent(m[1]);
};

test("github device flow: /authorize shows a one-time code and no client secret is needed", async (t) => {
  const gh = await fakeGithub(t);
  const { port } = await startServer(t, gh.base);
  const clientId = await registeredClient(port);
  const res = await request(port, { target: authorizePath(clientId) });
  assert.equal(res.status, 200);
  assert.match(res.body, /CC89-D30A/, "kullanıcı kodu gösterilmeli");
  assert.match(res.body, /github\.com|127\.0\.0\.1:\d+\/login\/device/);
  assert.match(res.body, /http-equiv="refresh"/, "sayfa kendiliğinden yoklamalı");
  assert.match(String(res.headers["content-security-policy"]), /default-src 'none'/);
  ticketOf(res.body);
});

test("github device flow: pending → authorized completes the whole exchange up to /mcp", async (t) => {
  const gh = await fakeGithub(t, { login: "tlegends231", email: null, emails: [{ email: "tlegends231@gmail.com", primary: true, verified: true }] });
  const { port } = await startServer(t, gh.base);
  const clientId = await registeredClient(port);
  const ticket = ticketOf((await request(port, { target: authorizePath(clientId) })).body);

  const first = await request(port, { target: `/oauth/github/poll?t=${encodeURIComponent(ticket)}` });
  assert.equal(first.status, 200, "ilk yoklama beklemede kalmalı");
  assert.match(first.body, /GitHub onayı bekleniyor/);
  assert.equal(gh.state.polls, 1, "GitHub'a bir kez sorulmalı");

  // GitHub interval'i 5 sn; ikinci yoklama gerçekten beklemeli.
  const blocked = await request(port, { target: `/oauth/github/poll?t=${encodeURIComponent(ticket)}` });
  assert.match(blocked.body, /bekleniyor/);
  assert.equal(gh.state.polls, 1, "interval dolmadan GitHub'a tekrar sorulmamalı");

  await new Promise((r) => setTimeout(r, 5200));
  const done = await request(port, { target: `/oauth/github/poll?t=${encodeURIComponent(ticket)}` });
  assert.equal(done.status, 302, done.body);
  const back = new URL(String(done.headers.location));
  assert.equal(back.origin + back.pathname, CLAUDE_CALLBACK);
  assert.equal(back.searchParams.get("state"), "claude-state");
  const code = back.searchParams.get("code");
  assert.ok(code && code.length > 40);

  const tok = await request(port, {
    method: "POST", target: "/token",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: VERIFIER, client_id: clientId, redirect_uri: CLAUDE_CALLBACK }).toString()
  });
  assert.equal(tok.status, 200, tok.body);
  const access = JSON.parse(tok.body).access_token;
  assert.ok(access);

  const init = await request(port, {
    method: "POST", target: "/mcp",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${access}` },
    body: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "device-test", version: "1" } } }
  });
  assert.equal(init.status, 200, init.body.slice(0, 200));
});

test("github device flow: an account outside the allowlist is refused and gets no code", async (t) => {
  const gh = await fakeGithub(t, { login: "someoneelse", emails: [{ email: "x@example.com", primary: true, verified: true }] });
  const { port } = await startServer(t, gh.base);
  const clientId = await registeredClient(port);
  const ticket = ticketOf((await request(port, { target: authorizePath(clientId) })).body);
  await request(port, { target: `/oauth/github/poll?t=${encodeURIComponent(ticket)}` });
  await new Promise((r) => setTimeout(r, 5200));
  const res = await request(port, { target: `/oauth/github/poll?t=${encodeURIComponent(ticket)}` });
  assert.equal(res.status, 403, res.body);
  assert.match(res.body, /izin verilmiyor/);
  assert.equal(res.headers.location, undefined);
});

test("github device flow: GitHub rejection and a forgotten ticket fail closed", async (t) => {
  const gh = await fakeGithub(t, { mode: "deny" });
  const { port } = await startServer(t, gh.base);
  const clientId = await registeredClient(port);
  const ticket = ticketOf((await request(port, { target: authorizePath(clientId) })).body);
  const denied = await request(port, { target: `/oauth/github/poll?t=${encodeURIComponent(ticket)}` });
  assert.equal(denied.status, 403);
  assert.match(denied.body, /reddedildi/);
  assert.equal(denied.headers.location, undefined);

  const unknown = await request(port, { target: "/oauth/github/poll?t=uydurma-bilet" });
  assert.equal(unknown.status, 410);
  const used = await request(port, { target: `/oauth/github/poll?t=${encodeURIComponent(ticket)}` });
  assert.equal(used.status, 410, "kullanılmış bilet tekrar çalışmamalı");
});
