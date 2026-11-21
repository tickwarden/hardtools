// AI-generated (Claude, Anthropic), 2026-11-13. Requires human security review before production use.
// Simulates what the claude.ai custom-connector dialog does: anonymous probe -> discovery -> DCR -> consent -> PKCE token -> /mcp.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const CB = "https://claude.ai/api/mcp/auth_callback";

async function start(token, extra = {}, issueInvite = false, settings = {}) {
  const root = tmp("ht-o-"); const audit = tmp("ht-o-audit-");
  const cfg = path.join(audit, "config.json"); fs.writeFileSync(cfg, JSON.stringify({ ...settings, audit: { dir: path.join(audit, "log") } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const env = { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_HTTP_TOKEN: token, ...(issueInvite ? { HARDTOOLS_INVITE_ORIGIN: `http://127.0.0.1:${port}` } : {}), ...extra }; delete env.HARDTOOLS_PROFILE;
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], { env, stdio: ["ignore", "ignore", "pipe"] });
  let err = ""; child.stderr.on("data", d => err += d);
  for (let i = 0; i < 50 && !/listening/.test(err) && child.exitCode === null; i++) await new Promise(r => setTimeout(r, 100));
  return { base: `http://127.0.0.1:${port}`, child, invite: issueInvite ? err.match(/http:\/\/127\.0\.0\.1:\d+\/invite\/[A-Za-z0-9._~-]+/)?.[0] : undefined };
}
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };
const mcp = (base, headers = {}, p = "/mcp") => fetch(base + p, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(INIT) });
const b64u = (b) => Buffer.from(b).toString("base64url");
const form = (o) => new URLSearchParams(o).toString();
const FORM = { "content-type": "application/x-www-form-urlencoded" };

async function register(base, redirect = CB) {
  return fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [redirect] }) });
}
function pkce() { const verifier = b64u(crypto.randomBytes(32)); return { verifier, challenge: b64u(crypto.createHash("sha256").update(verifier).digest()) }; }

test("oauth: anonymous probe gets a discoverable 401, then the full flow yields a working access token", async () => {
  const token = crypto.randomBytes(32).toString("hex");
  const { base, child } = await start(token);
  try {
    // 1. anonymous probe (what claude.ai does first) must point at the metadata
    const probe = await mcp(base);
    assert.equal(probe.status, 401);
    assert.match(probe.headers.get("www-authenticate") ?? "", /Bearer resource_metadata="http:\/\/127\.0\.0\.1:\d+\/\.well-known\/oauth-protected-resource"/);

    // 2. discovery
    const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource`)).json();
    assert.equal(prm.resource, `${base}/mcp`); assert.deepEqual(prm.authorization_servers, [base]);
    const asm = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
    assert.equal(asm.issuer, base); assert.deepEqual(asm.code_challenge_methods_supported, ["S256"]);
    for (const k of ["authorization_endpoint", "token_endpoint", "registration_endpoint"]) assert.ok(asm[k].startsWith(base));

    // 3. dynamic client registration
    const reg = await register(base); assert.equal(reg.status, 201);
    const client = await reg.json(); assert.ok(client.client_id); assert.equal(client.token_endpoint_auth_method, "none");

    // 4. consent page renders, wrong secret is rejected, right secret redirects with a code and echoes state
    // RFC 7636 Appendix B: the verifier still uses S256, not a password KDF or direct comparison.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const q = { response_type: "code", client_id: client.client_id, redirect_uri: CB, state: "xyz", code_challenge: challenge, code_challenge_method: "S256" };
    const page = await fetch(`${base}/authorize?${form(q)}`); assert.equal(page.status, 200);
    const consent = await page.text();
    assert.match(consent, /name="access_token"/); assert.match(consent, /BAGLAN\.html/);
    assert.match(consent, /without the <code>Bearer<\/code> prefix/); assert.ok(!consent.includes(token));
    const wrong = await fetch(`${base}/authorize`, { method: "POST", headers: FORM, body: form({ ...q, access_token: "nope" }), redirect: "manual" });
    assert.equal(wrong.status, 401);
    const encrypted = await fetch(`${base}/authorize`, { method: "POST", headers: FORM, body: form({ ...q, access_token: "YWdlLWVuY3J5ExampleCiphertext" }), redirect: "manual" });
    assert.equal(encrypted.status, 401); assert.match(await encrypted.text(), /access token değil/);
    const good = await fetch(`${base}/authorize`, { method: "POST", headers: FORM, body: form({ ...q, access_token: token }), redirect: "manual" });
    assert.equal(good.status, 302);
    const loc = new URL(good.headers.get("location")); assert.equal(loc.origin + loc.pathname, CB); assert.equal(loc.searchParams.get("state"), "xyz");
    const code = loc.searchParams.get("code"); assert.ok(code);

    // 5. token exchange: wrong verifier fails, right one works, replay fails
    const tok = (o) => fetch(`${base}/token`, { method: "POST", headers: FORM, body: form(o) });
    const base_ = { grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: CB };
    assert.equal((await tok({ ...base_, code_verifier: b64u(crypto.randomBytes(32)) })).status, 400);
    const ok = await tok({ ...base_, code_verifier: verifier }); assert.equal(ok.status, 200);
    const t = await ok.json(); assert.equal(t.token_type, "Bearer"); assert.ok(t.access_token.startsWith("hta.")); assert.ok(t.refresh_token);
    assert.equal(ok.headers.get("cache-control"), "no-store");
    assert.equal((await tok({ ...base_, code_verifier: verifier })).status, 400, "code is single-use");

    // 6. the OAuth access token opens /mcp; a tampered one does not
    const r = await mcp(base, { authorization: `Bearer ${t.access_token}` }); assert.equal(r.status, 200); assert.match(await r.text(), /hardtools/);
    assert.equal((await mcp(base, { authorization: `Bearer ${t.access_token.slice(0, -2)}xx` })).status, 401);

    // 7. refresh works and the static bearer keeps working for Claude Code / Desktop
    const rf = await tok({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: client.client_id });
    assert.equal(rf.status, 200); const t2 = await rf.json();
    assert.equal((await mcp(base, { authorization: `Bearer ${t2.access_token}` })).status, 200);
    assert.equal((await mcp(base, { authorization: `Bearer ${token}` })).status, 200);
    // a refresh token is not an access token, and an access token is not a refresh token
    assert.equal((await mcp(base, { authorization: `Bearer ${t.refresh_token}` })).status, 401);
    assert.equal((await tok({ grant_type: "refresh_token", refresh_token: t.access_token.slice(4) })).status, 400);
  } finally { child.kill("SIGKILL"); }
});

test("oauth: redirect URIs are restricted and never used for unregistered clients (no open redirect)", async () => {
  const token = crypto.randomBytes(32).toString("hex");
  const { base, child } = await start(token);
  try {
    assert.equal((await register(base, "https://evil.example/cb")).status, 400);
    assert.equal((await register(base, "https://claude.ai/other")).status, 400);
    assert.equal((await register(base, "http://localhost:6274/oauth/callback")).status, 201);
    const client = await (await register(base)).json();
    const { challenge } = pkce();
    const q = { response_type: "code", client_id: client.client_id, redirect_uri: "https://evil.example/cb", code_challenge: challenge, code_challenge_method: "S256" };
    const r = await fetch(`${base}/authorize?${form(q)}`, { redirect: "manual" }); assert.equal(r.status, 400);
    const forged = await fetch(`${base}/authorize?${form({ ...q, client_id: "forged.blob", redirect_uri: CB })}`, { redirect: "manual" }); assert.equal(forged.status, 400);
    // PKCE is mandatory: plain/no challenge is bounced back to the (valid) redirect URI with an error
    const nopkce = await fetch(`${base}/authorize?${form({ response_type: "code", client_id: client.client_id, redirect_uri: CB })}`, { redirect: "manual" });
    assert.equal(nopkce.status, 302); assert.equal(new URL(nopkce.headers.get("location")).searchParams.get("error"), "invalid_request");
  } finally { child.kill("SIGKILL"); }
});

// Regression: a real browser sends `Origin: null` on the consent form's POST when the page is served with
// `Referrer-Policy: no-referrer` (Fetch spec, "serializing a request origin"), and index.ts then answered 403
// "browser origins are not allowed". Node's fetch cannot emulate that, so pin the header that causes it.
test("oauth: consent page does not use a referrer policy that makes browsers send Origin: null", async () => {
  const token = crypto.randomBytes(32).toString("hex");
  const S = await start(token);
  try {
    const client = await (await register(S.base)).json(); const { challenge } = pkce();
    const q = { response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: challenge, code_challenge_method: "S256" };
    const r = await fetch(`${S.base}/authorize?${form(q)}`, { redirect: "manual" });
    assert.equal(r.status, 200);
    const rp = (r.headers.get("referrer-policy") ?? "").toLowerCase();
    assert.ok(rp === "same-origin" || rp === "strict-origin-when-cross-origin" || rp === "origin", `unsafe referrer-policy: ${rp}`);
    assert.notEqual(rp, "no-referrer");
    const nul = await fetch(`${S.base}/authorize`, { method: "POST", headers: { ...FORM, origin: "null" }, body: form({ ...q, access_token: token }), redirect: "manual" });
    assert.equal(nul.status, 403, "a literal Origin: null stays refused");
  } finally { S.child.kill("SIGKILL"); }
});

test("oauth: tokens from another server secret are rejected; consent POST allows only same-origin; failed attempts are throttled", async () => {
  const a = crypto.randomBytes(32).toString("hex"), b = crypto.randomBytes(32).toString("hex");
  const A = await start(a), B = await start(b);
  try {
    const client = await (await register(A.base)).json(); const { verifier, challenge } = pkce();
    const q = { response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: challenge, code_challenge_method: "S256" };
    const ok = await fetch(`${A.base}/authorize`, { method: "POST", headers: FORM, body: form({ ...q, access_token: a }), redirect: "manual" });
    const code = new URL(ok.headers.get("location")).searchParams.get("code");
    const t = await (await fetch(`${A.base}/token`, { method: "POST", headers: FORM, body: form({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: CB, code_verifier: verifier }) })).json();
    assert.equal((await mcp(B.base, { authorization: `Bearer ${t.access_token}` })).status, 401, "tokens do not transfer between server instances");

    const evil = await fetch(`${A.base}/authorize`, { method: "POST", headers: { ...FORM, origin: "https://evil.example" }, body: form({ ...q, access_token: a }), redirect: "manual" });
    assert.equal(evil.status, 403);
    const same = await fetch(`${A.base}/authorize`, { method: "POST", headers: { ...FORM, origin: A.base }, body: form({ ...q, access_token: a }), redirect: "manual" });
    assert.equal(same.status, 302);

    let last = 0; for (let i = 0; i < 12; i++) last = (await fetch(`${A.base}/authorize`, { method: "POST", headers: FORM, body: form({ ...q, access_token: "bad" + i }), redirect: "manual" })).status;
    assert.equal(last, 429);
    assert.equal((await fetch(`${A.base}/authorize`, { method: "POST", headers: FORM, body: form({ ...q, access_token: a }), redirect: "manual" })).status, 429, "even the right secret waits out the throttle");
  } finally { A.child.kill("SIGKILL"); B.child.kill("SIGKILL"); }
});

test("oauth: /mcp/<token> path fallback kaldırıldı — her zaman 404 döner", async () => {
  const token = crypto.randomBytes(32).toString("hex");
  const srv = await start(token);
  try {
    // Path fallback kaldırıldı: token doğru olsa bile 404
    assert.equal((await mcp(srv.base, {}, `/mcp/${token}`)).status, 404);
    assert.equal((await mcp(srv.base, {}, "/mcp/")).status, 404);
    assert.equal((await fetch(`${srv.base}/nothing`)).status, 404);
    // Bearer token hâlâ çalışmalı
    const bearer = await mcp(srv.base, { authorization: `Bearer ${token}` });
    assert.equal(bearer.status, 200);
  } finally { srv.child.kill("SIGKILL"); }
});


test("guest: one private invite suffices; accepted page gives the endpoint, no password or file, one use only", async () => {
  const token = crypto.randomBytes(32).toString("hex"), s = await start(token, {}, true);
  try {
    assert.ok(s.invite?.startsWith(s.base + '/invite/'));
    const visit = await fetch(s.invite); assert.equal(visit.status, 200);
    const html = await visit.text(); assert.match(html, /Davet kabul edildi/); assert.ok(html.includes(s.base + '/mcp') && !html.includes(token));
    const cookie = visit.headers.get('set-cookie').split(';')[0];
    const client = await (await register(s.base)).json(); const { challenge } = pkce();
    const q = { response_type: 'code', client_id: client.client_id, redirect_uri: CB, code_challenge: challenge, code_challenge_method: 'S256' };
    const consent = () => fetch(`${s.base}/authorize?${form(q)}`, { headers: { cookie }, redirect: 'manual' });
    assert.equal((await consent()).status, 302); assert.equal((await consent()).status, 200);
    assert.equal((await fetch(s.invite)).status, 410);
  } finally { s.child.kill('SIGKILL'); }
});

test('workspace/http: separate consent grants, stable refresh, private share link, download and revocation', async () => {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');
  const worker = process.env.HT_REQUIRE_WORKER_TEST === '1' || (process.platform === 'linux' && fs.existsSync('/usr/bin/bwrap'));
  const secret = crypto.randomBytes(32).toString('hex'), s = await start(secret, { HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: '1' }, false, { shell:{enabled:worker} });
  const sessions = [];
  try {
    const { client_id } = await (await register(s.base)).json();
    const exchange = async o => { const r = await fetch(s.base + '/token', { method:'POST', headers:FORM, body:form(o) }); assert.equal(r.status,200); return r.json(); };
    const grant = async () => {
      const {verifier, challenge} = pkce();
      const r = await fetch(s.base + '/authorize', {method:'POST',headers:FORM,redirect:'manual',body:form({client_id, access_token:secret, response_type:'code',redirect_uri:CB,code_challenge_method:'S256',code_challenge:challenge})});
      assert.equal(r.status,302);
      return exchange({client_id, grant_type:'authorization_code',redirect_uri:CB, code:new URL(r.headers.get('location')).searchParams.get('code'), code_verifier:verifier});
    };
    const as = async token => {
      const c = new Client({name:'grant-test',version:'1'});
      await c.connect(new StreamableHTTPClientTransport(new URL(s.base + '/mcp'), {requestInit:{headers:{authorization:`Bearer ${token}`}}}));
      sessions.push(c); return { client:c, call:(name, args = {})=>c.callTool({name,arguments:args}) };
    };
    const one = await grant(), two = await grant(); assert.notEqual(one.access_token,two.access_token);
    const a = await as(one.access_token), b = await as(two.access_token), master = await as(secret);
    const text = r => { assert.ok(!r.isError, r.content[0].text); return r.content[0].text; };
    if (worker) {
      text(await a.call('ht_add_var',{name:'TEAM',value:'sarı'}));
      for(const c of [b,master]) assert.deepEqual(JSON.parse(text(await c.call('ht_list_vars'))).names,[]);
    }
    const rf = await as((await exchange({client_id, grant_type:'refresh_token', refresh_token:one.refresh_token})).access_token);
    if (worker) assert.deepEqual(JSON.parse(text(await rf.call('ht_list_vars'))).names,['HT_VAR_TEAM']);
    text(await a.call('ht_write',{path:'report.txt',content:'merhaba'}));
    const msg = text(await a.call('ht_share',{source_path:'report.txt',ttl_minutes:2,name:'Çıktı.txt'}));
    const meta = JSON.parse(msg.split('\n').at(-1)); assert.equal(new URL(meta.url).origin,s.base); assert.ok(!msg.includes(secret));
    assert.deepEqual(JSON.parse(text(await b.call('ht_share',{action:'list'}))).files,[]);
    assert.ok((await b.call('ht_share',{action:'revoke',id:meta.id})).isError);
    const uri = `hardtools-share://local/_tmp/hardtools-share/${meta.id}`;
    await assert.rejects(b.client.readResource({uri}));
    assert.equal(Buffer.from((await rf.client.readResource({uri})).contents[0].blob, 'base64').toString(),'merhaba');
    const head=await fetch(meta.url,{method:'HEAD'}); assert.equal(head.status,200);assert.equal(await head.text(),'');
    const get=await fetch(meta.url);assert.equal(get.status,200); assert.equal(await get.text(),'merhaba');
    assert.match(get.headers.get('content-disposition'),/^attachment; filename\*=UTF-8''%/); assert.match(get.headers.get('cache-control'),/no-store/); assert.equal(get.headers.get('x-content-type-options'),'nosniff');
    assert.equal((await fetch(meta.url,{method:'POST'})).status,405);
    assert.equal((await fetch(s.base+'/_tmp/hardtools-share/report.txt')).status,404);
    assert.equal((await fetch(meta.url,{headers:{origin:'https://foreign.example'}})).status,403);
    text(await rf.call('ht_share',{action:'revoke',id:meta.id})); assert.equal((await fetch(meta.url)).status,404);
    // All clients use one public client_id and one workspace. Audit scope is the grant, not either of those.
    for (const [c, name] of [[a,'audit-marker-one'],[b,'audit-marker-two'],[master,'audit-marker-static']]) text(await c.call('ht_mkdir',{path:name}));
    const exportFor = async c => {
      const r=await c.call('ht_status',{audit_export:true}), m=JSON.parse(text(r));
      assert.equal(m.scope,'authorization'); assert.equal(m.next_offset,null);
      return {m, bytes:Buffer.from(r.content[1].resource.blob,'base64').toString()};
    };
    const own=await exportFor(rf); assert.match(own.bytes,/audit-marker-one/); assert.doesNotMatch(own.bytes,/audit-marker-two|audit-marker-static|invite_redeemed|sarı/);
    for(const [c,marker] of [[b,'audit-marker-two'],[master,'audit-marker-static']]) {
      const other=await exportFor(c); assert.ok(other.bytes.includes(marker)); assert.ok(!other.bytes.includes('audit-marker-one'));
      const wrong=await c.call('ht_status',{audit_export:true,audit_snapshot:own.m.snapshot,audit_offset:0});
      assert.equal(wrong.isError,true); assert.match(wrong.content[0].text,/audit_snapshot/);
    }
    const again=await a.call('ht_status',{audit_export:true,audit_snapshot:own.m.snapshot,audit_offset:0});
    assert.equal(JSON.parse(text(again)).expected_head,own.m.expected_head); assert.equal(Buffer.from(again.content[1].resource.blob,'base64').toString(),own.bytes);
  } finally { await Promise.allSettled(sessions.map(c=>c.close())); s.child.kill('SIGKILL'); }
});
