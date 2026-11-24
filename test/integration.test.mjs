// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
function envFor(root, audit, extra = {}) {
  const cfg = path.join(audit, "config.json"); fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: path.join(audit, "log") } }));
  const base = { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, ...extra };
  delete base.HARDTOOLS_PROFILE; return { ...base, ...extra };
}
const text = (r) => r.content.map(c => c.text).join("\n");

test("e2e/stdio: 24 tools, write→read→edit round trip, denials surface as tool errors, audit chain is intact", async () => {
  const root = tmp("ht-e2e-"); const audit = tmp("ht-e2e-audit-");
  const client = new Client({ name: "t", version: "0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry, "--profile", "balanced"], env: envFor(root, audit), stderr: "ignore" }));
  try {
    const tools = (await client.listTools()).tools.map(t => t.name).sort();
    assert.deepEqual(tools, ["ht_add_var", "ht_ask", "ht_delete_var", "ht_edit", "ht_empty_trash", "ht_fetch", "ht_glob", "ht_image_search", "ht_list_all_tools", "ht_list_vars", "ht_manage_tool", "ht_mkdir", "ht_move", "ht_new_shell_env", "ht_read", "ht_search", "ht_share", "ht_shell", "ht_status", "ht_stop", "ht_transfer_file", "ht_trash", "ht_user_input", "ht_write"]);
    for (const t of (await client.listTools()).tools) assert.ok(t.annotations, `${t.name} has annotations`);
    const w = await client.callTool({ name: "ht_write", arguments: { path: "hello.txt", content: "hi there\n" } }); assert.ok(!w.isError, text(w));
    const e = await client.callTool({ name: "ht_edit", arguments: { edits: [{ path: "hello.txt", old_str: "hi", new_str: "hello" }] } }); assert.ok(!e.isError, text(e));
    assert.match(text(await client.callTool({ name: "ht_read", arguments: { path: "hello.txt" } })), /hello there/);
    assert.match(text(await client.callTool({ name: "ht_search", arguments: { pattern: "there" } })), /hello\.txt:1:/);
    const bad = await client.callTool({ name: "ht_read", arguments: { path: "/etc/passwd" } }); assert.ok(bad.isError); assert.match(text(bad), /DENIED \[outside_roots\]/);
    const sh = await client.callTool({ name: "ht_shell", arguments: { argv: ["rm", "-rf", "hello.txt"] } }); assert.ok(!sh.isError, text(sh));
    assert.ok(!fs.existsSync(path.join(root, "hello.txt")));
    const st = JSON.parse(text(await client.callTool({ name: "ht_status", arguments: {} })));
    assert.equal(st.profile, "balanced"); assert.equal(st.audit.chain.ok, true); assert.ok(st.audit.chain.entries >= 10);
  } finally { await client.close(); }
  const logs = fs.readdirSync(path.join(audit, "log")); assert.equal(logs.length, 1);
  const v = spawnSync(process.execPath, [entry, "--verify", path.join(audit, "log", logs[0])]);
  assert.equal(v.status, 0, String(v.stdout));
});

test("e2e/stdio: strict profile fails closed when the root is the filesystem root", async () => {
  const audit = tmp("ht-e2e-audit-");
  const r = spawnSync(process.execPath, [entry, "--profile", "strict"], { env: envFor("/", audit), encoding: "utf8", timeout: 10000 });
  assert.equal(r.status, 1); assert.match(r.stderr, /filesystem root/);
});

async function startHttp(root, audit, extra = {}) {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], { env: envFor(root, audit, extra), stdio: ["ignore", "ignore", "pipe"] });
  let err = ""; child.stderr.on("data", d => err += d);
  for (let i = 0; i < 50; i++) { if (/listening/.test(err)) break; if (child.exitCode !== null) break; await new Promise(r => setTimeout(r, 100)); }
  return { port, child, err: () => err };
}
const rawPost = (port, body, headers) => new Promise((resolve, reject) => {
  const data = JSON.stringify(body);
  const req = http.request({ host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "content-length": Buffer.byteLength(data), ...headers } },
    (res) => { let s = ""; res.on("data", d => s += d); res.on("end", () => resolve({ status: res.statusCode, body: s })); });
  req.on("error", reject); req.end(data);
});
const rpc = (port, body, headers = {}) => fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(body) });

test("e2e/http: refuses to start without a strong token", async () => {
  const root = tmp("ht-h-"); const audit = tmp("ht-h-audit-");
  const r = spawnSync(process.execPath, [entry, "--http", "--port", "29999"], { env: envFor(root, audit), encoding: "utf8", timeout: 10000 });
  assert.equal(r.status, 1); assert.match(r.stderr, /HARDTOOLS_HTTP_TOKEN/);
  const r2 = spawnSync(process.execPath, [entry, "--http", "--port", "29998"], { env: envFor(root, audit, { HARDTOOLS_HTTP_TOKEN: "short" }), encoding: "utf8", timeout: 10000 });
  assert.equal(r2.status, 1);
});

test("e2e/http: auth, host check, origin check; shell+write are OFF by default in remote mode", async () => {
  const root = tmp("ht-h-"); const audit = tmp("ht-h-audit-"); const token = "t".repeat(48);
  const { port, child } = await startHttp(root, audit, { HARDTOOLS_HTTP_TOKEN: token });
  try {
    const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };
    assert.equal((await rpc(port, init)).status, 401);
    assert.equal((await rpc(port, init, { authorization: "Bearer wrong" + token })).status, 401);
    assert.equal((await rawPost(port, init, { authorization: `Bearer ${token}`, host: "evil.example" })).status, 403);
    assert.equal((await rawPost(port, init, { authorization: `Bearer ${token}`, origin: "https://evil.example" })).status, 403);
    const ok = await rpc(port, init, { authorization: `Bearer ${token}` }); assert.equal(ok.status, 200); assert.match(await ok.text(), /hardtools/);
    const call = await rpc(port, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "ht_shell", arguments: { argv: ["ls"] } } }, { authorization: `Bearer ${token}` });
    assert.match(await call.text(), /shell_disabled/);
    const w = await rpc(port, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "ht_write", arguments: { path: "x.txt", content: "x" } } }, { authorization: `Bearer ${token}` });
    assert.match(await w.text(), /write_disabled/); assert.ok(!fs.existsSync(path.join(root, "x.txt")));
    const get = await fetch(`http://127.0.0.1:${port}/mcp`, { headers: { authorization: `Bearer ${token}` } }); assert.equal(get.status, 405);
  } finally { child.kill("SIGKILL"); }
});

test('e2e/http: fixed /mcp Web transport preserves SSE, header negotiation, limits and empty acknowledgements', async () => {
  const root = tmp('ht-web-'), audit = tmp('ht-web-audit-'), token = 'x'.repeat(64);
  const { port, child } = await startHttp(root, audit, { HARDTOOLS_HTTP_TOKEN:token });
  const headers = { authorization:`Bearer ${token}` };
  const list = { jsonrpc:'2.0', id:23, method:'tools/list', params:{} };
  try {
    const stream = await rpc(port, list, headers); assert.equal(stream.status,200);
    assert.match(stream.headers.get('content-type'), /text\/event-stream/);
    const body = await stream.text(); assert.match(body, /event: message/); assert.match(body, /ht_status/);
    assert.equal((await rpc(port,list,{...headers,accept:'application/json'})).status,406);
    assert.equal((await rpc(port,list,{...headers,'content-type':'text/plain'})).status,415);
    assert.equal((await rpc(port,list,{...headers,'mcp-protocol-version':'unsupported'})).status,400);
    const notify = await rpc(port, {jsonrpc:'2.0',method:'notifications/initialized'}, headers);
    assert.equal(notify.status,202); assert.equal(await notify.text(),'');
    assert.equal((await rpc(port,{...list,params:{padding:'x'.repeat(1_000_000)}},headers)).status,413);
  } finally { child.kill('SIGKILL'); fs.rmSync(root,{recursive:true,force:true}); fs.rmSync(audit,{recursive:true,force:true}); }
});

test('e2e/http opt-in: command and argv both run in /work without the host environment or a sibling mount', {
  skip: process.env.HT_REQUIRE_WORKER_TEST !== '1' && (process.platform !== 'linux' || !fs.existsSync('/usr/bin/bwrap')) && 'Linux bubblewrap not installed',
}, async t => {
  const root = tmp('ht-isolated-'), admin = tmp('ht-management-fixture-'), token = 't'.repeat(48);
  // Only benign test fixtures; do not read runner credentials to prove they are absent.
  const marker = path.join(admin,'outside.txt'); fs.writeFileSync(marker,'host fixture');
  const { port, child, err } = await startHttp(root, admin, { HARDTOOLS_HTTP_TOKEN:token, HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS:'1', HT_HOST_FIXTURE:'host-only' });
  t.after(() => { child.kill('SIGKILL'); fs.rmSync(root,{recursive:true,force:true}); fs.rmSync(admin,{recursive:true,force:true}); });
  assert.match(err(), /HTTP listening/, err());
  const c = new Client({name:'dedicated-workspace-test',version:'1'});
  await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {requestInit:{headers:{authorization:`Bearer ${token}`}}}));
  t.after(() => c.close());
  const call = async (name,args={}) => { const r=await c.callTool({ name,arguments:args }); assert.ok(!r.isError,text(r)); return r.content[0].text; };
  const sh = async args => JSON.parse(await call('ht_shell',{...args, expected_exit_codes:[0],output_format:'json'})).stdout;
  const st=JSON.parse(await call('ht_status')); assert.equal(st.shell.execution,'workspace'); assert.equal(st.shell.shellSyntax,true);
  assert.equal(st.shell.network,'isolated');
  await sh({command:'test -z "${HTTPS_PROXY:-}" && test ! -S /runtime/https.sock'});
  await call('ht_write',{path:'sub/input',content:'iki satır\n',mkdirp:true});
  await call('ht_add_var',{name:'APP_TEST',value:'ekip'});
  const stdout=await sh({cwd:'/work/sub',stdin_file:'input',inherit_vars:['APP_TEST'],command:`test ! -e '${marker}' && cat | tr a-z A-Z > out && pwd && printf '%s' "$APP_TEST"`});
  assert.equal(stdout,'/work/sub\nekip'); assert.equal(fs.readFileSync(path.join(root,'sub','out'),'utf8'),'IKI SATıR\n');
  const probe = `
    const fs = require('node:fs');
    const runtime = fs.statSync('/runtime/node', {bigint:true});
    const inherited = fs.readdirSync('/proc/self/fd').some(n => {
      try { const s = fs.fstatSync(Number(n), {bigint:true}); return s.dev === runtime.dev && s.ino === runtime.ino; }
      catch (e) { if (e.code === 'EBADF') return false; throw e; }
    });
    console.log(JSON.stringify({cwd:process.cwd(), outside:fs.existsSync(${JSON.stringify(marker)}),
      hostenv:process.env.HT_HOST_FIXTURE ?? null, selected:process.env.APP_TEST ?? null,
      exec:process.execPath, runtime:[String(runtime.dev),String(runtime.ino)], inherited,
      pid:fs.readlinkSync('/proc/self/ns/pid'), net:fs.readlinkSync('/proc/self/ns/net')}));`;
  await call('ht_write',{path:'sub/probe.cjs',content:probe});
  const r=JSON.parse(await sh({cwd:'sub',argv:['node','/work/sub/probe.cjs']}));
  assert.equal(r.cwd,'/work/sub'); assert.equal(r.outside,false); assert.equal(r.hostenv,null); assert.equal(r.selected,null);
  const serverNode = fs.statSync('/proc/self/exe', {bigint:true}); // same binary as the HTTP subprocess
  assert.equal(r.exec,'/runtime/node'); assert.deepEqual(r.runtime,[String(serverNode.dev),String(serverNode.ino)]);
  assert.equal(r.inherited,false,'the guest did not inherit the launcher mount descriptor');
  for(const ns of ['pid','net']) assert.notEqual(r[ns],fs.readlinkSync(`/proc/self/ns/${ns}`));
  assert.match(await call('ht_read',{path:'sub/out'}), /IKI SATıR/);
  assert.equal(fs.readFileSync(marker,'utf8'),'host fixture');
});

test('e2e/http opt-in: unsuitable dedicated roots fail startup instead of falling back to the host shell', () => {
  const root=tmp('ht-invalid-worker-'), token='x'.repeat(48);
  try {
    const r=spawnSync(process.execPath,[entry,'--http','--port','0'],{encoding:'utf8',timeout:6000,env:envFor(root, root,{HARDTOOLS_HTTP_TOKEN:token,HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS:'1'})});
    assert.equal(r.status,1); assert.doesNotMatch(r.stderr,/HTTP listening/); assert.match(r.stderr,/dedicated workspace|requires Linux/);
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('e2e/http: workspace HTTPS is explicit, proxy-only, and does not expose the host network namespace', {
  skip:process.env.HT_REQUIRE_WORKER_TEST!=='1' && (process.platform!=='linux'||!fs.existsSync('/usr/bin/bwrap')) && 'Linux bubblewrap not installed',
},async t=>{
  const root=tmp('ht-whttps-'),admin=tmp('ht-whttps-admin-'),token='w'.repeat(48);
  t.after(()=>{fs.rmSync(root,{recursive:true,force:true});fs.rmSync(admin,{recursive:true,force:true});});
  const noShell=spawnSync(process.execPath,[entry,'--http','--port','0'],{encoding:'utf8',timeout:6000,env:envFor(root,admin,{HARDTOOLS_HTTP_TOKEN:token,HARDTOOLS_WORKSPACE_HTTPS:'1',HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS:'0'})});
  assert.equal(noShell.status,1);assert.doesNotMatch(noShell.stderr,/HTTP listening/);
  const {port,child,err}=await startHttp(root,admin,{HARDTOOLS_HTTP_TOKEN:token,HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS:'1',HARDTOOLS_WORKSPACE_HTTPS:'1',HT_PRIVATE_FIXTURE:'never pass to the guest'});
  t.after(()=>child.kill('SIGKILL'));assert.match(err(),/HTTP listening/,err());
  const c=new Client({name:'HTTPS-test',version:'1'});
  await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`),{requestInit:{headers:{authorization:`Bearer ${token}`}}}));t.after(()=>c.close());
  const call=async(name,args={})=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,text(r));return r.content[0].text;};
  const st=JSON.parse(await call('ht_status'));assert.equal(st.shell.execution,'workspace');assert.equal(st.shell.network,'public-https-proxy');
  const sh=async args=>JSON.parse(await call('ht_shell',{...args,output_format:'json'}));
  const check=await sh({command:'test -z "${HT_PRIVATE_FIXTURE:-}" && test -S /runtime/https.sock && test -r /etc/ssl/certs/ca-certificates.crt && readlink /proc/self/ns/net && cat',stdin:'guest stdin'});
  assert.equal(check.exit_code,0,check.stderr);const [ns,line]=check.stdout.split('\n');assert.match(ns,/^net:\[/);assert.notEqual(ns,fs.readlinkSync('/proc/self/ns/net'));assert.equal(line,'guest stdin');
  const denied=await sh({argv:['curl','--silent','--show-error','--max-time','4','https://127.0.0.1/']});assert.notEqual(denied.exit_code,0);assert.match(denied.stderr,/403/);
  const plain=await sh({argv:['curl','--silent','--fail','--show-error','--max-time','4','http://example.invalid/']});assert.notEqual(plain.exit_code,0);assert.match(plain.stderr,/405/);
});
