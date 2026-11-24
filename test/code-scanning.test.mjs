import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { equalSecret } from '../dist/credentials.js';
import { SHARE_CWD, shareIdFromUri } from '../dist/share.js';
import { loadPolicy } from '../dist/config.js';
import { runShell } from '../dist/shell.js';
import { probeWorkspaceShell } from '../dist/workspace-shell.js';

// The consent form, static bearer and signed MAC comparisons use the same exact-byte check.
test('opaque credentials compare the complete UTF-8 bytes, including length, not a fast password hash', () => {
  for (const s of ['ASCII', 'çok baytlı', 'pad\0', '']) assert.equal(equalSecret(s, s), true);
  for (const [a,b] of [['same-length', 'same-lengti'], ['key', 'key\0'], ['key-more','key'], ['é','e\u0301'], ['', 'x']]) {
    assert.equal(equalSecret(a,b), false);
    assert.equal(equalSecret(b,a), false);
  }
});

test('resource routes accept only the literal share prefix and one complete opaque ID', () => {
  const prefix = 'hardtools-share://local' + SHARE_CWD, id = 'aZ-_012345'.repeat(4) + 'abc';
  assert.equal(shareIdFromUri(prefix + id), id);
  for (const uri of [prefix, prefix + id.slice(1), prefix + id + 'a', prefix + id + '?view', prefix + id + '#x', prefix + id + '/', prefix + 'a'.repeat(41) + '**', prefix + 'a'.repeat(42) + '\n', prefix.replace('://local/', '://other/') + id])
    assert.equal(shareIdFromUri(uri), null);
});

test('MCP schema validation and tool calls work with V8 string code generation forbidden', async () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ht-interpreted-')));
  const root = path.join(dir, 'root'), settings = path.join(dir,'settings');
  fs.mkdirSync(root); fs.mkdirSync(settings);
  const cfg = path.join(settings,'config.json'); fs.writeFileSync(cfg, JSON.stringify({ audit: { dir:path.join(dir,'log') } }));
  const client = new Client({name:'interpreter-test',version:'1'});
  try {
    await client.connect(new StdioClientTransport({ command:process.execPath, args:['--disallow-code-generation-from-strings', path.resolve(process.env.HT_ENTRY ?? 'dist/index.js')], env:{PATH:process.env.PATH, HARDTOOLS_CONFIG:cfg, HARDTOOLS_ROOTS:root}, stderr:'ignore' }));
    const {tools} = await client.listTools(); const shell = tools.find(t=>t.name==='ht_shell'), ed = tools.find(t=>t.name==='ht_edit');
    assert.equal(shell.inputSchema.properties.command.type, 'string'); assert.equal(ed.inputSchema.properties.edits.type, 'array');
    const bad = await client.callTool({ name:'ht_shell', arguments:{ command:7 } });
    assert.equal(bad.isError,true); assert.equal(fs.existsSync(path.join(root,'file.txt')),false);
    const good = await client.callTool({ name:'ht_shell', arguments:{ argv:['sh','-c','printf %s ok > file.txt'] } });
    assert.ok(!good.isError, good.content[0]?.text); assert.equal(fs.readFileSync(path.join(root,'file.txt'),'utf8'),'ok');
  } finally { await client.close(); fs.rmSync(dir, {recursive:true,force:true}); }
});

// A display/install pathname (even a canonical one) is not the identity of an executable.
// These fixtures exercise the real Linux mount; CI requires the worker test, not a stub.
const workerTest = { skip: process.env.HT_REQUIRE_WORKER_TEST !== '1' && (process.platform !== 'linux' || !fs.existsSync('/usr/bin/bwrap')) && 'Linux bubblewrap not installed' };
function workerFixture(t) {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ht-runtime-fd-')));
  t.after(() => fs.rmSync(base, {recursive:true, force:true}));
  const root = path.join(base, 'project'); fs.mkdirSync(root);
  const p = loadPolicy({ profile:'balanced', roots:[root], override:{audit:{dir:path.join(base,'audit')}} });
  return {root, policy:{...p, shellWorker:'workspace'}};
}
function openRuntimeDescriptors() {
  const runtime = fs.statSync('/proc/self/exe', {bigint:true});
  return fs.readdirSync('/proc/self/fd').filter(n => {
    try { const s=fs.fstatSync(Number(n), {bigint:true}); return s.ino===runtime.ino && s.dev===runtime.dev; }
    catch (e) { if (e.code==='EBADF') return false; throw e; }
  }).length;
}

test('workspace runtime: probe and spawn pin the running Node even without a usable execPath; no parent fd leaks', workerTest, async t => {
  const {root,policy} = workerFixture(t), original=process.execPath, count=openRuntimeDescriptors();
  try {
    // Ordinary, nonexistent fixture. No file at this path should be looked up or mounted.
    process.execPath = path.join(root, 'no-such-node');
    probeWorkspaceShell(policy);
    assert.equal(openRuntimeDescriptors(), count);
    const result=await runShell(policy, {argv:['node','--version'], expected_exit_codes:[0], output_format:'json'});
    assert.equal(result.isError,false,result.text); assert.equal(JSON.parse(result.text).stdout.trim(),process.version);
    assert.equal(openRuntimeDescriptors(), count);
  } finally { process.execPath=original; }
});

test('workspace runtime: unavailable procfs descriptor rejects both probe and command without running on host', workerTest, async t => {
  const {root,policy}=workerFixture(t), orig=fs.openSync;
  t.mock.method(fs,'openSync',function(file,...args) {
    if(file==='/proc/self/exe') throw new Error('unavailable in fixture');
    return orig.call(this,file,...args);
  });
  assert.throws(()=>probeWorkspaceShell(policy),{code:'worker_unavailable'});
  await assert.rejects(runShell(policy,{command:'printf ran > marker.txt'}),{code:'worker_unavailable'});
  assert.ok(!fs.existsSync(path.join(root,'marker.txt')));
});
