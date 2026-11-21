import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { loadPolicy } from '../dist/config.js';
import { Shares, SHARE_CWD } from '../dist/share.js';
import { htEmptyTrash, htTrash } from '../dist/fs-extra.js';
import { Variables } from '../dist/variables.js';

function fixture(t) {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ht-tools-')));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const root = path.join(base, 'project'), audit = path.join(base, 'audit'); fs.mkdirSync(root);
  const policy = loadPolicy({ roots: [root], override: { profile: 'balanced', audit: { dir: audit } } });
  return { base, root, audit, policy };
}
async function session(t) {
  const f = fixture(t), cfg = path.join(f.base, 'settings', 'config.json');
  fs.mkdirSync(path.dirname(cfg)); fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: f.audit } }));
  const client = new Client({ name: 'workspace-tests', version: '1' });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [path.resolve(process.env.HT_ENTRY ?? 'dist/index.js'), '--profile', 'balanced'], env: { PATH: process.env.PATH, HARDTOOLS_ROOTS: f.root, HARDTOOLS_CONFIG: cfg }, stderr: 'ignore' }));
  t.after(() => client.close());
  return { ...f, client, call: (name, args = {}) => client.callTool({ name, arguments: args }) };
}
const text = r => r.content[0].text;
const ok = r => { assert.ok(!r.isError, text(r)); return text(r); };
const denied = (r, pattern) => { assert.equal(r.isError, true); assert.match(text(r), pattern); };

test('MCP shell: confined stdin_file, independent streams, byte budget, JSON and exit expectations', async t => {
  const { root, call } = await session(t);
  fs.mkdirSync(path.join(root, 'work')); fs.writeFileSync(path.join(root, 'work', 'input'), 'merhaba\n');
  fs.writeFileSync(path.join(root, '.env'), 'no'); fs.writeFileSync(path.join(root, 'large'), Buffer.alloc(65537));
  const sh = (a) => call('ht_shell', a);
  const base = { cwd: 'work', argv: ['node', '-e', 'process.stdin.pipe(process.stdout);process.stderr.write("notice");process.exitCode=7'], stdin_file: 'input', output_format: 'json' };
  const r = JSON.parse(ok(await sh({ ...base, capture: 'stdout', expected_exit_codes: [0, 7] })));
  assert.equal(r.ok, true); assert.equal(r.exit_code, 7); assert.equal(r.stdout, 'merhaba\n'); assert.equal(r.stderr, undefined); assert.equal(r.cwd, 'work');
  const e = await sh({ ...base, capture: 'stderr', expected_exit_codes: [0] }); assert.equal(e.isError, true);
  const d = JSON.parse(text(e)); assert.equal(d.ok, false); assert.equal(d.stderr, 'notice'); assert.equal(d.stdout, undefined);
  const b = JSON.parse(ok(await sh({ argv: ['node', '-e', 'process.stdout.write("X".repeat(12000));process.stderr.write("Y".repeat(5000))'], max_output_bytes: 1000, output_format: 'json' })));
  assert.equal(b.omitted_bytes.stdout + b.omitted_bytes.stderr, 16000); assert.match(b.stdout, /omitted/);
  const capped = JSON.parse(ok(await sh({ argv: ['node', '-e', 'process.stdout.write("X".repeat(200000))'], output_format: 'json', capture: 'stdout', max_output_bytes: 2**20 })));
  assert.equal(capped.omitted_bytes.stdout, 200000 - (128 << 10));
  denied(await sh({ ...base, stdin: '' }), /mutually exclusive/);
  denied(await sh({ ...base, stdin_file: '../.env' }), /denied_path/);
  denied(await sh({ ...base, stdin_file: '../../nope' }), /outside_roots/);
  denied(await sh({ ...base, stdin_file: '../large' }), /too_large/);
  const timeout = await sh({ argv: ['node', '-e', 'setTimeout(()=>{},5000)'], timeout_ms: 120, expected_exit_codes: [0], output_format: 'json' });
  assert.equal(timeout.isError, true); assert.equal(JSON.parse(text(timeout)).timed_out, true);
});

test('MCP variables: selectable, literal, delete/overwrite; values absent from list, response and audit', async t => {
  const { call, audit } = await session(t); const v = 'a private ordinary value; $(not expanded)';
  const add = await call('ht_add_var', { name: 'renk', value: v }); assert.match(ok(add), /HT_VAR_RENK/); assert.ok(!text(add).includes(v));
  ok(await call('ht_add_var', { name: 'APP_TEAM', value: 'ekip' }));
  const listed = JSON.parse(ok(await call('ht_list_vars'))); assert.deepEqual(listed.names, ['APP_TEAM', 'HT_VAR_RENK']);
  denied(await call('ht_add_var', { name: 'HT_VAR_RENK', value: 'other' }), /var_exists/);
  const env = async names => JSON.parse(ok(await call('ht_shell', { argv: ['node', '-e', 'console.log(JSON.stringify([process.env.HT_VAR_RENK,process.env.APP_TEAM]))'], inherit_vars: names, output_format: 'json' }))).stdout.trim();
  assert.deepEqual(JSON.parse(await env([])), [null, null]); assert.deepEqual(JSON.parse(await env(['renk'])), [v, null]);
  ok(await call('ht_add_var', { name: 'renk', value: 'new', overwrite: true })); assert.deepEqual(JSON.parse(await env(['HT_VAR_RENK','APP_TEAM'])), ['new','ekip']);
  ok(await call('ht_delete_var', { name: 'renk' })); assert.deepEqual(JSON.parse(ok(await call('ht_list_vars'))).names, ['APP_TEAM']);
  denied(await call('ht_shell', { argv: ['pwd'], inherit_vars: ['renk'] }), /var_missing/);
  assert.ok(!fs.readFileSync(path.join(audit, fs.readdirSync(audit)[0]), 'utf8').includes(v));
});

test('variables: OS/runtime names are never overridden, quotas and owner separation', t => {
  const { policy: p } = fixture(t), s = new Variables(); const orig = process.env.PATH;
  assert.match(s.add(p, 'a', {name:'PATH',value:'only-data'}), /HT_VAR_PATH/); assert.deepEqual(Object.keys(s.select(p,'a',['PATH'])), ['HT_VAR_PATH']); assert.equal(process.env.PATH,orig);
  assert.equal(s.list(p,'b'), '{"names":[]}'); assert.throws(() => s.select(p,'b',['PATH']), /no such session/);
  for (const name of ['bad-name','__proto__','']) assert.throws(() => s.add(p,'a',{name,value:'x'}), /name/);
  assert.throws(() => s.add(p,'a',{name:'x',value:'ü'.repeat(2049)}), /4096/);
  assert.throws(() => s.add(p,'a',{name:'x',value:'x\0y'}), /NUL/);
  for(let i=0;i<31;i++) s.add(p,'a',{name:`k${i}`,value:''}); assert.throws(() => s.add(p,'a',{name:'excess',value:''}), /maximum 32/);
  assert.throws(() => s.add({...p,shell:{...p.shell,enabled:false}}, 'a', {name:'x',value:'x'}), /enabled shell/);
});

test('trash: preview before purge, one root only; retain root and never follow directory or entry links', t => {
  const { base, root, policy: p } = fixture(t), other = path.join(base,'other'); fs.mkdirSync(other); p.roots.push(other);
  fs.writeFileSync(path.join(other,'keep'),'keep'); fs.writeFileSync(path.join(root,'item'),'ok'); htTrash(p,{path:'item'});
  const bin = path.join(root,'.ht-trash'); fs.symlinkSync(other,path.join(bin,'linked')); fs.mkdirSync(path.join(bin,'nested')); fs.symlinkSync(other,path.join(bin,'nested','link'));
  assert.match(htEmptyTrash(p,{}), /PREVIEW: 3/); assert.equal(fs.readdirSync(bin).length,4);
  assert.throws(() => htEmptyTrash(p,{root: bin,confirm:true}), /configured root/);
  assert.throws(() => htEmptyTrash({...p,fs:{...p.fs,writeEnabled:false}},{confirm:true}), /disabled/);
  assert.throws(() => htEmptyTrash({...p,protectedDirs:[path.join(bin,'nested')]},{confirm:true}), /protected/);
  assert.throws(() => htEmptyTrash({...p,fs:{...p.fs,denyWrite:['.ht-trash/nested/*']}},{confirm:true}), /protected/); assert.equal(fs.readdirSync(bin).length,4);
  assert.match(htEmptyTrash(p,{confirm:true}), /EMPTIED: 3/); assert.deepEqual(fs.readdirSync(bin),[]); assert.equal(fs.readFileSync(path.join(other,'keep'),'utf8'),'keep');
  assert.match(htEmptyTrash(p,{confirm:true}), /EMPTIED: 0/); assert.match(htEmptyTrash(p,{root:other,confirm:true}), /nothing deleted/);
  fs.rmdirSync(bin); fs.symlinkSync(other,bin); assert.throws(() => htEmptyTrash(p,{confirm:true}), /link|protected/); assert.ok(fs.existsSync(path.join(other,'keep')));
});

test('trash: a linked manifest does not receive writes or swallow a source', t => {
  const { root, base, policy } = fixture(t), bin = path.join(root,'.ht-trash'), sentinel = path.join(base,'keep'), index = path.join(bin,'index.jsonl');
  fs.mkdirSync(bin); fs.writeFileSync(sentinel,'untouched'); fs.writeFileSync(path.join(root,'item'),'keep');
  for(const link of [fs.symlinkSync, fs.linkSync]) { link(sentinel,index); assert.throws(() => htTrash(policy,{path:'item'})); assert.equal(fs.readFileSync(sentinel,'utf8'),'untouched'); assert.ok(fs.existsSync(path.join(root,'item'))); fs.unlinkSync(index); }
});

test('MCP share: virtual cwd, embedded binary, authenticated resources/read, immutable snapshot, revoke', async t => {
  const { call, client, root } = await session(t); const b = Buffer.from([0,1,250,13,10]);
  const dir = path.join(root,SHARE_CWD.slice(1)); fs.mkdirSync(dir,{recursive:true}); fs.writeFileSync(path.join(dir,'rapor.bin'),b);
  const r = await call('ht_share',{path:SHARE_CWD+'rapor.bin',name:'Çıktı.bin'}), m = JSON.parse(ok(r));
  assert.equal(m.cwd, SHARE_CWD); assert.equal(m.name,'Çıktı.bin'); assert.equal(m.size,b.length); assert.equal(r.content[1].type,'resource');
  const res = r.content[1].resource; assert.deepEqual(Buffer.from(res.blob,'base64'),b); fs.writeFileSync(path.join(dir,'rapor.bin'),'modified');
  assert.deepEqual(Buffer.from((await client.readResource({uri:res.uri})).contents[0].blob,'base64'),b);
  assert.deepEqual(JSON.parse(ok(await call('ht_share',{action:'list'}))).files.map(f=>f.id),[m.id]);
  ok(await call('ht_share',{action:'revoke',id:m.id})); await assert.rejects(client.readResource({uri:res.uri}));
});

test('share: no publication through paths/links or disabled writes; expiry, scope and byte limits', t => {
  const { base, root, policy:p }=fixture(t); let now=1000; const store=new Shares(()=>now), f=path.join(root,'demo'); fs.writeFileSync(f,'ok');
  const m=JSON.parse(text(store.tool(p,'A',{source_path:'demo',ttl_minutes:1}))); assert.equal(JSON.parse(text(store.tool(p,'B',{action:'list'}))).files.length,0);
  assert.throws(()=>store.tool(p,'B',{action:'revoke',id:m.id}),/not found/); assert.throws(()=>store.readResource('B',m.id),/not found/);
  now+=60000; assert.throws(()=>store.readResource('A',m.id),/expired/);
  fs.symlinkSync(f,path.join(root,'symlink')); fs.writeFileSync(path.join(root,'.env'),'private'); fs.linkSync(path.join(root,'.env'),path.join(root,'linked'));
  fs.writeFileSync(path.join(root,'too-large'),Buffer.alloc((2<<20)+1)); fs.writeFileSync(path.join(root,'looks-like-a-key.txt'),'-----BEGIN PRIVATE KEY-----');
  for(const a of [{path:'../demo'},{path:'/outside'},{source_path:path.join(base,'outside')},{source_path:'.env'},{source_path:'symlink'},{source_path:'linked'},{source_path:'too-large'},{source_path:'looks-like-a-key.txt'},{source_path:'demo',name:'../x'},{source_path:'demo',ttl_minutes:61}]) assert.throws(()=>store.tool(p,'a',a));
  assert.throws(()=>store.tool({...p,fs:{...p.fs,writeEnabled:false}},'a',{source_path:'demo'}),/write permission/);
});
