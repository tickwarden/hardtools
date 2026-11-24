import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { loadPolicy } from '../dist/config.js';
import { Shares, SHARE_CWD } from '../dist/share.js';
import { htEmptyTrash, htMove, htTrash } from '../dist/fs-extra.js';
import { Audit } from '../dist/audit.js';
import { Variables } from '../dist/variables.js';

function fixture(t) {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ht-tools-')));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const root = path.join(base, 'project'), audit = path.join(base, 'audit'); fs.mkdirSync(root);
  const policy = loadPolicy({ roots: [root], override: { profile: 'balanced', audit: { dir: audit } } });
  return { base, root, audit, policy };
}
async function session(t, config = {}) {
  const f = fixture(t), cfg = path.join(f.base, 'settings', 'config.json');
  fs.mkdirSync(path.dirname(cfg)); fs.writeFileSync(cfg, JSON.stringify({ ...config, audit: { dir: f.audit } }));
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
  const readonly = {...p,fs:{...p.fs,writeEnabled:false}};
  assert.match(htEmptyTrash(readonly,{}),/PREVIEW: 3/);
  assert.throws(() => htEmptyTrash(readonly,{confirm:true}), /disabled/);
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
  const ts = await client.listResourceTemplates();
  assert.deepEqual(ts.resourceTemplates.map(t=>t.uriTemplate), ['hardtools-share://local/_tmp/hardtools-share/{id}']);
  assert.deepEqual((await client.listResources()).resources, []); // do not advertise private share IDs
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

test('MCP: isolated allowlist fixture reaches the running server', async t => {
  const { call } = await session(t, { net: { allowDomains: ['allowed.example'] } });
  assert.deepEqual(JSON.parse(ok(await call('ht_status'))).net.allowDomains, ['allowed.example']);
  denied(await call('ht_fetch', { url: 'https://unlisted.invalid/' }), /DENIED \[domain_not_allowed\]/);
});

test('MCP stdio balanced: native pipeline and redirection in the host cwd, argv remains literal', async t => {
  const { root, call } = await session(t);
  const st = JSON.parse(ok(await call('ht_status'))); assert.equal(st.shell.execution, 'host'); assert.equal(st.shell.shellSyntax, true);
  if (process.platform === 'win32') return; // POSIX fixture only
  const stdout = async args => JSON.parse(ok(await call('ht_shell', { ...args, expected_exit_codes: [0], output_format: 'json' }))).stdout;
  assert.equal(await stdout({ command: 'printf merhaba | tr a-z A-Z > sonuc.txt && pwd' }), root + '\n');
  assert.equal(fs.readFileSync(path.join(root, 'sonuc.txt'), 'utf8'), 'MERHABA');
  assert.equal(await stdout({ argv: ['echo', 'a | b > c'] }), 'a | b > c\n');
  const custom = await session(t, { shell: { allowShellSyntax: false } });
  denied(await custom.call('ht_shell', { command: 'echo not-run' }), /shell_syntax_disabled/);
});

test('MCP audit: own JSONL bytes, pinned multi-page prefix, independent hashes and offline CLI checkpoint', async t => {
  const { base, call } = await session(t);
  const status = JSON.parse(ok(await call('ht_status')));
  denied(await call('ht_shell', { argv: ['cat', status.audit.file] }), /outside_roots|DENIED/);
  const first = await call('ht_status', { audit_export:true }); const small = JSON.parse(ok(first));
  assert.equal(small.scope,'process'); assert.equal(small.next_offset,null); assert.equal(first.content[1].resource.mimeType,'application/x-ndjson');
  // Create enough bounded audit entries to require paging, without changing any project file.
  const edits = Array.from({length:45}, () => ({path:'nonexistent.txt',old_str:'a'.repeat(400),new_str:'b'.repeat(400)}));
  for (let i=0; i<4; i++) denied(await call('ht_edit', {edits,dry_run:true}), /not_found/);
  const page = await call('ht_status', {audit_export:true}), start = JSON.parse(ok(page));
  assert.ok(start.next_offset > 0); const parts = [Buffer.from(page.content[1].resource.blob,'base64')];
  ok(await call('ht_mkdir',{path:'after-snapshot-marker'}));
  let offset = start.next_offset;
  while (offset !== null) {
    const r = await call('ht_status', {audit_export:true, audit_snapshot:start.snapshot, audit_offset:offset});
    const m=JSON.parse(ok(r)); assert.equal(m.offset,offset); assert.equal(m.expected_head,start.expected_head);
    assert.equal(m.entries,start.entries); assert.equal(m.total_bytes,start.total_bytes);
    parts.push(Buffer.from(r.content[1].resource.blob,'base64')); offset=m.next_offset;
  }
  const bytes=Buffer.concat(parts); assert.equal(bytes.length,start.total_bytes); assert.ok(!bytes.includes('after-snapshot-marker'));
  const lines=bytes.toString().trimEnd().split('\n'); assert.equal(lines.length,start.entries);
  let prev='0'.repeat(64);
  for(const [i,line] of lines.entries()) {
    const {hash,...body}=JSON.parse(line); assert.equal(body.prev,prev); assert.equal(body.seq,i);
    prev=crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex'); assert.equal(hash,prev);
  }
  assert.equal(prev,start.expected_head);
  const f=path.join(base,'export.jsonl'), verify = () => spawnSync(process.execPath,[path.resolve(process.env.HT_ENTRY ?? 'dist/index.js'),'--verify',f,'--expect-head',start.expected_head],{encoding:'utf8'});
  fs.writeFileSync(f,bytes); assert.equal(verify().status,0);
  fs.writeFileSync(f,lines.slice(0,-1).join('\n')+'\n'); assert.equal(verify().status,2);
  fs.writeFileSync(f,bytes.toString().replace('"ev":"start"','"ev":"other"')); assert.equal(verify().status,2);
  denied(await call('ht_status',{audit_export:true,audit_snapshot:crypto.randomUUID()}),/audit_snapshot/);
  denied(await call('ht_status',{audit_export:true,audit_offset:32}),/audit_offset/);
});

test('trash restore: a nested file keeps its parent row, and an unusable index never loses the remaining directory', t => {
  const { policy, root } = fixture(t), bin=path.join(root,'.ht-trash'), manifest=path.join(bin,'index.jsonl');
  fs.mkdirSync(path.join(root,'tree')); fs.writeFileSync(path.join(root,'tree','a'),'alpha');
  htTrash(policy,{path:'tree',recursive:true}); const saved=fs.readFileSync(manifest), row=JSON.parse(saved.toString());
  htMove(policy,{from:`.ht-trash/${row.name}/a`,to:'a'});
  assert.deepEqual(fs.readFileSync(manifest),saved); assert.equal(fs.readFileSync(path.join(root,'a'),'utf8'),'alpha');
  fs.writeFileSync(manifest,'bad-json\n');
  assert.throws(()=>htMove(policy,{from:`.ht-trash/${row.name}`,to:'tree'}),/invalid trash index/);
  assert.ok(fs.statSync(path.join(bin,row.name)).isDirectory()); assert.ok(!fs.existsSync(path.join(root,'tree')));
  assert.equal(fs.readFileSync(manifest,'utf8'),'bad-json\n'); assert.ok(!fs.existsSync(path.join(root,'.ht-trash-index.lock')));
  fs.writeFileSync(manifest,saved); htMove(policy,{from:`.ht-trash/${row.name}`,to:'tree'});
  assert.ok(fs.statSync(path.join(root,'tree')).isDirectory()); assert.equal(fs.readFileSync(manifest,'utf8'),'');
});

test('audit exports refuse replaced or linked journal files instead of reading an unrelated fixture', t => {
  const {audit,base}=fixture(t), op=new Audit(audit,true), own=op.forGrant('one'), other=op.forGrant('two');
  other.write({ev:'marker',tag:'only-two'}); const original=path.join(base,'saved-own.jsonl'); fs.renameSync(own.file,original);
  for(const link of [fs.linkSync,fs.symlinkSync]) {
    link(other.file,own.file); assert.throws(()=>own.exportPage()); fs.unlinkSync(own.file);
  }
  fs.writeFileSync(own.file,'not my original file'); assert.throws(()=>own.exportPage(),/identity changed/);
  fs.unlinkSync(own.file); fs.renameSync(original,own.file); assert.ok(!Buffer.from(own.exportPage().resource.blob,'base64').includes('only-two'));
});
