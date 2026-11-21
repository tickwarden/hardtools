import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import dns from 'node:dns/promises';
import net from 'node:net';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { loadPolicy } from '../dist/config.js';
import { workspacePeer, openWorkspaceEgress } from '../dist/workspace-egress.js';
import { runShell } from '../dist/shell.js';

function fixture(t) {
  const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ht-https-test-')));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const root=path.join(dir,'project'); fs.mkdirSync(root);
  const p=loadPolicy({profile:'balanced',roots:[root],override:{audit:{dir:path.join(dir,'audit')}}});
  return {dir,root,p:{...p,shellWorker:'workspace',workspaceHttps:true}};
}
const worker={skip:process.env.HT_REQUIRE_WORKER_TEST!=='1' && (process.platform!=='linux'||!fs.existsSync('/usr/bin/bwrap')) && 'Linux bubblewrap not installed'};

// Address checks are pure/offline. Do not connect to private services to test a refusal.
test('workspace HTTPS: public destinations only, even with explicit ht_fetch loopback exceptions', async t=>{
  const {p}=fixture(t); p.net={...p.net,loopbackPorts:[443]};
  t.mock.method(os,'networkInterfaces',()=>({fixture:[{family:'IPv4',address:'93.184.215.10',cidr:'93.184.215.10/24'}]}));
  t.mock.method(dns,'lookup',async()=>{throw Error('unexpected DNS lookup')});
  for(const authority of ['127.0.0.1:443','127.1:443','2130706433:443','10.1.1.1:443','169.254.169.254:443','168.63.129.16:443','100.100.100.200:443','192.88.99.1:443','[::1]:443','[::ffff:127.0.0.1]:443','[fd00::1]:443','[64:ff9b::7f00:1]:443','[2002:7f00:0001::]:443','[2001:db8::1]:443','[3fff::1]:443','93.184.215.10:443','93.184.215.25:443','127.0.0.1:8443','local:443','host.local:443','x.internal:443','host.home.arpa:443','user@site.example:443','site.example/path:443','site.example:443:443','site.example:22']) {
    await assert.rejects(workspacePeer(p,authority),e=>e.message!=='unexpected DNS lookup',authority);
  }
  assert.deepEqual(await workspacePeer(p,'1.1.1.1:443'),{address:'1.1.1.1',family:4});
  assert.equal((await workspacePeer(p,'[2606:4700:4700::1111]:443')).family,6);
});

test('workspace HTTPS: exact DNS query once, all answers vetted, normal domain policy retained',async t=>{
  const {p}=fixture(t); p.net={...p.net,allowDomains:['repo.example'],denyDomains:['blocked.repo.example']};
  let records=[{address:'93.184.215.11',family:4},{address:'fd00::42',family:6}]; let calls=0;
  t.mock.method(dns,'lookup',async(host,opts)=>{calls++;assert.equal(host,'repo.example.');assert.equal(opts.all,true);return records;});
  for(const authority of ['outside.example:443','blocked.repo.example:443']) await assert.rejects(workspacePeer(p,authority));
  assert.equal(calls,0);
  await assert.rejects(workspacePeer(p,'repo.example:443'),{code:'workspace_https_denied'});assert.equal(calls,1);
  records=records.slice(0,1);assert.deepEqual(await workspacePeer(p,'repo.example.:443'),records[0]);assert.equal(calls,2);
  for(const altered of [{workspaceHttps:false},{shellWorker:undefined},{net:{...p.net,enabled:false}},{net:{...p.net,ports:[8443]}},{net:{...p.net,schemes:['http']}},{net:{...p.net,requireAllowDomains:true,allowDomains:[]}}]) {
    await assert.rejects(openWorkspaceEgress({...p,...altered}),{code:'workspace_https_unavailable'});
  }
  await assert.rejects(openWorkspaceEgress({...p,roots:['/tmp']}),{code:'worker_root'});
});

test('workspace HTTPS: one private Unix endpoint per command, closes peers and removes socket directory',{skip:process.platform!=='linux'},async t=>{
  const {p}=fixture(t), a=await openWorkspaceEgress(p), b=await openWorkspaceEgress(p);
  t.after(()=>{a.close();b.close()});
  assert.notEqual(a.socketPath,b.socketPath);assert.equal(fs.statSync(a.socketPath).mode&0o777,0o600);
  assert.equal(fs.statSync(path.dirname(a.socketPath)).mode&0o777,0o700);
  const client=net.createConnection(a.socketPath); await new Promise((ok,fail)=>client.once('connect',ok).once('error',fail));
  const ended=new Promise(ok=>client.once('close',ok)); a.close(); await ended;
  assert.equal(fs.existsSync(path.dirname(a.socketPath)),false);assert.ok(fs.statSync(b.socketPath).isSocket());
});

test('workspace HTTPS: verified TLS from real isolated curl via pinned peer; no public target needed in CI',worker,async t=>{
  const {p,dir,root}=fixture(t);
  // The numeric production dial is intercepted *in this test process only*. The guest
  // still performs TLS and verifies the fixture name/cert. No production loopback exception.
  const cert=path.join(root,'fixture.crt'),key=path.join(dir,'fixture.key');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=repo.example','-addext','subjectAltName=DNS:repo.example','-keyout',key,'-out',cert],{stdio:'ignore'});
  const origin=https.createServer({key:fs.readFileSync(key),cert:fs.readFileSync(cert)},(req,res)=>{
    if(req.url==='/go'){res.writeHead(302,{location:'https://denied.example/data'}).end();return;}
    res.end('verified guest HTTPS');
  });
  await new Promise(ok=>origin.listen(0,'127.0.0.1',ok)); t.after(()=>new Promise(ok=>origin.close(ok)));
  let resolutions=0, dials=0;
  t.mock.method(dns,'lookup',async name=>{assert.equal(name,'repo.example.');resolutions++;return [{address:'93.184.215.10',family:4}];});
  const connect=net.createConnection.bind(net);
  t.mock.method(net,'createConnection',options=>{assert.equal(options.host,'93.184.215.10');assert.equal(options.port,443);dials++;return connect({host:'127.0.0.1',port:origin.address().port});});
  p.net={...p.net,allowDomains:['repo.example']};
  const curl=async (...args)=>JSON.parse((await runShell(p,{argv:['curl','--silent','--show-error','--max-time','5',...args],output_format:'json'})).text);
  const ok=await curl('--cacert','fixture.crt','https://repo.example/'); assert.equal(ok.exit_code,0,ok.stderr);assert.equal(ok.stdout,'verified guest HTTPS');
  const untrusted=await curl('https://repo.example/');assert.notEqual(untrusted.exit_code,0);assert.match(untrusted.stderr,/certificate/i);
  const redirected=await curl('--cacert','fixture.crt','-L','https://repo.example/go');assert.notEqual(redirected.exit_code,0);assert.match(redirected.stderr,/403/);
  assert.equal(resolutions,3);assert.equal(dials,3,'redirect target never resolved or dialled');
});

test('workspace HTTPS: ending a command cancels pending dials even if DNS completes late',{skip:process.platform!=='linux'},async t=>{
  const {p}=fixture(t);const lease=await openWorkspaceEgress(p);t.after(()=>lease.close());
  let begin,finish;const started=new Promise(ok=>begin=ok),answer=new Promise(ok=>finish=ok);
  t.mock.method(dns,'lookup',async()=>{begin();return answer;});
  const client=net.createConnection(lease.socketPath);client.on('error',()=>{});
  const dial=t.mock.method(net,'createConnection',()=>{throw Error('unexpected dial after shutdown')});
  client.write('CONNECT repo.example:443 HTTP/1.1\r\nHost: repo.example:443\r\n\r\n');
  await started;lease.close();finish([{address:'93.184.215.10',family:4}]);await new Promise(ok=>setImmediate(ok));
  assert.equal(dial.mock.callCount(),0);assert.equal(fs.existsSync(path.dirname(lease.socketPath)),false);
});

test('workspace HTTPS: timeout and missing guest bridge close the per-call broker without a host fallback',worker,async t=>{
  const {p,root}=fixture(t);const mk=fs.mkdtempSync,dirs=[];
  t.mock.method(fs,'mkdtempSync',(...args)=>{const dir=mk(...args);if(args[0]==='/tmp/ht-egress-')dirs.push(dir);return dir;});
  const r=JSON.parse((await runShell(p,{command:'sleep 4',timeout_ms:250,output_format:'json'})).text);
  assert.equal(r.timed_out,true);assert.equal(dirs.length,1);assert.equal(fs.existsSync(dirs[0]),false);
  const op=fs.openSync;t.mock.method(fs,'openSync',(...args)=>{if(args[0] instanceof URL && args[0].pathname.endsWith('/workspace-bridge.js'))throw Error('missing guest relay');return op(...args);});
  await assert.rejects(runShell(p,{command:'printf ran > marker'}),/missing guest relay/);
  assert.equal(dirs.length,2);assert.equal(fs.existsSync(dirs[1]),false);assert.equal(fs.existsSync(path.join(root,'marker')),false);
});
