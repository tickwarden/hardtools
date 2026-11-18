import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { armor, Encrypter, generateX25519Identity, identityToRecipient } from 'age-encryption';
import { zipSync } from 'fflate';
import { connectionFile, getIdentity, MAX_FILE, parseDetails, targetMatches, unlock } from '../reader/format.mjs';
import { renderGuide, writePublicFiles } from '../scripts/connect-guide.mjs';

const b = s => new TextEncoder().encode(s);
const host = 'reader-test.trycloudflare.com', ep = `https://${host}/mcp`, invite = `https://${host}/invite/example-only`;
const token = randomBytes(32).toString('hex');
const run = 'https://github.com/example/hardtools/actions/runs/123';
const body = `HARDTOOLS MCP — ÖZEL BAĞLANTI BİLGİSİ | #17 (serve)\n\n${invite}\nMCP Endpoint URL: ${ep}\nURL: ${ep}\nHeader name: Authorization\nHeader value: Bearer ${token}\nOturum: ${run}\n`;
const guide = renderGuide(ep, run, '17', 'serve', 'age');

test('reader: private/plain, old field indentation, CRLF and identical repeated endpoints', async () => {
  const old = `1. Git: ${invite}\r\n    URL: ${ep}\r\n    Header value: Bearer ${token}\r\n`;
  assert.deepEqual(parseDetails(old), { invite, endpoint: ep, token, number: '' });
  const packet = connectionFile(zipSync({ 'connect.txt': b(body), 'BASLA-BURADAN.txt': b(guide), 'BAGLAN.html': b('ignored') }));
  assert.equal(packet.kind, 'plain');
  assert.deepEqual(await unlock(packet), { invite, endpoint: ep, token, number: '17' });
});

test('reader: decrypt armored ZIP and raw age bytes with either native identity format; reject wrong key', async () => {
  const id = await generateX25519Identity(), enc = new Encrypter();
  enc.addRecipient(await identityToRecipient(id));
  const bytes = await enc.encrypt(body);
  const packet = connectionFile(zipSync({ 'connect.txt': b(armor.encode(bytes)), 'BASLA-BURADAN.txt': b(guide) }));
  const key = b('# comment\r\n' + id + '\r\n');
  assert.equal(packet.kind, 'age');
  assert.equal((await unlock(packet, zipSync({ 'hardtools-key.txt': key }))).token, token);
  assert.equal((await unlock(connectionFile(bytes), key)).invite, invite);
  await assert.rejects(unlock(packet, b(await generateX25519Identity())));
  assert.throws(() => getIdentity(zipSync({ 'wrong.txt': key })));
  assert.throws(() => getIdentity(b(id + '\n' + id)));
});

test('reader: reject ambiguous, malformed, cross-origin and mismatched-run data', async () => {
  for (const bad of [body + `Header value: Bearer ${token}`, body.replace(token, token.slice(1)), body.replace(invite, invite.replace('reader-test', 'other-test')),
    body + `URL: ${ep}/other`, body.replace(invite, invite + '?private=1'), body.replace(' (serve)', ' (check-connection)'), body.replace(token, 'Bearer ' + token)]) {
    assert.throws(() => parseDetails(bad));
  }
  const p = connectionFile(b(body));
  await assert.rejects(unlock(p, undefined, { number: '18' }));
  await assert.rejects(unlock(p, undefined, { endpoint: ep.replace('reader-test', 'other-test') }));
  await assert.rejects(unlock(connectionFile(zipSync({ 'connect.txt': b(body), 'BASLA-BURADAN.txt': b(guide.replace('#17', '#21')) }))));
});

test('reader: authorize origin must match, not a path token, MCP URL, or lookalike', () => {
  for (const good of [host, `https://${host}/authorize`, `https://${host}/authorize?client_id=example&state=test`]) assert.ok(targetMatches(good, ep));
  for (const bad of ['', ep, invite, `http://${host}/authorize`, `https://user@${host}/authorize`, `https://${host}:8080/authorize`, `${host}.example.org`, `https://some-${host}/authorize`]) assert.ok(!targetMatches(bad, ep));
});

test('reader: marked closed/test ZIPs, excessive sizes and non-connection ZIPs never unlock', () => {
  for (const mode of ['check-connection', 'cancelled']) assert.throws(() => connectionFile(zipSync({ 'connect.txt': b(body), 'BASLA-BURADAN.txt': b(renderGuide(ep, run, '17', mode, 'age')) })));
  assert.throws(() => connectionFile(new Uint8Array(MAX_FILE + 1)));
  assert.throws(() => connectionFile(zipSync({ 'connect.txt': new Uint8Array(32769) })));
  assert.throws(() => connectionFile(zipSync({ 'other/connect.txt': b(body) })));
});

test('reader: SSH recipient is routed to local age CLI and does not need an SSH private key in the page', async () => {
  const syntheticHeader = 'age-encryption.org/v1\n-> ssh-ed25519 example\neA\n--- example\n';
  const p = connectionFile(b(syntheticHeader));
  assert.equal(p.kind, 'ssh'); await assert.rejects(unlock(p), /SSH alıcısı/);
});

test('delivery: stamped page carries only public run coordinates, keeps hashed inline assets intact', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ht-stamp-'));
  try {
    await writePublicFiles(dir, ep, run, '17', 'serve', 'age');
    const html = await readFile(join(dir, 'BAGLAN.html'), 'utf8');
    assert.ok(html.includes(`content="17" data-mode="serve" data-endpoint="${ep}"`));
    assert.ok(!html.includes(invite) && !html.includes(token));
    assert.match(html, /default-src 'none'; connect-src 'none'/);
    for (const [tag, directive] of [['script', 'script'], ['style', 'style']]) {
      const content = html.match(new RegExp(`<${tag}>([\\s\\S]+?)</${tag}>`))[1];
      const sum = createHash('sha256').update(content).digest('base64');
      assert.ok(html.includes(`${directive}-src 'sha256-${sum}'`));
    }
    await assert.rejects(writePublicFiles(dir, invite, run, '17', 'serve', 'age'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
