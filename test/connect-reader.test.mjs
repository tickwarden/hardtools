import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { armor, Encrypter, generateX25519Identity, identityToRecipient } from 'age-encryption';
import { zipSync } from 'fflate';
import { connectionFile, getIdentity, MAX_FILE, parseDetails, pastedPacket, targetMatches, unlock } from '../reader/legacy.mjs';
// Previous artifacts are immutable: keep read-only test fixtures for their public guide.
const renderGuide = (ep, run, num, mode) => `HARDTOOLS MCP | BAĞLANTI KILAVUZU | #${num}\n${mode === 'cancelled' ? 'İPTAL EDİLDİ — kapalı' : mode === 'check-connection' ? 'SADECE TEST — kapalı' : 'YAYIN (serve)'}\n${ep}\n${run}\n`;

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

test('legacy paste: standard Base64 body with blank lines, armored text and missing padding need the original identity', async () => {
  const id = await generateX25519Identity(), enc = new Encrypter(); enc.addRecipient(await identityToRecipient(id));
  const bin = await enc.encrypt(body), raw = Buffer.from(bin).toString('base64');
  for (const pasted of [raw.match(/.{1,72}/g).join('\r\n\r\n'), "'" + raw + "'", raw.replace(/=+$/, ''), armor.encode(bin)]) {
    const p = pastedPacket(pasted); assert.equal(p.kind, 'age');
    assert.equal((await unlock(p, b(id))).token, token);
    await assert.rejects(unlock(p, b(await generateX25519Identity())));
  }
  for (const bad of ['', token, id, 'YWdlLWVuY3J5cHRpb24ub3JnL3Yx!!', '-----BEGIN AGE ENCRYPTED FILE-----\n' + raw]) assert.throws(() => pastedPacket(bad));
});
