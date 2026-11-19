import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, copyFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { zipSync } from 'fflate';
import { coordinates, decodeCard, encodeCard, openCard, sealCard, validPassword } from '../reader/session.mjs';
import { importConnection } from '../reader/import.mjs';
import { makePage } from '../scripts/connection-card.mjs';
const root = fileURLToPath(new URL('../', import.meta.url));
const meta = { v: 2, number: '17', mode: 'serve', endpoint: 'https://card-test.trycloudflare.com/mcp', run: 'https://github.com/example/test/actions/runs/123' };
const details = { token: randomBytes(32).toString('hex'), invite: 'https://card-test.trycloudflare.com/invite/' + randomBytes(24).toString('base64url') };
const secret = randomBytes(30).toString('base64url');
const extract = html => decodeCard(html.match(/<meta name="hardtools-card" content="([A-Za-z0-9+/=]+)">/)[1]);

test('card: only strong-length single-line passwords and credential-free run coordinates', async () => {
  for (const s of [undefined, '', 'too short', 'a'.repeat(257), ' ' + secret, secret + '\n']) assert.ok(!validPassword(s));
  assert.ok(validPassword(secret));
  for (const invalid of [{ mode: 'unknown' }, { v: 1 }, { run: meta.run + '?code=x' }, { endpoint: meta.endpoint + '?s=1' }, { endpoint: details.invite }, { number: '0' }]) assert.throws(() => coordinates({ ...meta, ...invalid }));
  await assert.rejects(sealCard(meta, { ...details, invite: details.invite.replace('card-test', 'another-run') }, secret));
  await assert.rejects(sealCard(meta, { ...details, token: 'invalid' }, secret));
});

test('card: per-artifact random salt and IV, wrong password and tampering fail closed', async () => {
  const a = await sealCard(meta, details, secret), b = await sealCard(meta, details, secret);
  assert.notEqual(a.salt, b.salt); assert.notEqual(a.iv, b.iv); assert.notEqual(a.data, b.data);
  assert.deepEqual(await openCard(decodeCard(encodeCard(a)), secret), { ...details, endpoint: meta.endpoint, number: meta.number });
  const bytes = Buffer.from(a.data, 'base64'); bytes[0] ^= 1;
  for (const bad of [{ number: '18' }, { endpoint: meta.endpoint.replace('card-test','other-test') }, { mode: 'check-connection' }, { run: meta.run + '4' }, { data: bytes.toString('base64') }]) await assert.rejects(openCard({ ...a, ...bad }, secret));
  await assert.rejects(openCard(a, secret + 'x')); assert.throws(() => decodeCard('%'));
});

test('card: only ciphertext in static HTML, hashed inline code and style still intact; inert ZIP import', async () => {
  const html = await makePage(meta, details, secret), c = extract(html);
  for (const item of [secret, details.token, details.invite]) assert.ok(!html.includes(item) && !JSON.stringify(c).includes(item));
  assert.match(html, /default-src 'none'; connect-src 'none'/);
  for (const tag of ['script','style']) {
    const src = html.match(new RegExp(`<${tag}>([\\s\\S]+?)</${tag}>`))[1];
    assert.ok(html.includes(`${tag}-src 'sha256-${createHash('sha256').update(src).digest('base64')}'`));
  }
  assert.deepEqual(importConnection(zipSync({ 'BAGLAN.html': Buffer.from(html) })).card, c);
  const testCard = extract(await makePage({ ...meta, mode: 'check-connection' }, details, secret));
  await assert.rejects(openCard(testCard, secret));
});

test('delivery CLI: build artifact layout, fail before producing a file without a secret, exactly one portable HTML', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ht-card-pack-')); try {
    const pkg = join(dir, 'artifact'), dest = join(dir, 'connect'); await mkdir(dest);
    for (const f of ['bundle/BAGLAN.html','scripts/connection-card.mjs','reader/session.mjs']) { await mkdir(join(pkg, f.split('/')[0]), { recursive: true }); await copyFile(join(root,f), join(pkg,f)); }
    const cli = join(pkg,'scripts/connection-card.mjs');
    const run = (pw, args) => spawnSync(process.execPath, [cli,...args], { env: { CONNECT_PASSWORD: pw }, input: details.invite + '\n' + details.token + '\n', encoding: 'utf8' });
    assert.notEqual(run('', ['--check-password']).status, 0); assert.equal(run(secret, ['--check-password']).status, 0);
    const args = [join(dest,'BAGLAN.html'), meta.endpoint, meta.run, meta.number, meta.mode];
    assert.notEqual(run('', args).status, 0); assert.deepEqual(await readdir(dest), []);
    const built = run(secret,args); assert.equal(built.status, 0); assert.equal(built.stdout + built.stderr, '');
    assert.deepEqual(await readdir(dest), ['BAGLAN.html']);
    assert.equal((await openCard(extract(await readFile(args[0], 'utf8')),secret)).token, details.token);
  } finally { await rm(dir, { recursive: true, force:true }); }
});
