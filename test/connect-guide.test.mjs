import test from 'node:test';
import assert from 'node:assert/strict';
import { renderGuide } from '../scripts/connect-guide.mjs';

const ep = 'https://example-unit.trycloudflare.com/mcp';
const run = 'https://github.com/example/hardtools/actions/runs/1234';

test('hardtools-connect: public guide contains the exact endpoint, platform commands and web/header setup', () => {
  const guide = renderGuide(ep, run, '12', 'serve', 'age');
  for (const literal of ['\n' + ep + '\n', run, '#12', '.\\age.exe -d -i .\\hardtools-key.txt .\\connect.txt',
    'age -d -i hardtools-key.txt connect.txt', 'Name: hardtools', 'OAuth client secret: boş bırak', 'Authorization',
    'Run workflow → main → serve', 'Yeni anahtar oluştur', 'hardtools-key.txt indir', 'age_recipient']) assert.ok(guide.includes(literal), literal);
  assert.ok(!guide.includes('/invite/'));
});

test('hardtools-connect: private plaintext delivery never asks for a decryption key', () => {
  const guide = renderGuide(ep, run, '12', 'serve', 'plain');
  assert.match(guide, /düz metin/);
  assert.ok(!guide.includes('age -d') && !guide.includes('age.exe'));
});

test('hardtools-connect: diagnostic and cancelled archives warn before showing the address', () => {
  for (const [mode, warning] of [['check-connection','SADECE TEST'], ['cancelled','İPTAL EDİLDİ']]) {
    const guide = renderGuide(ep, run, '12', mode, 'age');
    assert.ok(guide.includes(warning) && guide.indexOf(warning) < guide.indexOf(ep));
  }
});

test('hardtools-connect: do not render credential-bearing URLs or arbitrary input in the public file', () => {
  for (const invalid of [ep + '/private', ep + '?key=private', ep.replace('/mcp', '/invite/private'), ep + '\n']) {
    assert.throws(() => renderGuide(invalid, run, '12', 'serve', 'age'));
  }
  assert.throws(() => renderGuide(ep, run + '?key=private', '12', 'serve', 'age'));
  assert.throws(() => renderGuide(ep, run, '12', 'unrecognised', 'age'));
  assert.throws(() => renderGuide(ep, run, '12', 'serve', 'unrecognised'));
});
