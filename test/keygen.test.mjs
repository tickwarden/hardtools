import test from 'node:test';
import assert from 'node:assert/strict';
import { Encrypter, Decrypter } from 'age-encryption';
import { zipSync } from 'fflate';
import { getIdentity } from '../reader/format.mjs';
import { createKeyFile, recipientFromFile } from '../reader/keys.mjs';

const enc = s => new TextEncoder().encode(s);
const text = b => new TextDecoder().decode(b);

test('keygen -o: unique X25519 identity files with matching public recipients; no external services', async () => {
  const a = await createKeyFile(), b = await createKeyFile();
  try {
    assert.match(a.recipient, /^age1[0-9a-z]{58}$/);
    assert.notEqual(a.recipient, b.recipient);
    assert.ok(text(a.bytes).includes(`# public key: ${a.recipient}\n`));
    assert.equal(await recipientFromFile(a.bytes), a.recipient);
    const writer = new Encrypter(); writer.addRecipient(a.recipient);
    const reader = new Decrypter(); reader.addIdentity(getIdentity(a.bytes));
    assert.equal(await reader.decrypt(await writer.encrypt('synthetic round-trip'), 'text'), 'synthetic round-trip');
  } finally { a.bytes.fill(0); b.bytes.fill(0); }
});

test('keygen -y: compute from the existing private key, not its comments (TXT / ZIP, CRLF)', async () => {
  const pair = await createKeyFile();
  try {
    const contents = enc(`# public key: not-the-recipient\r\n${getIdentity(pair.bytes)}\r\n`);
    assert.equal(await recipientFromFile(contents), pair.recipient);
    assert.equal(await recipientFromFile(zipSync({ 'hardtools-key.txt': contents })), pair.recipient);
  } finally { pair.bytes.fill(0); }
});

test('keygen -y: empty, public-only, multiple, invalid-checksum and wrong ZIP inputs are rejected without echoing data', async () => {
  const p = await createKeyFile();
  try {
    const id = getIdentity(p.bytes), mutated = id.slice(0, -1) + (id.endsWith('Q') ? 'P' : 'Q');
    for (const data of [enc(''), enc(p.recipient), enc(id + '\n' + id), enc(mutated), enc(id + '\nother-record'), zipSync({ 'other.txt': p.bytes })]) {
      await assert.rejects(recipientFromFile(data), e => e.message === 'Anahtar okunamadı. Tek bir geçerli age özel anahtarı içeren TXT veya hardtools anahtar ZIP’ini seç.');
    }
  } finally { p.bytes.fill(0); }
});
