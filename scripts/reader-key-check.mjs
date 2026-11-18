// Browser integration for both age-keygen operations, only with disposable test identities.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { identityToRecipient } from 'age-encryption';
import { zipSync } from 'fflate';
import { getIdentity } from '../reader/format.mjs';

export async function checkKeyPanel(page, root, dir) {
  const $ = id => page.locator('#' + id);
  const importKey = (name, buffer) => $('sourceKey').setInputFiles({ name, buffer, mimeType: 'application/octet-stream' });
  const waitKey = msg => page.waitForFunction(s => document.querySelector('#keysStatus').textContent.includes(s), msg, { timeout: 5000 });
  await page.goto(pathToFileURL(join(root, 'bundle/BAGLAN.html')).href); // no run or artifact yet
  assert.ok(await $('keysPanel').evaluate(e => e.open)); assert.ok(await $('recipientRow').isHidden());
  await $('makeKey').click(); await $('saveKey').waitFor({ state: 'visible' });
  assert.ok(await $('makeKey').isDisabled()); assert.ok(await $('recipientRow').isHidden());
  const event = page.waitForEvent('download'); await $('saveKey').click(); const download = await event;
  assert.equal(download.suggestedFilename(), 'hardtools-key.txt');
  const filename = join(dir, 'browser-private.txt'); await download.saveAs(filename);
  const bytes = await readFile(filename), id = getIdentity(bytes), recipient = await $('recipient').inputValue();
  assert.ok(await identityToRecipient(id) === recipient);
  if (process.env.AGE_KEYGEN_BIN) {
    assert.ok(execFileSync(process.env.AGE_KEYGEN_BIN, ['-y', filename], { encoding: 'utf8' }).trim() === recipient);
  }
  const visibleOrInDOM = await page.evaluate(() => [document.documentElement.outerHTML, ...Array.from(document.querySelectorAll('input,textarea'), x => x.value)].join('\n'));
  assert.ok(!visibleOrInDOM.includes(id), 'the private key must not be in HTML or a field');
  await $('copyRecipient').click(); await waitKey('kopyalandı'); assert.equal(await page.evaluate(() => window.testCopied), recipient);
  await page.evaluate(() => { window.denyClipboard = true; }); await $('copyRecipient').click(); await waitKey('Ctrl+C');
  assert.equal(await $('recipient').evaluate(e => e.selectionEnd - e.selectionStart), recipient.length);
  await page.evaluate(() => { window.denyClipboard = false; });
  await $('clearKeys').click(); assert.equal(await $('saveKey').getAttribute('href'), null); assert.equal(await $('recipient').inputValue(), '');
  await importKey('hardtools-key.txt', bytes); await waitKey('hesaplandı'); assert.equal(await $('recipient').inputValue(), recipient); assert.ok(await $('saveRow').isHidden());
  await importKey('hardtools-ozel-anahtar.zip', Buffer.from(zipSync({ 'hardtools-key.txt': bytes }))); await waitKey('hesaplandı'); assert.equal(await $('recipient').inputValue(), recipient);
  if (process.env.AGE_KEYGEN_BIN) {
    const path = join(dir, 'go-private.txt'); execFileSync(process.env.AGE_KEYGEN_BIN, ['-o', path], { stdio: ['ignore', 'pipe', 'pipe'] });
    const expected = execFileSync(process.env.AGE_KEYGEN_BIN, ['-y', path], { encoding: 'utf8' }).trim();
    await importKey('hardtools-key.txt', await readFile(path)); await page.waitForFunction(pub => document.querySelector('#recipient').value === pub, expected);
  }
  await importKey('public.txt', Buffer.from(recipient)); await waitKey('okunamadı'); assert.ok(await $('recipientRow').isHidden()); assert.ok(await $('copyRecipient').isDisabled());
  // Reuse exactly the browser-created recipient and the saved TXT for the end-to-end connection reader check.
  return { bytes, recipient };
}
