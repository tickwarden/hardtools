// End to end: production payload writer → artifact-shaped ZIP → local file in Chrome.
// No real endpoints or secrets. These test packages are not loaded by the reader.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright-core';
import { armor, Encrypter, generateX25519Identity } from 'age-encryption';
import { zipSync } from 'fflate';
import { writePublicFiles } from './connect-guide.mjs';
import { checkKeyPanel } from './reader-key-check.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'ht-reader-'));
const host = 'offline-reader-test.trycloudflare.com', ep = `https://${host}/mcp`, invite = `https://${host}/invite/example-only`;
const run = 'https://github.com/example/hardtools/actions/runs/3456', token = randomBytes(32).toString('hex');
let browser;
try {
  const plain = execFileSync('bash', ['-c', '. scripts/connect-payload.sh; connection_details "$1" "$2" "$3" "$4"', '_', invite, ep, token, run], {
    cwd: root, env: { PATH: process.env.PATH, GITHUB_RUN_NUMBER: '37', RUN_MODE: 'serve', ALLOW_LOCAL_TOOLS: '0', AUTO_RENEW: '0' },
  });
  await writePublicFiles(dir, ep, run, '37', 'serve', 'age');
  const local = pathToFileURL(join(dir, 'BAGLAN.html')).href;
  const html = await readFile(join(dir, 'BAGLAN.html')), guide = await readFile(join(dir, 'BASLA-BURADAN.txt'));
  browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || 'google-chrome', headless: true, args: ['--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking'] });
  const context = await browser.newContext(), page = await context.newPage();
  const requests = [], errors = [];
  context.on('request', r => { if (/^(?:https?|wss?):/i.test(r.url())) requests.push(r.url()); });
  await context.route(/^https?:\/\//i, r => r.abort());
  page.on('pageerror', e => errors.push(e.message));
  await context.addInitScript(() => Object.defineProperty(navigator, 'clipboard', { value: { writeText: async s => { if (window.denyClipboard) throw Error(); window.testCopied = s; } } }));
  const $ = id => page.locator('#' + id);
  const put = (field, name, buffer) => $(field).setInputFiles({ name, buffer, mimeType: 'application/octet-stream' });
  const status = part => page.waitForFunction(s => document.querySelector('#status').textContent.includes(s), part, { timeout: 5000 });
  const copied = () => page.evaluate(() => window.testCopied);
  const { bytes: keyBytes, recipient } = await checkKeyPanel(page, root, dir);
  const enc = new Encrypter(); enc.addRecipient(recipient);
  // Optionally exercise the exact Go age/age-keygen CLI in both directions.
  const cipher = process.env.AGE_BIN ? execFileSync(process.env.AGE_BIN, ['-a', '-r', recipient], { input: plain }) : Buffer.from(armor.encode(await enc.encrypt(plain)));
  const zip = Buffer.from(zipSync({ 'connect.txt': cipher, 'BASLA-BURADAN.txt': guide, 'BAGLAN.html': html }));
  const keyZip = Buffer.from(zipSync({ 'hardtools-key.txt': keyBytes }));
  await page.goto(local);
  await put('pack', 'hardtools-connect.zip', zip); await status('Paket şifreli');
  await put('key', 'hardtools-ozel-anahtar.zip', keyZip); await status('Hazır.');
  await $('copyInvite').click(); await status('Davet kopyalandı'); assert.equal(await copied(), invite);
  await $('copyEndpoint').click(); await status('/mcp adresi kopyalandı'); assert.equal(await copied(), ep);
  await $('formBox').locator('summary').click();
  await $('target').fill('other-run.trycloudflare.com'); assert.ok(await $('copyRaw').isDisabled());
  assert.equal(await copied(), ep);
  await $('target').fill(`https://${host}/authorize?state=example`); await $('copyRaw').click(); await status('Yalın token kopyalandı'); assert.equal(await copied(), token);
  await page.evaluate(() => { window.denyClipboard = true; }); await $('copyRaw').click(); await status('Ctrl+C');
  assert.equal(await $('manual').inputValue(), token);
  assert.equal(await $('manual').evaluate(el => el.selectionEnd - el.selectionStart), token.length);
  await $('target').fill('wrong'); assert.ok(await $('copyRaw').isDisabled()); assert.equal(await $('manual').inputValue(), '');
  await page.evaluate(() => { window.denyClipboard = false; });
  await $('headerBox').locator('summary').click(); await $('copyHeader').click(); await status('Header değeri Bearer'); assert.equal(await copied(), 'Bearer ' + token);
  await put('key', 'other-key.txt', Buffer.from(await generateX25519Identity())); await status('Dosya açılamadı'); assert.ok(await $('results').isHidden());
  await put('pack', 'connect.txt', cipher); await status('Paket şifreli'); await put('key', 'hardtools-key.txt', keyBytes); await status('Hazır.');
  await put('pack', 'plain.txt', plain); await status('Hazır.'); assert.ok(await $('key').isHidden());
  await put('pack', 'other.txt', Buffer.from(plain.toString().replaceAll(host, 'other-run.trycloudflare.com'))); await status('eşleşmiyor'); assert.ok(await $('results').isHidden());
  await put('pack', 'test.zip', Buffer.from(zipSync({ 'connect.txt': cipher, 'BASLA-BURADAN.txt': Buffer.from('SADECE TEST — örnek') }))); await status('kapalı bir oturum');
  await $('reset').click(); assert.equal(await $('pack').inputValue(), ''); assert.equal(await $('manual').inputValue(), ''); assert.ok(await $('key').isHidden());
  await writePublicFiles(dir, ep, run, '37', 'check-connection', 'age'); await page.reload(); await status('kapalı bir oturum'); assert.ok(await $('pack').isDisabled()); assert.ok(await $('makeKey').isEnabled());
  const preview = await context.newPage(); await preview.setContent(html.toString()); assert.ok(await preview.locator('#pack').isDisabled()); assert.ok(await preview.locator('#makeKey').isDisabled()); assert.ok(await preview.locator('#sourceKey').isDisabled()); assert.match(await preview.locator('#status').textContent(), /Önizlemede/);
  assert.deepEqual(requests, []); assert.deepEqual(errors, []);
  keyBytes.fill(0);
  console.log('Browser PASS: local keygen -o/-y, native TXT download, public-only clipboard, workflow payload, encrypted/plain ZIP and TXT, 4 copy targets, origin mismatch, manual copy, wrong key, closed run, preview lock, reset; zero network requests.');
} finally { await browser?.close(); await rm(dir, { recursive: true, force: true }); }
