// All passwords, keys, payloads and URLs are disposable fixtures. No live invite is visited.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright-core';
import { Encrypter, generateX25519Identity, identityToRecipient } from 'age-encryption';
import { zipSync } from 'fflate';
import { makePage } from './connection-card.mjs';
const root = fileURLToPath(new URL('../', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'ht-card-browser-'));
const host = 'offline-card-test.trycloudflare.com', endpoint = `https://${host}/mcp`, invite = `https://${host}/invite/example-only`;
const meta = { v: 2, number: '37', mode: 'serve', endpoint, run: 'https://github.com/example/test/actions/runs/3456' };
const token = randomBytes(32).toString('hex'), password = randomBytes(24).toString('base64url');
let browser;
try {
  const html = await makePage(meta, { token, invite }, password);
  await writeFile(join(dir, 'BAGLAN.html'), html);
  const local = pathToFileURL(join(dir, 'BAGLAN.html')).href, generic = pathToFileURL(join(root, 'bundle/BAGLAN.html')).href;
  const archive = Buffer.from(zipSync({ 'BAGLAN.html': Buffer.from(html) }));
  browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || 'google-chrome', headless: true, args: ['--disable-gpu','--disable-dev-shm-usage','--disable-background-networking'] });
  const context = await browser.newContext(), page = await context.newPage(), requests = [], errors = [];
  context.on('request', r => { if (/^(?:https?|wss?):/i.test(r.url())) requests.push(r.url()); });
  await context.route(/^https?:\/\//i, r => r.abort()); page.on('pageerror', e => errors.push(e.message));
  await context.addInitScript(() => Object.defineProperty(navigator, 'clipboard', { value: { writeText: async s => { if (window.denyClipboard) throw Error(); window.testCopied = s; } } }));
  await context.addInitScript(() => {
    const read = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = async function () { await new Promise(resolve => setTimeout(resolve, 80)); return read.call(this); };
  });
  const $ = id => page.locator('#' + id), copied = () => page.evaluate(() => window.testCopied);
  // setInputFiles can act on a hidden/disabled input. Wait for the same UI a user sees,
  // especially when importing a ZIP asynchronously on a slow runner.
  const put = async (id,name,buffer) => {
    await $(id).waitFor({ state: 'visible' });
    await page.waitForFunction(s => !document.getElementById(s).disabled, id);
    await $(id).setInputFiles({ name, buffer, mimeType:'application/octet-stream' });
  };
  const status = msg => page.waitForFunction(s => document.querySelector('#status').textContent.includes(s), msg, { timeout: 6000 });
  async function enter(pw) { await $('password').fill(pw); await $('password').press('Enter'); }
  await page.goto(local); assert.ok(await $('pack').isHidden()); assert.ok(await $('key').isHidden()); assert.ok(await $('password').isVisible());
  await $('copyEndpoint').click(); await status('MCP adresi kopyalandı'); assert.equal(await copied(), endpoint);
  await enter('YWdlLWVuY3J5example'); await status('parolası değil');
  await enter(password + 'wrong'); await status('Paket açılamadı'); assert.ok(await $('results').isHidden());
  await enter(password); await status('Bağlantı bilgileri açıldı'); assert.equal(await $('password').inputValue(), '');
  await $('copyInvite').click(); await status('Davet kopyalandı'); assert.equal(await copied(), invite);
  await $('extra').locator('summary').click(); await $('target').fill('other-run.trycloudflare.com'); assert.ok(await $('copyRaw').isDisabled());
  await $('target').fill(`https://${host}/authorize?state=example`); await $('copyRaw').click(); await status('Yalın token'); assert.equal(await copied(), token);
  await page.evaluate(() => { window.denyClipboard = true; }); await $('copyRaw').click(); await status('Ctrl+C');
  assert.equal(await $('manual').inputValue(), token); assert.equal(await $('manual').evaluate(e => e.selectionEnd-e.selectionStart), token.length);
  await $('target').fill('wrong'); assert.equal(await $('manual').inputValue(), ''); await page.evaluate(() => { window.denyClipboard = false; });
  await $('copyHeader').click(); await status('Authorization değeri'); assert.equal(await copied(), 'Bearer '+token);
  await $('reset').click(); assert.ok(await $('results').isHidden()); assert.ok(await $('password').isVisible());
  await page.goto(generic); await put('pack','hardtools-connect.zip', archive); await enter(password); await status('Bağlantı bilgileri açıldı'); await $('reset').click();
  const id = await generateX25519Identity(), recipient = await identityToRecipient(id);
  const clear = `HARDTOOLS MCP — ÖZEL BAĞLANTI BİLGİSİ | #37 (serve)\n${invite}\nMCP Endpoint URL: ${endpoint}\nURL: ${endpoint}\nHeader value: Bearer ${token}\n`;
  const encrypter = new Encrypter(); encrypter.addRecipient(recipient);
  const binary = process.env.AGE_BIN ? execFileSync(process.env.AGE_BIN, ['-r',recipient], { input:clear }) : Buffer.from(await encrypter.encrypt(clear));
  const raw = binary.toString('base64').match(/.{1,72}/g).join('\r\n\r\n');
  await $('oldText').locator('summary').click(); await $('paste').fill(raw); await $('loadText').click(); await status('Şifreli eski paket tanındı');
  await put('key','other.txt',Buffer.from(await generateX25519Identity())); await status('eski paketi açmadı'); assert.ok(await $('results').isHidden());
  await put('key','hardtools-key.txt',Buffer.from(id)); await status('Bağlantı bilgileri açıldı'); await $('copyInvite').click(); await status('Davet kopyalandı'); assert.equal(await copied(), invite);
  await $('reset').click(); await put('pack','old.zip', Buffer.from(zipSync({ 'connect.txt':binary,'BAGLAN.html':Buffer.from('<!doctype html><head></head>') })));
  await status('Şifreli eski paket tanındı');
  await put('key','hardtools-ozel-anahtar.zip',Buffer.from(zipSync({ 'hardtools-key.txt':Buffer.from(id) }))); await status('Bağlantı bilgileri açıldı');
  await $('reset').click(); await put('pack','old-test.zip',Buffer.from(zipSync({ 'connect.txt':binary, 'BASLA-BURADAN.txt':Buffer.from('SADECE TEST — kapalı') }))); await status('kapalı bir oturum');
  await writeFile(join(dir,'BAGLAN.html'), await makePage({ ...meta,mode:'check-connection' },{ token, invite }, password)); await page.goto(local); await status('testi bir yayın değil'); assert.ok(await $('password').isDisabled()); assert.ok(await $('results').isHidden());
  const preview = await context.newPage(); await preview.setContent(html); assert.ok(await preview.locator('#password').isDisabled()); assert.ok(await preview.locator('#pack').isDisabled()); assert.match(await preview.locator('#status').textContent(), /Önizleme/);
  assert.deepEqual(requests, []); assert.deepEqual(errors, []);
  console.log('Browser PASS: one HTML → one password → invite; public endpoint, invalid password, raw/header clipboard, Ctrl+C, reset, new ZIP import, legacy Base64/blank lines/age keys, closed run, preview lock; zero network requests.');
} finally { await browser?.close(); await rm(dir, { recursive: true, force: true }); }
