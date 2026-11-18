// Native age X25519 (the format used by age-keygen and the workflow's pinned Go age).
// No generated or user-selected private key is placed in the DOM, clipboard or storage.
import { generateX25519Identity, identityToRecipient } from 'age-encryption';
import { getIdentity, ReaderError } from './format.mjs';

// Equivalent to age-keygen -o hardtools-key.txt. The caller saves and clears bytes.
export async function createKeyFile() {
  const id = await generateX25519Identity(); // crypto.getRandomValues; no insecure fallback
  const recipient = await identityToRecipient(id);
  const bytes = new TextEncoder().encode(`# created: ${new Date().toISOString()}\n# public key: ${recipient}\n${id}\n`);
  return { recipient, bytes };
}

// Equivalent to age-keygen -y for one native identity. Do not trust a public-key comment.
export async function recipientFromFile(bytes) {
  try { return await identityToRecipient(getIdentity(bytes)); }
  catch { throw new ReaderError('Anahtar okunamadı. Tek bir geçerli age özel anahtarı içeren TXT veya hardtools anahtar ZIP’ini seç.'); }
}

// Called only on a top-level local file with Web Crypto, never in a hosted preview.
export function enableKeyPanel(el, readFile) {
  const make = el('makeKey'), source = el('sourceKey'), download = el('saveKey');
  const field = el('recipient'), copy = el('copyRecipient'), clear = el('clearKeys');
  let revision = 0, url = '', current = '';
  const note = (s, kind = '') => { el('keysStatus').textContent = s; el('keysStatus').className = kind; };
  function reset() {
    ++revision; current = ''; field.value = ''; copy.disabled = true;
    download.removeAttribute('href'); if (url) URL.revokeObjectURL(url); url = '';
    el('saveRow').hidden = el('recipientRow').hidden = true;
    source.value = ''; make.disabled = source.disabled = false; clear.disabled = true;
    note('');
  }
  function showRecipient() {
    field.value = current; el('recipientRow').hidden = false; copy.disabled = false;
  }
  function busy() {
    reset(); make.disabled = source.disabled = true; clear.disabled = false;
    return revision;
  }
  make.addEventListener('click', async () => {
    const n = busy(); let pair;
    try {
      pair = await createKeyFile(); if (n !== revision) return;
      // The Blob snapshots the bytes. Keep its URL only until reset/pagehide so a
      // cancelled download can be retried without silently generating a different key.
      url = URL.createObjectURL(new Blob([pair.bytes], { type: 'text/plain;charset=utf-8' }));
      current = pair.recipient; download.href = url; el('saveRow').hidden = false;
      note('Anahtar hazır. Önce özel TXT dosyasını indir.'); download.focus();
    } catch { if (n === revision) { reset(); note('Güvenli anahtar oluşturulamadı. Dosyayı güncel bir tarayıcıda aç.', 'bad'); } }
    finally { pair?.bytes.fill(0); }
  });
  download.addEventListener('click', () => {
    if (!url) return;
    showRecipient(); source.disabled = false;
    note('İndirme istendi. Dosyanın kaydedildiğini kontrol et; sonra açık anahtarı kullan.');
  });
  source.addEventListener('change', async () => {
    const file = source.files[0]; if (!file) return;
    const n = busy(); let bytes;
    try {
      bytes = await readFile(file); if (n !== revision) return;
      const pub = await recipientFromFile(bytes); if (n !== revision) return;
      current = pub; showRecipient(); note('Açık anahtar dosyandan hesaplandı. Yeni anahtar oluşturulmadı.');
    } catch (e) {
      if (n === revision) { reset(); note(e instanceof ReaderError ? e.message : 'Anahtar dosyası okunamadı.', 'bad'); }
    } finally { bytes?.fill(0); if (n === revision) source.disabled = false; }
  });
  copy.addEventListener('click', async () => {
    if (copy.disabled || !current) return;
    const n = revision;
    try { await navigator.clipboard.writeText(current); if (n === revision) note('Yalnızca açık anahtar kopyalandı. Yeni serve için age_recipient alanına yapıştır.', 'good'); }
    catch { if (n === revision) { field.focus(); field.select(); note('Açık anahtar seçildi. Ctrl+C (Mac: ⌘C) ile kopyala.'); } }
  });
  clear.addEventListener('click', reset); reset();
  return reset;
}
