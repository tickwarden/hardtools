import { connectionFile, MAX_FILE, packetBinding, ReaderError, targetMatches, unlock } from './format.mjs';
import { enableKeyPanel } from './keys.mjs';

const el = id => document.getElementById(id);
const meta = document.querySelector('meta[name=hardtools-run]');
const binding = { number: meta.content, endpoint: meta.dataset.endpoint };
const pack = el('pack'), key = el('key'), target = el('target');
let seq = 0, values = null, copyId = 0;
const say = (s, kind = '') => { el('status').textContent = s; el('status').className = kind; };
function clearManual() {
  ++copyId;
  el('manualBox').hidden = true;
  el('manual').value = '';
}
function invalidate() {
  ++seq; values = null; clearManual();
  target.value = ''; el('copyRaw').disabled = true; el('match').textContent = '';
  el('ep').textContent = ''; el('which').textContent = ''; el('results').hidden = true;
  el('formBox').open = el('headerBox').open = false;
}
function reset() {
  invalidate(); pack.value = key.value = ''; key.disabled = el('keyRow').hidden = true;
  say('Önce bu çalıştırmanın connect.txt veya hardtools-connect.zip dosyasını seç.');
}
async function readFile(file) {
  if (!file || !file.size || file.size > MAX_FILE) throw new ReaderError('Beklenen küçük ZIP veya TXT dosyasını seç.');
  return new Uint8Array(await file.arrayBuffer());
}
async function refresh() {
  invalidate();
  const id = seq, file = pack.files[0], keyFile = key.files[0];
  let bytes, packet, keyBytes;
  try {
    if (!file) { reset(); return; }
    say('Bağlantı dosyası okunuyor…');
    bytes = await readFile(file); if (id !== seq) return;
    packet = connectionFile(bytes);
    packetBinding(packet, binding); // reject a different run before asking for an identity
    const needsKey = packet.kind === 'age';
    key.disabled = el('keyRow').hidden = !needsKey;
    if (needsKey) {
      if (!keyFile) { say('Paket şifreli. Kendi age özel anahtar dosyanı seç.'); return; }
      keyBytes = await readFile(keyFile); if (id !== seq) return;
      say('Şifre bilgisayarında çözülüyor…');
    }
    const opened = await unlock(packet, keyBytes, binding); if (id !== seq) return;
    values = opened;
    el('ep').textContent = values.endpoint;
    el('which').textContent = (values.number ? 'Run #' + values.number + ' · ' : '') + new URL(values.endpoint).hostname;
    el('results').hidden = false;
    say('Hazır. Kopyalamak istediğin değeri seç.', 'good');
  } catch (e) {
    if (id === seq) say(e instanceof ReaderError ? e.message : 'Dosya açılamadı. Paketi ve ona ait özel anahtarı kontrol et.', 'bad');
  } finally {
    for (const b of [bytes, packet?.cipher, keyBytes]) b?.fill(0);
  }
}
function checkTarget() {
  clearManual();
  const typed = target.value.trim() !== '', ok = !!values && targetMatches(target.value, values.endpoint);
  el('copyRaw').disabled = !ok;
  el('match').textContent = ok ? 'Alan adı bu oturumla eşleşti.' : typed ? 'Adres bu pakete ait değil veya /authorize adresi değil. Token kopyalanmaz.' : '';
  el('match').className = ok ? 'good' : 'bad';
  return ok;
}
async function copy(kind) {
  if (!values || (kind === 'raw' && !checkTarget())) return;
  clearManual(); const id = copyId;
  const [s, msg] = {
    invite: [values.invite, 'Davet kopyalandı; henüz açılmadı.'],
    endpoint: [values.endpoint, '/mcp adresi kopyalandı. Claude’da connector URL alanına yapıştır.'],
    raw: [values.token, 'Yalın token kopyalandı. Eşleşen sayfada Access token kutusuna yapıştır.'],
    header: ['Bearer ' + values.token, 'Header değeri Bearer önekiyle kopyalandı.'],
  }[kind];
  try { await navigator.clipboard.writeText(s); if (id === copyId) say(msg, 'good'); }
  catch {
    if (id !== copyId) return;
    el('manualBox').hidden = false; el('manual').value = s; el('manual').focus(); el('manual').select();
    say('Seçili değeri Ctrl+C (Mac: ⌘C) ile kopyala.');
  }
}

if (binding.number) {
  el('context').textContent = `Run #${binding.number} · ${binding.endpoint}`; el('context').hidden = false;
}
const local = location.protocol === 'file:' && window.self === window.top;
const closedRun = Boolean(meta.dataset.mode && meta.dataset.mode !== 'serve');
el('localNotice').hidden = local; el('keysPanel').open = !binding.number || closedRun;
if (!local) {
  say('Önizlemede işlemler kapalı. BAGLAN.html dosyasını indirip kendi bilgisayarında aç.');
} else if (!globalThis.crypto?.subtle || typeof globalThis.crypto.getRandomValues !== 'function') {
  el('localNotice').hidden = false; el('localNotice').textContent = 'Güvenli kriptografi kullanılamıyor. Dosyayı güncel Edge, Chrome veya Firefox ile aç.';
  say(el('localNotice').textContent, 'bad');
} else {
  // Preparing a key for a future run is independent of the selected run/packet.
  const resetKeys = enableKeyPanel(el, readFile);
  window.addEventListener('pagehide', resetKeys);
  if (closedRun) {
    el('localNotice').hidden = false; el('localNotice').textContent = 'Bu kısa test veya kapalı bir oturum. Yeni yayın için anahtar hazırlayabilirsin; bu paketten bağlanamazsın.';
    say(el('localNotice').textContent, 'bad');
  } else {
    pack.disabled = el('reset').disabled = false;
    pack.addEventListener('change', () => { key.value = ''; key.disabled = el('keyRow').hidden = true; void refresh(); });
    key.addEventListener('change', refresh);
    target.addEventListener('input', checkTarget);
    for (const [id, kind] of [['copyInvite', 'invite'], ['copyEndpoint', 'endpoint'], ['copyRaw', 'raw'], ['copyHeader', 'header']]) el(id).addEventListener('click', () => copy(kind));
    el('reset').addEventListener('click', () => { resetKeys(); reset(); }); window.addEventListener('pagehide', reset); reset();
  }
}
