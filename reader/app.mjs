import { decodeCard, openCard } from './session.mjs';
import { importConnection } from './import.mjs';
import { MAX_FILE, pastedPacket, ReaderError, targetMatches, unlock as unlockOld } from './legacy.mjs';

const $ = id => document.getElementById(id);
const show = (id, yes = true) => { $(id).hidden = !yes; };
const note = (msg, bad = false) => { $('status').textContent = msg; $('status').className = bad ? 'bad' : ''; };
let embedded = null, card = null, old = null, values = null, epoch = 0, copyEpoch = 0;
function eraseManual() { ++copyEpoch; $('manual').value = ''; show('manualBox', false); }
function clear() {
  ++epoch; eraseManual(); old?.cipher?.fill(0); old = card = values = null;
  for (const id of ['password', 'key', 'pack', 'paste', 'target']) $(id).value = '';
  for (const id of ['picker', 'locked', 'oldKey', 'results', 'advanced', 'endpointBox', 'runInfo', 'reset']) show(id, false);
  for (const id of ['password', 'unlock', 'key', 'pack', 'paste', 'loadText', 'copyRaw']) $(id).disabled = true;
  $('endpoint').textContent = $('match').textContent = ''; $('runInfo').replaceChildren();
  $('oldText').open = $('extra').open = false;
}
function endpoint(ep, step = false) {
  $('endpoint').textContent = ep; $('epLabel').textContent = step ? '2 · Claude' : 'Genel bağlantı bilgisi'; show('endpointBox');
}
function useCard(c) {
  card = c; $('intro').textContent = `Run #${c.number} · Bu sayfa yalnızca bu yayına ait.`;
  show('picker', false); show('runInfo');
  const a = document.createElement('a'); a.href = c.run; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = `GitHub’da #${c.number} durumunu gör`; $('runInfo').replaceChildren(a);
  if (c.mode !== 'serve') { note('Bu kısa bağlantı testi bir yayın değil. Bağlanmak için bir serve oturumu gerekiyor.', true); show('reset', !embedded); return; }
  endpoint(c.endpoint); show('locked'); show('reset', !embedded);
  $('password').disabled = $('unlock').disabled = false;
  note('Paket hazır. Aşağıya bağlantı parolanı yaz.');
}
function start() {
  clear();
  if (embedded) { useCard(embedded); return; }
  $('intro').textContent = 'Paketini seç veya ZIP’teki BAGLAN.html dosyasını aç. Yeni yayınlarda yalnızca bağlantı parolası gerekir.';
  show('picker'); $('pack').disabled = $('paste').disabled = $('loadText').disabled = false;
  note('Bağlantı verileri başka bir yere gönderilmez.');
}
function ready(data) {
  values = data; $('password').value = $('key').value = ''; $('password').disabled = $('unlock').disabled = $('key').disabled = true;
  show('picker', false); show('oldKey', false); show('locked', false); show('results'); show('advanced'); show('reset'); endpoint(data.endpoint, true);
  $('intro').textContent = `${data.number ? 'Run #' + data.number + ' · ' : ''}${new URL(data.endpoint).hostname}`;
  note('Bağlantı bilgileri açıldı. Daveti kopyalamak onu tüketmez.');
}
async function read(file) {
  if (!file?.size || file.size > MAX_FILE) throw new ReaderError('Beklenen küçük bağlantı veya anahtar dosyasını seç.');
  return new Uint8Array(await file.arrayBuffer());
}
async function load(file, pasted) {
  start(); const n = epoch; let bytes;
  try {
    let source;
    if (file) { bytes = await read(file); if (n !== epoch) return; source = importConnection(bytes); }
    else source = { legacy: pastedPacket(pasted) };
    if (source.card) { useCard(source.card); return; }
    old = source.legacy;
    if (old.kind === 'ssh') throw new ReaderError('Bu eski paket SSH alıcısına şifreli. Eski ZIP’in BASLA-BURADAN.txt dosyasındaki yerel age -d yolunu kullan.');
    if (old.kind === 'plain') { const data = await unlockOld(old); if (n === epoch) ready(data); return; }
    if (old.cipher === bytes) old.cipher = bytes.slice();
    show('picker', false); show('oldKey'); show('reset'); $('key').disabled = false;
    note('Şifreli eski paket tanındı. Yalnızca o paketin özel anahtarıyla açılır.');
  } catch (e) { if (n === epoch) { start(); note(e instanceof ReaderError ? e.message : 'Paket okunamadı. Çalışan oturumun ZIP’ini veya tam şifreli metni kullan.', true); } }
  finally { bytes?.fill(0); }
}
async function passwordUnlock() {
  if (!card || $('unlock').disabled) return;
  const p = $('password').value; $('password').value = '';
  if (/^(?:YWdlLWVuY3J5|-----BEGIN AGE|AGE-SECRET-KEY-)/.test(p.trim())) { note('Bu bir bağlantı parolası değil. Eski şifreli metni genel BAGLAN.html’de “Eski connect.txt metnini yapıştır” ile aç.', true); return; }
  const n = ++epoch; $('unlock').disabled = $('password').disabled = true; note('Paket bu cihazda açılıyor…');
  try { const data = await openCard(card, p); if (n === epoch) ready(data); }
  catch { if (n === epoch) { $('unlock').disabled = $('password').disabled = false; $('password').focus(); note('Paket açılamadı. Bu yayın için belirlenen bağlantı parolasını kontrol et.', true); } }
}
async function oldUnlock() {
  if (!old) return;
  const n = ++epoch, file = $('key').files[0]; let b;
  try { b = await read(file); if (n !== epoch) return; const data = await unlockOld(old, b); if (n === epoch) ready(data); }
  catch (e) { if (n === epoch) { $('key').value = ''; note(e instanceof ReaderError ? e.message : 'Bu özel anahtar eski paketi açmadı. O çalıştırmaya ait anahtarı seç; yeni anahtar üretme.', true); } }
  finally { b?.fill(0); }
}
function matches() { return !!values && targetMatches($('target').value, values.endpoint); }
async function copy(kind) {
  eraseManual(); const n = copyEpoch;
  const s = kind === 'endpoint' ? (values?.endpoint || (card?.mode === 'serve' && card.endpoint)) : kind === 'invite' ? values?.invite : kind === 'raw' && matches() ? values.token : kind === 'header' && values ? 'Bearer ' + values.token : '';
  if (!s) return;
  try { await navigator.clipboard.writeText(s); if (n === copyEpoch) note(({ endpoint: 'MCP adresi kopyalandı. Connector URL alanına yapıştır.', invite: 'Davet kopyalandı; henüz açılmadı.', raw: 'Yalın token kopyalandı. Eşleşen Access token kutusuna yapıştır.', header: 'Authorization değeri Bearer önekiyle kopyalandı.' })[kind]); }
  catch { if (n === copyEpoch) { $('manual').value = s; show('manualBox'); $('manual').focus(); $('manual').select(); note('Seçili metni Ctrl+C (Mac: ⌘C) ile kopyala.'); } }
}
function init() {
  if (location.protocol !== 'file:' || self !== top) { note('Önizleme: dosyayı indirip kendi bilgisayarında aç. Burada parola veya dosya istenmez.'); return; }
  if (!globalThis.crypto?.subtle) { note('Bu tarayıcı yerel şifre çözmeyi desteklemiyor. Güncel Edge, Chrome veya Firefox kullan.', true); return; }
  const stamp = document.querySelector('meta[name=hardtools-card]').content;
  if (stamp) { try { embedded = decodeCard(stamp); } catch { note('Bu bağlantı kartı bozuk. Güvenilir run’dan yeniden indir.', true); return; } }
  $('pack').addEventListener('change', () => { const f = $('pack').files[0]; if (f) void load(f); });
  $('loadText').addEventListener('click', () => load(null, $('paste').value)); $('key').addEventListener('change', oldUnlock);
  $('unlock').addEventListener('click', passwordUnlock); $('password').addEventListener('keydown', e => { if (e.key === 'Enter') void passwordUnlock(); });
  $('target').addEventListener('input', () => { eraseManual(); const ok = matches(); $('copyRaw').disabled = !ok; $('match').textContent = ok ? 'Oturum adresi eşleşti.' : $('target').value ? 'Adres bu oturumla eşleşmedi.' : ''; });
  for (const [id, kind] of [['copyInvite','invite'],['copyEndpoint','endpoint'],['copyRaw','raw'],['copyHeader','header']]) $(id).addEventListener('click', () => copy(kind));
  $('reset').addEventListener('click', start); window.addEventListener('pagehide', clear); window.addEventListener('pageshow', e => { if (e.persisted) start(); }); start();
}
init();
