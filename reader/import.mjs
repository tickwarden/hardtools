// Only the generic reader imports files. Never load markup, scripts, or URLs from an archive.
import { unzipSync } from 'fflate';
import { connectionFile, MAX_FILE, ReaderError } from './legacy.mjs';
import { decodeCard } from './session.mjs';
const decoder = new TextDecoder(), MAX_HTML = 512 * 1024;
function readStamp(bytes) {
  const head = decoder.decode(bytes.subarray(0, 40000)).split('</head>')[0];
  const markers = [...head.matchAll(/<meta name="hardtools-card" content="([^"]*)">/g)];
  if (!markers.length) return null;
  if (markers.length !== 1 || !markers[0][1]) throw new ReaderError('Bu genel okuyucu; çalışan yayının hardtools-connect ZIP’ini seç.');
  return decodeCard(markers[0][1]);
}
export function importConnection(bytes) {
  if (!bytes?.length || bytes.length > MAX_FILE) throw new ReaderError('Geçerli bir bağlantı paketi seç.');
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
    let found = false;
    const page = unzipSync(bytes, { filter(entry) {
      if (entry.name !== 'BAGLAN.html') return false;
      if (found || entry.originalSize > MAX_HTML || entry.size > MAX_HTML || !entry.originalSize) throw new ReaderError('Paket yapısı geçersiz.');
      found = true; return true;
    } })['BAGLAN.html'];
    if (page) { const card = readStamp(page); if (card) return { card }; }
  } else if (/^\s*<!doctype html/i.test(decoder.decode(bytes.subarray(0, 40)))) {
    const card = readStamp(bytes); if (card) return { card };
    throw new ReaderError('Bu eski sayfada veri gömülü değil. Eski ZIP’i seç veya connect.txt metnini yapıştır.');
  }
  return { legacy: connectionFile(bytes) };
}
