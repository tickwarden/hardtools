// Read-only compatibility for already-issued packages. New runs never write these formats.
import { Decrypter } from 'age-encryption';
import { unzipSync } from 'fflate';

const text = bytes => new TextDecoder().decode(bytes);
const unique = values => [...new Set(values)];
const hostPattern = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.trycloudflare\\.com';
const hostRe = new RegExp(`^${hostPattern}$`);
const endpointRe = new RegExp(`^https://${hostPattern}/mcp$`);
const inviteRe = new RegExp(`^https://${hostPattern}/invite/[A-Za-z0-9._~%=-]{1,4096}$`);
const isZip = b => b[0] === 0x50 && b[1] === 0x4b;
export const MAX_FILE = 2 * 1024 * 1024;
const MAX_MEMBER = 32 * 1024;
export class ReaderError extends Error {}
const fail = message => { throw new ReaderError(message); };

// Match what the user sees in the authorize tab. Never use a host hardcoded at build time.
export function targetMatches(input, endpoint) {
  const s = input.trim();
  let h;
  if (hostRe.test(s.toLowerCase())) h = s.toLowerCase();
  else {
    try {
      const u = new URL(s);
      if (u.protocol !== 'https:' || u.username || u.password || u.port || u.pathname !== '/authorize') return false;
      h = u.hostname;
    } catch { return false; }
  }
  return endpoint === `https://${h}/mcp`;
}

function members(bytes, names) {
  if (!bytes.length || bytes.length > MAX_FILE) fail('Dosya beklenen boyutta değil.');
  // Only read these small entries, never evaluate or extract the HTML in a selected ZIP.
  const selected = new Set();
  const files = unzipSync(bytes, { filter(entry) {
    if (!names.includes(entry.name)) return false;
    if (selected.has(entry.name) || entry.originalSize < 1 || entry.originalSize > MAX_MEMBER || entry.size > MAX_MEMBER) fail('Paket yapısı beklenenden farklı.');
    selected.add(entry.name); return true;
  } });
  return files;
}
const closed = s => /^(?:İPTAL EDİLDİ|SADECE TEST)\s*[—:-]/m.test(s) || /^HARDTOOLS MCP[^\n]*\(check-connection\)/m.test(s);
const runNo = s => s.match(/^HARDTOOLS MCP[^\n]*#(\d+)\b/m)?.[1] || '';

const signature = 'age-encryption.org/v1\n';
const basePrefix = 'YWdlLWVuY3J5cHRpb24ub3JnL3Yx';
function unpackText(s) {
  const begin = '-----BEGIN AGE ENCRYPTED FILE-----', end = '-----END AGE ENCRYPTED FILE-----';
  if (s.startsWith(begin)) {
    if (!s.endsWith(end)) fail('Şifreli metnin sonu eksik. Tam metni veya eski ZIP’i seç.');
    s = s.slice(begin.length, -end.length);
  } else if (!s.replace(/[\r\n \t]/g, '').startsWith(basePrefix)) return null;
  const body = s.replace(/[\r\n \t]/g, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body) || body.length % 4 === 1) fail('Şifreli metin eksik veya bozuk.');
  let decoded;
  try { decoded = atob(body); } catch { fail('Şifreli metin eksik veya bozuk.'); }
  if (decoded.length > MAX_MEMBER || !decoded.startsWith(signature) || !decoded.includes('\n--- ') || btoa(decoded).replace(/=+$/, '') !== body.replace(/=+$/, '')) fail('Geçerli bir eski age paketi değil.');
  return Uint8Array.from(decoded, c => c.charCodeAt(0));
}
export function pastedPacket(value) {
  if (typeof value !== 'string' || value.length > MAX_MEMBER * 2) fail('Şifreli metin çok büyük.');
  let s = value.trim();
  if (s.length > 1 && ["'", '"', '`'].includes(s[0]) && s.at(-1) === s[0]) s = s.slice(1, -1).trim();
  const cipher = unpackText(s);
  if (!cipher) fail('Buraya eski connect.txt içindeki şifreli metni yapıştır; token veya özel anahtar değil.');
  return connectionFile(cipher);
}

export function connectionFile(bytes) {
  if (!bytes.length || bytes.length > MAX_FILE) fail('Beklenen bağlantı paketini seç.');
  let data = bytes, guide = '';
  if (isZip(bytes)) {
    const files = members(bytes, ['connect.txt', 'BASLA-BURADAN.txt']);
    data = files['connect.txt'];
    if (!data) fail('Bağlantı alanına hardtools-connect.zip veya connect.txt dosyasını seç.');
    if (files['BASLA-BURADAN.txt']) guide = text(files['BASLA-BURADAN.txt']);
  }
  if (data.length > MAX_MEMBER) fail('connect.txt beklenenden büyük.');
  if (closed(guide)) fail('Bu kısa test veya kapalı bir oturum. Çalışan serve paketini seç.');
  let cipher;
  const s = text(data).trim();
  if (text(data.subarray(0, signature.length)) === signature) cipher = data;
  else cipher = unpackText(s);
  const ep = guide.split(/\r?\n/).map(l => l.trim()).find(l => endpointRe.test(l));
  if (!cipher) return { kind: 'plain', plain: s, endpoint: ep, number: runNo(guide) };
  const header = text(cipher.subarray(0, 4096)).split('\n--- ')[0];
  const kind = !/^-> X25519 /m.test(header) && /^-> ssh-(?:rsa|ed25519) /m.test(header) ? 'ssh' : 'age';
  return { kind, cipher, endpoint: ep, number: runNo(guide) };
}

export function getIdentity(bytes) {
  if (!bytes?.length) fail('Eşleşen özel anahtar dosyasını seç.');
  let data = bytes;
  if (isZip(bytes)) data = members(bytes, ['hardtools-key.txt'])['hardtools-key.txt'];
  if (!data || data.length > 4096) fail('hardtools-ozel-anahtar.zip veya içindeki hardtools-key.txt gerekiyor.');
  try {
    const ids = text(data).split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    if (ids.length !== 1 || !/^AGE-SECRET-KEY-1[A-Z0-9]{58}$/.test(ids[0])) fail('Tek bir geçerli age özel anahtarı seç (.pub değil).');
    return ids[0];
  } finally { if (data !== bytes) data.fill(0); }
}

export function parseDetails(s, binding = {}) {
  if (closed(s)) fail('Bu dosya bağlantı testi için oluşturuldu, canlı yayın değil.');
  const rows = s.split(/\r?\n/).map(l => l.trim());
  const endpoints = unique(rows.flatMap(l => /^(?:MCP Endpoint URL|URL):\s*(.*)$/i.exec(l)?.slice(1) || []));
  const invites = unique((s.match(/https:\/\/[^\s<>"']+/g) || []).filter(u => inviteRe.test(u)));
  const headers = rows.filter(l => /^Header value:/i.test(l));
  const token = headers.length === 1 && /^Header value:\s*Bearer\s+([0-9a-f]{64})$/i.exec(headers[0])?.[1];
  const number = runNo(s);
  if (endpoints.length !== 1 || !endpointRe.test(endpoints[0]) || invites.length !== 1 || !token || new URL(endpoints[0]).origin !== new URL(invites[0]).origin) fail('Pakette tutarlı bir davet, endpoint ve access token bulunamadı.');
  if ((binding.endpoint && binding.endpoint !== endpoints[0]) || (binding.number && number && binding.number !== number)) fail('Dosya bu oturumun adresi veya numarasıyla eşleşmiyor.');
  return { endpoint: endpoints[0], invite: invites[0], token, number: number || binding.number || '' };
}

export function packetBinding(packet, binding = {}) {
  if ((binding.endpoint && packet.endpoint && binding.endpoint !== packet.endpoint) || (binding.number && packet.number && binding.number !== packet.number)) fail('Bu ZIP farklı bir oturuma ait. Aynı run’ın dosyalarını kullan.');
  return { endpoint: binding.endpoint || packet.endpoint, number: binding.number || packet.number };
}

export async function unlock(packet, keyBytes, binding = {}) {
  const expected = packetBinding(packet, binding);
  if (packet.kind === 'ssh') fail('SSH alıcısı: eski ZIP’teki BASLA-BURADAN.txt içindeki age -d komutunu cihazında kullan.');
  if (packet.kind === 'plain') return parseDetails(packet.plain, expected);
  const d = new Decrypter(); d.addIdentity(getIdentity(keyBytes));
  const plain = await d.decrypt(packet.cipher);
  try { return parseDetails(text(plain), expected); } finally { plain.fill(0); }
}
