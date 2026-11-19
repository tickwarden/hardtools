// Shared by the packaging CLI and the offline browser. Public metadata is authenticated
// as AAD. Only encrypted invite/token bytes are embedded. No user-controlled algorithms.
const utf8 = new TextEncoder(), decode = b => new TextDecoder('utf-8', { fatal: true }).decode(b);
const endpointRE = /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com\/mcp$/;
const runRE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/actions\/runs\/[1-9][0-9]{0,19}$/;
const iterations = 600_000;
export const SECRET_NAME = 'HARDTOOLS_CONNECT_PASSWORD';
export const CARD_MARKER = '<meta name="hardtools-card" content="">';
function fail() { throw new Error('Bağlantı kartı geçersiz.'); }
export function validPassword(s) {
  return typeof s === 'string' && s.length >= 20 && s.length <= 256 && s === s.trim() && !/[\u0000-\u001f\u007f]/.test(s);
}
export function coordinates(m) {
  if (!m || m.v !== 2 || !['serve', 'check-connection'].includes(m.mode) || typeof m.number !== 'string' || !/^[1-9]\d{0,15}$/.test(m.number) || typeof m.endpoint !== 'string' || !endpointRE.test(m.endpoint) || typeof m.run !== 'string' || !runRE.test(m.run) || /\s/.test(m.number + m.endpoint + m.run)) fail();
  return { v: 2, number: m.number, mode: m.mode, endpoint: m.endpoint, run: m.run };
}
function checkedDetails(m, data) {
  if (!data || typeof data.token !== 'string' || !/^[0-9a-f]{64}$/.test(data.token) || data.token.length !== 64 || typeof data.invite !== 'string') fail();
  const prefix = m.endpoint.slice(0, -4) + '/invite/';
  if (!data.invite.startsWith(prefix) || !/^[A-Za-z0-9_.~-]{1,4096}$/.test(data.invite.slice(prefix.length)) || /\s/.test(data.invite)) fail();
  return { invite: data.invite, token: data.token, endpoint: m.endpoint, number: m.number };
}
const b64 = bytes => btoa(String.fromCharCode(...bytes));
function unb64(s, limit) {
  if (typeof s !== 'string' || !s.length || s.length > Math.ceil(limit / 3) * 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) fail();
  const b = Uint8Array.from(atob(s), c => c.charCodeAt(0));
  if (b.length > limit || b64(b) !== s) fail();
  return b;
}
async function aesKey(password, salt, use) {
  const raw = utf8.encode(password);
  try {
    const base = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, [use]);
  } finally { raw.fill(0); }
}
const params = (iv, m) => ({ name: 'AES-GCM', iv, tagLength: 128, additionalData: utf8.encode(JSON.stringify(coordinates(m))) });
export async function sealCard(meta, details, password) {
  const m = coordinates(meta);
  if (!validPassword(password)) throw new Error(SECRET_NAME + ': parola yöneticisinden en az 20 karakterlik, tek satırlık bir parola kullan.');
  const { invite, token } = checkedDetails(m, details);
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(password, salt, 'encrypt'), clear = utf8.encode(JSON.stringify({ invite, token }));
  try {
    const cipher = new Uint8Array(await crypto.subtle.encrypt(params(iv, m), key, clear));
    return { ...m, salt: b64(salt), iv: b64(iv), data: b64(cipher) };
  } finally { clear.fill(0); }
}
export function encodeCard(card) { return b64(utf8.encode(JSON.stringify(card))); }
export function decodeCard(s) {
  const c = JSON.parse(decode(unb64(s, 12288))), m = coordinates(c);
  if (unb64(c.salt, 16).length !== 16 || unb64(c.iv, 12).length !== 12 || unb64(c.data, 8192).length <= 16) fail();
  return { ...m, salt: c.salt, iv: c.iv, data: c.data };
}
export async function openCard(card, password) {
  const m = coordinates(card);
  if (m.mode !== 'serve' || !validPassword(password)) fail();
  const salt = unb64(card.salt, 16), iv = unb64(card.iv, 12), data = unb64(card.data, 8192);
  if (salt.length !== 16 || iv.length !== 12 || data.length <= 16) fail();
  const key = await aesKey(password, salt, 'decrypt');
  const clear = new Uint8Array(await crypto.subtle.decrypt(params(iv, m), key, data));
  try { return checkedDetails(m, JSON.parse(decode(clear))); } finally { clear.fill(0); }
}
