import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { CARD_MARKER, decodeCard, encodeCard, sealCard, SECRET_NAME, validPassword } from '../reader/session.mjs';

export async function makePage(meta, details, password) {
  const template = await readFile(new URL('../bundle/BAGLAN.html', import.meta.url), 'utf8');
  if (template.split(CARD_MARKER).length !== 2) throw Error('Tek dosyalık şablon geçersiz.');
  const card = await sealCard(meta, details, password);
  return template.replace(CARD_MARKER, `<meta name="hardtools-card" content="${encodeCard(card)}">`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const password = process.env.CONNECT_PASSWORD;
  if (process.argv[2] === '--verify-check') {
    try {
      const [path, ep, run, num] = process.argv.slice(3);
      const head = (await readFile(path,'utf8')).slice(0,40000).split('</head>')[0];
      const stamp = head.match(/<meta name="hardtools-card" content="([A-Za-z0-9+/=]+)">/);
      const c = decodeCard(stamp?.[1]);
      if (c.mode !== 'check-connection' || c.endpoint !== ep || c.run !== run || c.number !== num) throw Error();
    } catch { console.error('::error::İndirilen kart bu testin endpointi ve run bilgileriyle eşleşmiyor.'); process.exitCode = 1; }
  } else if (!validPassword(password)) {
    console.error(`::error::Repo yöneticisi: Settings → Secrets and variables → Actions → New repository secret. ${SECRET_NAME} için 20–256 karakterlik güçlü, tek satırlık bir parola kaydet (başta/sonda boşluk olmasın). Parolayı workflow girdisine veya loga yazma.`);
    process.exitCode = 1;
  } else if (process.argv[2] !== '--check-password') {
    try {
      const [output, endpoint, run, number, mode] = process.argv.slice(2);
      const chunks = []; let size = 0;
      for await (const b of process.stdin) { if ((size += b.length) > 8192) throw Error(); chunks.push(b); }
      const rows = Buffer.concat(chunks).toString('utf8').split('\n');
      if (rows.length !== 3 || rows[2] !== '') throw Error();
      const html = await makePage({ v: 2, endpoint, run, number, mode }, { invite: rows[0], token: rows[1] }, password);
      await writeFile(output, html, { mode: 0o600, flag: 'wx' });
    } catch { console.error('::error::Bağlantı sayfası oluşturulamadı. Özel değerler günlüğe yazılmadı.'); process.exitCode = 1; }
  }
}
