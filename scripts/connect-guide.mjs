import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

// Public even when connect.txt is encrypted. Never pass an invite, token or key here.
export function renderGuide(endpoint, runUrl, runNumber, mode, delivery) {
  if (typeof endpoint !== 'string' || !/^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com\/mcp$/.test(endpoint) || /\s/.test(endpoint)) throw new Error('Geçersiz herkese açık MCP adresi.');
  if (typeof runUrl !== 'string' || !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/actions\/runs\/[1-9]\d*$/.test(runUrl) || /\s/.test(runUrl)) throw new Error('Geçersiz GitHub run adresi.');
  if (!/^[1-9]\d*$/.test(runNumber) || /\s/.test(runNumber)) throw new Error('Geçersiz çalıştırma numarası.');
  if (!['serve', 'check-connection', 'cancelled'].includes(mode) || !['age', 'plain'].includes(delivery)) throw new Error('Bilinmeyen teslim biçimi.');
  const workflow = runUrl.split('/actions/runs/')[0] + '/actions/workflows/hardtools-mcp.yml';
  const status = {
    serve: 'YAYIN (serve) — Bu adres yalnızca bu oturum çalışırken geçerlidir.',
    'check-connection': "SADECE TEST — Bu adresi Claude'a ekleme. Kontrol bitince tünel kapanır.",
    cancelled: 'İPTAL EDİLDİ — Bu oturum kapalıdır. Aşağıdaki eski adres ve davetle bağlanamazsın.',
  }[mode];
  const unlock = delivery === 'plain' ? `connect.txt bu private repo için düz metin. Okuyucuda yalnızca bu dosyayı seç;
anahtar gerekmez. Bir metin düzenleyiciyle de açabilirsin. Repo okuyucuları da
indirebilir; içeriğini paylaşma.` : `connect.txt şifrelidir. Okuyucuda bu dosyayı, ardından kendi
hardtools-key.txt dosyanı (veya önceki hardtools-ozel-anahtar.zip dosyanı) seç.
Elinde bir anahtar varsa “Anahtar işlemleri → Anahtarım var” bölümünde açık
anahtarını görebilirsin. İlk kez başlıyorsan repodaki bundle/BAGLAN.html’yi
indirip yerelde aç: “Yeni anahtar oluştur” → “hardtools-key.txt indir”. Açık
age1… değerini YENİ serve çalıştırmasının age_recipient alanına gir. Yeni bir
anahtar bu ZIP’in mevcut şifresini açmaz.
age1… alıcısı için Windows’ta paket kurman gerekmez. Eşleşen ÖZEL anahtar
sende kalır. Anahtar yerine .pub seçme; hiçbir dosyayı bir siteye yükleme.

SSH alıcısı mı kullandın? Okuyucu SSH özel anahtarı istemez. Resmi age aracıyla
kendi bilgisayarında aç: age -d -i "$HOME/.ssh/id_ed25519" connect.txt
Windows’ta örnek: .\\age.exe -d -i "$HOME\\.ssh\\id_ed25519" .\\connect.txt
Anahtarın adı farklıysa -i sonrasındaki yolu değiştir.
age özel anahtarı için isteğe bağlı terminal yolu:
  Windows: .\\age.exe -d -i .\\hardtools-key.txt .\\connect.txt
  macOS/Linux: age -d -i hardtools-key.txt connect.txt
Resmi indirme: https://github.com/FiloSottile/age/releases`;
  return `HARDTOOLS MCP | BAĞLANTI KILAVUZU | #${runNumber}
${status}

MCP ENDPOINT URL — Claude’daki URL alanına gireceğin adres:
${endpoint}

1. DOSYALARI KENDİ BİLGİSAYARINDA AÇ
hardtools-connect.zip için “Tümünü ayıkla” seç. Çıkan BAGLAN.html dosyasını
Edge, Chrome veya Firefox’ta aç (GitHub önizlemesinde değil).
${unlock}

2. CLAUDE WEB: DAVET VE CONNECTOR AYRI ALANLARDIR
• “Daveti kopyala”: bu URL’yi Claude ile aynı tarayıcı profilinde bir kez aç.
  Kopyalamak daveti tüketmez; açmak tüketir. 10 dakika içinde Claude’dan bağlan.
• Claude → Settings → Connectors → Add custom connector. Name: hardtools.
• URL: “/mcp adresini kopyala”. Yukarıdaki endpointi kullan, daveti değil.
• OAuth client ID ve OAuth client secret: boş bırak.
• “Access token” kutusu açıldıysa: BAGLAN.html’de bu başlığı genişlet. Sayfanın
  adres çubuğundaki alan adını veya tam /authorize adresini gir. Eşleşirse
  “Access token’ı kopyala” → giriş kutusuna yapıştır → Authorize. Yalnızca
  yalın token gerekir; Bearer, davet, şifreli metin ve özel anahtar girilmez.
  Terminal kullandıysan “Header value: Bearer …” satırının yalnızca Bearer
  sözcüğünden sonraki kısmını kullan.

3. HEADER DESTEKLEYEN İSTEMCİLER
URL aynı /mcp endpointidir. Header name: Authorization.
“Header değerini kopyala” ile Bearer öneki DAHİL tam değeri al. Web giriş
kutusundan farklıdır. Token’ı URL’ye ekleme.

4. ÇALIŞTIRMA / SORUN GİDERME
Durum: ${runUrl}
Bu ZIP canlı durumu sorgulamaz. “Wrong access token” görüyorsan eski run’ın
bilgilerini kullanmadığını ve Bearer yazmadığını kontrol et. Daveti zaten
açtıysan aynı profilde Claude’dan yeniden bağlan; daveti tekrar açmana gerek yok.
Run bittiyse tünel kapanır; adres ve token yeni oturumda değişir.
Yeni oturum: ${workflow}
Run workflow → main → serve. Yeni run’ın hardtools-connect ZIP’ini indir.
${delivery === 'age' ? 'Anahtar eşleşmiyorsa bu run’ın age_recipient alıcısına (veya varsayılan\nHARDTOOLS_AGE_RECIPIENT repo değişkenine) ait özel anahtarı kullan.\n' : ''}
Summary veya canlı log gerekmez. Daveti, token’ı ve özel anahtarını paylaşma.
`;
}

const marker = '<meta name="hardtools-run" content="" data-mode="" data-endpoint="">';
export async function writePublicFiles(dir, endpoint, runUrl, number, mode, delivery) {
  const guide = renderGuide(endpoint, runUrl, number, mode, delivery); // validates all substitutions
  const template = await readFile(new URL('../bundle/BAGLAN.html', import.meta.url), 'utf8');
  if (template.split(marker).length !== 2) throw new Error('Okuyucu şablonu eksik veya geçersiz.');
  const page = template.replace(marker, `<meta name="hardtools-run" content="${number}" data-mode="${mode}" data-endpoint="${endpoint}">`);
  await Promise.all([writeFile(join(dir, 'BASLA-BURADAN.txt'), guide), writeFile(join(dir, 'BAGLAN.html'), page)]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await writePublicFiles(...process.argv.slice(2));
}
