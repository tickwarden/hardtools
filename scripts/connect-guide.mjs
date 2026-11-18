import { pathToFileURL } from 'node:url';

// This file is PUBLIC, even when connect.txt is encrypted. Only accept the
// credential-free /mcp endpoint and GitHub's run coordinates, never the invite/token.
export function renderGuide(endpoint, runUrl, runNumber, mode, delivery) {
  if (typeof endpoint !== 'string' || !/^https:\/\/[a-z0-9-]+\.trycloudflare\.com\/mcp$/.test(endpoint) || /\s/.test(endpoint)) throw new Error('Geçersiz herkese açık MCP adresi.');
  if (typeof runUrl !== 'string' || !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/actions\/runs\/[1-9]\d*$/.test(runUrl) || /\s/.test(runUrl)) throw new Error('Geçersiz GitHub run adresi.');
  if (!/^[1-9]\d*$/.test(runNumber) || /\s/.test(runNumber)) throw new Error('Geçersiz çalıştırma numarası.');
  if (!['serve', 'check-connection', 'cancelled'].includes(mode) || !['age', 'plain'].includes(delivery)) throw new Error('Bilinmeyen teslim biçimi.');
  const workflow = runUrl.split('/actions/runs/')[0] + '/actions/workflows/hardtools-mcp.yml';
  const status = {
    serve: 'YAYIN (serve) — Bu adres yalnızca bu oturum çalışırken geçerlidir.',
    'check-connection': "SADECE TEST — Bu adresi Claude'a ekleme. Kontrol bitince tünel kapanır.",
    cancelled: 'İPTAL EDİLDİ — Bu oturum kapalıdır. Aşağıdaki eski adres ve davetle bağlanamazsın.',
  }[mode];
  const unlock = delivery === 'plain' ? `connect.txt bu private repo için düz metin olarak oluşturuldu. Dosyayı kendi
bilgisayarında bir metin düzenleyiciyle aç. Özel anahtar veya age gerekmez.
Dosyayı repo okuyucuları da indirebilir; içeriğini paylaşma.` : `connect.txt şifrelidir. Bu dosya ile alıcıya ait ÖZEL anahtarı kendi
bilgisayarında kullan; bir web sitesine yükleme. hardtools-ozel-anahtar.zip
kullanıyorsan içindeki hardtools-key.txt dosyasını connect.txt ile aynı
klasöre çıkar. ZIP'in içinden değil, çıkardığın klasörden çalıştır.

Windows / PowerShell (age.exe aynı klasördeyse):
  .\\age.exe -d -i .\\hardtools-key.txt .\\connect.txt
macOS / Linux veya age PATH üzerinde ise:
  age -d -i hardtools-key.txt connect.txt

Alıcı olarak SSH açık anahtarı verdiysen onun eşleşen ÖZEL anahtarını kullan:
  age -d -i "$HOME/.ssh/id_ed25519" connect.txt
Anahtarının adı farklıysa -i sonrasındaki yolu değiştir; .pub dosyası şifre çözmez.
age yüklü değilse resmi indirme: https://github.com/FiloSottile/age/releases
Windows'ta indirdiğin paketten age.exe'yi çıkar. Komut sonucu yalnızca kendi
terminalinde görünsün: çıktıda gerçek davet ve bearer token bulunur.`;
  return `HARDTOOLS MCP | BAĞLANTI KILAVUZU | #${runNumber}
${status}

MCP ENDPOINT URL — Claude'daki URL alanına gireceğin adres:
${endpoint}

1. DAVETİ VEYA TOKEN'I OKU
${unlock}

2. CLAUDE WEB'E BAĞLAN (yalnızca açık bir serve oturumu için)
• connect.txt içindeki tek kullanımlık davet URL'sini önce Claude için
  kullandığın tarayıcı profilinde aç. Daveti başkasına gönderme.
• Claude → Settings → Connectors → Add custom connector.
• Name: hardtools
• URL: yukarıdaki /mcp ile biten MCP ENDPOINT URL (davet URL'si değil).
• OAuth client ID ve OAuth client secret: boş bırak. Devam et ve yetkilendirmeyi tamamla.

3. HEADER DESTEKLEYEN MCP İSTEMCİLERİ (örn. Claude Code)
Aynı MCP endpointini kullan. Header name: Authorization.
Header value: connect.txt içindeki “Bearer …” değerinin tamamı. Davet gerekmez.
Bearer token'ı URL'ye ekleme. Özel anahtar, davet ve token loga veya sohbete yazılmaz.

4. OTURUM / SORUN GİDERME
Durum: ${runUrl}
Bu ZIP canlı durumu güncellemez. Run bittiğinde veya iptal edildiğinde tünel kapanır.
Yeni oturum: ${workflow}
Run workflow → main → serve. Yeni run'dan yeni hardtools-connect ZIP'ini indir.
Eski davet veya endpointi yeniden kullanma. Boş age_recipient, tanımlıysa
HARDTOOLS_AGE_RECIPIENT repo değişkenini kullanır. “No identity matched” hatası
anahtarın bu ZIP'in alıcısıyla eşleşmediğini gösterir.

Bu ZIP'teki rehber ve connect.txt yeterlidir; Summary veya canlı log gerekmez.
`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.stdout.write(renderGuide(...process.argv.slice(2)));
}
