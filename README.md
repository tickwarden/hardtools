# hardtools

Claude'un yerleşik dosya/arama/kabuk/web araçlarının **sınırlandırılmış, denetlenebilir** karşılıkları. Tek bir MCP sunucusu; Claude Code, Claude Desktop (stdio) ve uzak MCP (HTTP) üzerinden çalışır.

> **Durum:** v0.2.0, kod AI tarafından yazıldı (bkz. `CREDITS.md`). Otomatik testler var; bağımsız insan güvenlik incelemesi yapılmadı. Claude Code / Desktop / claude.ai içinde **gerçek yükleme burada denenmedi**; testler MCP SDK istemcisi ve ham HTTP ile yapıldı.

## Araçlar

| Araç | Yerleşik karşılığı | Ne ekliyor |
|---|---|---|
| `ht_read` | dosya okuma / `ls` | satır aralığı, eol/BOM bilgisi, `sha256` (düzenlemede `if_hash` olarak kullanılır), gizli dosyaları gizler |
| `ht_edit` | `str_replace` | **çok dosyalı atomik** düzenleme, ya hep ya hiç + geri alma, `dry_run` diff, eşzamanlı değişiklik tespiti, CRLF/BOM korunur, `$&` gibi dizilerde bozulma yok |
| `ht_write` | dosya yazma | asla üstüne yazmaz (`overwrite`+`if_hash` ister), atomik, gizli veri taraması |
| `ht_glob` | `find` | glob ile dosya/klasör listeler (`**/*.java`), symlink izlemez, gizli/korumalı dosyaları saklar, giriş/süre sınırı (`PARTIAL` olarak bildirilir), boyut+mtime verir |
| `ht_mkdir` | `mkdir -p` | kök içinde idempotent klasör oluşturma; `.git` içine oluşturmaz |
| `ht_move` | `mv` | **asla üstüne yazmaz** (hedef yoksa), symlink kaynağını/kökü/`.git`'i reddeder, kendi içine taşımayı reddeder, `mkdirp` |
| `ht_trash` | `rm` | **geri alınabilir silme**: `.ht-trash/` içine taşır, `index.jsonl`'a özgün yolu yazar; geri yükleme `ht_move` ile. Kalıcı silme aracı **bilerek yok** |
| `ht_search` | grep | regex/sabit, bağlam, glob, `.gitignore`, sonuç ve **süre** sınırı (ReDoS öldürülebilir worker'da) |
| `ht_shell` | bash | **kabuksuz argv**, blocklist (`shell.denyCommands`, allowlist YOK), argüman/yol denetimi, env'den gizli veri temizliği, süre aşımında süreç grubunu öldürme |
| `ht_fetch` | web fetch | SSRF korumalı (bağlantı anında IP doğrulama, her yönlendirmede yeniden doğrulama), boyut/süre/sıkıştırma-bombası limiti, `<untrusted_web_content>` sarmalı |
| `ht_status` | – | aktif politika + audit zinciri doğrulaması |

## Profiller

`strict` (en geniş blocklist + ağ istemcileri kapalı, `net.allowDomains` zorunlu, audit fail-closed; **artık default-deny değil**) · `balanced` (günlük geliştirme) · `open` (kabuk sözdizimi serbest; **sandbox değildir**).

Politika dosyası **yalnızca** `HARDTOOLS_CONFIG` veya `~/.hardtools/config.json` yolundan okunur, **asla çalışma alanından değil** (kötü niyetli bir repo kendi gevşek politikasını getiremesin). Bilinmeyen/typo anahtarlar hata verir. Örnek: `hardtools.config.example.json`. Öncelik: `--profile` > `HARDTOOLS_PROFILE` > dosya > `balanced`.

## Kurulum

```bash
npm ci && npm test               # kilitli bağımlılıklar + testler (derleme dahil)
npm run bundle                   # bundle/index.js (node_modules gerekmez)
```

### Claude Code (plugin)
Klasörü plugin olarak yükle (`.claude-plugin/plugin.json` + `.mcp.json` hazır; sunucu `${CLAUDE_PLUGIN_ROOT}/bundle/index.js` ile başlar). Yerelde denemek için `claude --plugin-dir ./hardtools`; yükleme sorunlarında `claude --debug`. Kök dizin = sunucunun çalışma dizini; `/` veya ev dizini olursa **başlamayı reddeder**.
**Önemli:** yerleşik `Bash/Edit/Write/WebFetch` kapatılmazsa Claude onları kullanmaya devam eder ve bu eklenti güvenliği artırmaz, sadece seçenek ekler. `claude-code-settings.example.json`'a bak (sözdizimini sürümünde doğrula).

### Claude Desktop (stdio)
`claude_desktop_config.example.json` içeriğini Desktop'un MCP yapılandırmasına ekle. Desktop'ta çalışma dizini proje olmadığı için `HARDTOOLS_ROOTS` **zorunlu** pratikte.

### İlk kullanım: Windows’ta `age-keygen.exe` olmadan anahtar al

Bir yayına yalnızca davetle katılıyorsan özel anahtara ihtiyacın yok. Kendi şifreli bağlantı paketini alacaksan **`serve` başlatmadan önce** [**BAGLAN.html**](bundle/BAGLAN.html) dosyasını repodan **Download raw file (↓)** ile indir ve bilgisayarında Edge, Chrome veya Firefox ile aç. Bu adım için henüz bir artifact gerekmez.

- **Anahtarın yoksa:** **Anahtar işlemleri → Yeni anahtar oluştur → hardtools-key.txt indir**. Bu, `age-keygen -o hardtools-key.txt` karşılığıdır. TXT’yi güvenli bir yerde sakla; ZIP yapman gerekmez. Önceki bir anahtarın üstüne yazma.
- **Anahtarın varsa:** **Anahtarım var** altında kendi TXT’ni veya eski `hardtools-ozel-anahtar.zip` dosyanı seç. `age-keygen -y hardtools-key.txt` gibi, mevcut özel anahtardan açık anahtar hesaplanır; dosyan değişmez.
- **Açık anahtarı kopyala:** `age1…` ile başlayan değeri aşağıdaki `age_recipient` alanına gir. Özel TXT’yi yükleme. Yeni anahtar eski bir paketi açmaz; ayar sonraki çalıştırma içindir.

### GitHub Actions: job bitmeden bağlanma

1. **Actions → hardtools MCP → Run workflow** menüsünde varsayılan **`serve`** seçili kalsın.
   Actions listesinde bu çalıştırma **MCP yayını (serve)** olarak görünür. Elle başlatılan
   yayın, ilk bağlantıyı beklerken de açık kalır. `auto_renew` varsayılan olarak kapalıdır:
   normal kapanış yaklaşık 5 saat 45 dakika sonradır. `push` ve PR olayları MCP yayını açmaz.
   Public repoda
   `age_recipient` alanına **kendi açık anahtarını** gir (`age1…` veya `.pub` dosyandaki
   `ssh-ed25519 …` / `ssh-rsa …` satırı). İstersen bir kez `HARDTOOLS_AGE_RECIPIENT`
   adlı **repository variable** olarak kaydet. Özel anahtarını GitHub'a yükleme.
   Private repoda hem girdi hem repo değişkeni boşsa repo okuyucuları bağlantı dosyasını düz metin olarak indirebilir.
2. Çalışan run’dan **Artifacts → hardtools-connect** ZIP’ini indir. Windows’ta **Tümünü ayıkla**, sonra **`BAGLAN.html`** dosyasını bilgisayarında Edge, Chrome veya Firefox ile aç. Aynı klasördeki `connect.txt` dosyasını (veya inen ZIP’i) seç. Şifreliyse **kendi** `hardtools-ozel-anahtar.zip` veya `hardtools-key.txt` dosyanı seç. `age1…` alıcısında kurulum, terminal, Summary veya canlı log gerekmez. Okuyucu ağa bağlanmaz ve dosyaları yüklemez. **SSH alıcısı** için `BASLA-BURADAN.txt` içindeki yerel `age -d` yolunu kullan; düz metin private pakette anahtar istenmez.
3. İhtiyacına göre doğru değeri kopyala:

   | Nereye? | `BAGLAN.html` içinde neyi seçmelisin? |
   |---|---|
   | Claude ile aynı tarayıcı profili | **Daveti kopyala**. Adresi bir kez aç, 10 dakika içinde Claude’dan bağlan. |
   | Claude → Settings → Connectors → Add custom connector → URL | **/mcp adresini kopyala**. Ad: `hardtools`; OAuth client ID ve secret boş. |
   | Yetkilendirme sayfasındaki **Access token** kutusu | Okuyucuda bu bölümü aç ve sayfanın alan adını veya tam `/authorize` adresini gir. Eşleşirse **Access token’ı kopyala**; kutuya `Bearer` yazmadan yapıştır. |
   | Header destekleyen istemci → `Authorization` değeri | **Header değerini kopyala**. Burada `Bearer ` öneki dahildir. |

   `BASLA-BURADAN.txt` tam endpointi, durum bağlantısını ve terminal alternatifini içerir. Okuyucu daveti kendiliğinden açmaz, yeni token üretmez ve run’ın canlılığını sorgulamaz. Eski bir run kapandıysa yeni run’ın ZIP’i gerekir. Okuyucusuz eski bir **çalışan** run için repodaki `bundle/BAGLAN.html` dosyasını indirip kendi bilgisayarında açabilir, o run’ın ZIP’ini seçebilirsin. Özel anahtarını, davetini veya token’ını paylaşma.

**Kısa doğrulama bir yayın değildir.** `check-connection`, artifact'ı job sürerken geri
indirip karşılaştırır ve tünelin MCP adresini doğrular; sonra **bilerek kapanır**.
Bu testin URL'sini Claude'a ekleme. Eski testte **Re-run jobs** yine test çalıştırır;
gerçek bir oturum için **Run workflow → serve** kullan.

### Uzak / HTTP modu (web dahil: **sınırlı**)
```bash
export HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)
node bundle/index.js --http --port 8787 --profile balanced      # 127.0.0.1'e bağlanır
```
- A static bearer token (`Authorization: Bearer <HARDTOOLS_HTTP_TOKEN>`) works for **Claude Code / Desktop** (they can send headers).
- **claude.ai web / Claude app**: the custom-connector dialog cannot send headers, so the server speaks a minimal stateless **OAuth 2.1** (RFC 9728 + RFC 8414 discovery, RFC 7591 dynamic client registration, PKCE S256). Add the connector with the `/mcp` URL and leave the OAuth client fields empty; a consent page opens and asks for `HARDTOOLS_HTTP_TOKEN`. Only someone holding that secret can obtain tokens (access tokens live 1 h, refresh tokens 12 h; everything dies when the server restarts with a new secret). Redirect URIs are limited to `https://claude.ai|claude.com/api/mcp/auth_callback` and loopback; add more with `HARDTOOLS_OAUTH_REDIRECT_URIS` (comma-separated, exact match).
- Verified with this repo's tests and the official MCP SDK OAuth client; **not yet verified against the live claude.ai dialog**.
- Uzak modda `ht_shell` ve yazma araçları varsayılan **kapalı** (sunucunun dosya sistemi senin makinen değil). Açmak: `HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=1` (önerilmez). TLS sonlandırma (ters vekil/tünel) senin sorumluluğunda; Host doğrulaması için `HARDTOOLS_ALLOWED_HOSTS=alanadi.com`.

## Bilinen sınırlar (özet; ayrıntı `SECURITY.md`)
Windows'ta `ht_shell` yalnızca `.exe` çalıştırır (`.cmd` shim yok), süreç ağacı `taskkill` ile öldürülür; asıl hedef Linux/macOS/WSL. `balanced` içindeki `npm test` gibi komutlar **proje betiklerini** çalıştırır. `open` profili sandbox değildir. Yol denetimi check-then-use (TOCTOU) artığı taşır.
