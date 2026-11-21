# hardtools

Claude'un yerleşik dosya/arama/kabuk/web araçlarının **sınırlandırılmış, denetlenebilir** karşılıkları. Tek bir MCP sunucusu; Claude Code, Claude Desktop (stdio) ve uzak MCP (HTTP) üzerinden çalışır.

> **Durum:** v0.3.0, kod AI tarafından yazıldı (bkz. `CREDITS.md`). Otomatik testler var; bağımsız insan güvenlik incelemesi yapılmadı. Claude Code / Desktop / claude.ai içinde **gerçek yükleme burada denenmedi**; testler MCP SDK istemcisi ve ham HTTP ile yapıldı.

## Araçlar

| Araç | Yerleşik karşılığı | Ne ekliyor |
|---|---|---|
| `ht_read` | dosya okuma / `ls` | satır aralığı, eol/BOM bilgisi, `sha256` (düzenlemede `if_hash` olarak kullanılır), korumalı dosyaları listede gizler |
| `ht_edit` | `str_replace` | **çok dosyalı atomik** düzenleme, ya hep ya hiç + geri alma, `dry_run` diff, eşzamanlı değişiklik tespiti, CRLF/BOM korunur, `$&` gibi dizilerde bozulma yok |
| `ht_write` | dosya yazma | varsayılan olarak üzerine yazmaz (`balanced`/`strict`: `overwrite`+`if_hash`), atomik, gizli veri taraması |
| `ht_glob` | `find` | glob ile dosya/klasör listeler (`**/*.java`), symlink izlemez, gizli/korumalı dosyaları saklar, giriş/süre sınırı (`PARTIAL` olarak bildirilir), boyut+mtime verir |
| `ht_mkdir` | `mkdir -p` | kök içinde idempotent klasör oluşturma; `.git` içine oluşturmaz |
| `ht_move` | `mv` | **asla üstüne yazmaz** (hedef yoksa), symlink kaynağını/kökü/`.git`'i reddeder, kendi içine taşımayı reddeder, `mkdirp` |
| `ht_trash` | `rm` | **geri alınabilir silme**: `.ht-trash/` içine taşır, `index.jsonl`'a özgün yolu yazar; geri yükleme `ht_move` ile; kalıcı boşaltma ayrı onay ister |
| `ht_empty_trash` | çöpü boşalt | varsayılanı yalnızca önizleme; `confirm:true` ile sadece seçili kökün çöp içeriğini ve indeksini siler |
| `ht_search` | grep | regex/sabit, bağlam, glob, `.gitignore`, sonuç ve **süre** sınırı (ReDoS öldürülebilir worker'da) |
| `ht_shell` | bash | **kabuksuz argv**, blocklist (`shell.denyCommands`, allowlist YOK), argüman/yol denetimi, env'den gizli veri temizliği, süre aşımında süreç grubunu öldürme |
| `ht_add_var` / `ht_list_vars` / `ht_delete_var` | oturum değişkenleri | isim/değer tanımla, yalnız adları listele veya tek adı kaldır; seçilen değerler `ht_shell` alt sürecine gider |
| `ht_share` | kullanıcıya dosya ver | süreli indirme bağlantısı veya MCP dosya eki, özel çalışma klasörü, SHA-256, yeniden adlandırma, listeleme ve iptal |
| `ht_image_search` | görsel arama | Wikimedia Commons araması, gerçek küçük resimler, boyut/yön/tür seçimi, sayfalama, kaynak ve lisans bilgisi |
| `ht_fetch` | web fetch | SSRF korumalı (bağlantı anında IP doğrulama, her yönlendirmede yeniden doğrulama), boyut/süre/sıkıştırma-bombası limiti, `<untrusted_web_content>` sarmalı |
| `ht_status` | – | aktif politika + audit zinciri doğrulaması |

## Yeni araçları dene

### `ht_shell` ve oturum değişkenleri

Örnek sıra: `ht_add_var` → `{"name":"APP_TEAM","value":"aydın"}`; ardından `ht_shell` → `{"argv":["printenv","APP_TEAM"],"inherit_vars":["APP_TEAM"],"output_format":"json"}` (Linux/macOS). `stdout` içinde `aydın` döner. `ht_list_vars` → `{}` yalnızca adları verir; `ht_delete_var` → `{"name":"APP_TEAM"}` bu oturumdaki değeri kaldırır. `process.env`, GitHub Secrets ve Windows kullanıcı ortamı değişmez.

| Yeni `ht_shell` argümanı | Davranış |
|---|---|
| `stdin_file` | `cwd` altındaki okunabilir bir dosyayı olduğu gibi stdin’e verir (en fazla 64 KiB ve profil okuma limiti). `stdin` ile birlikte kullanılmaz. |
| `capture` | `both` (varsayılan), `stdout` veya `stderr`. Seçilmeyen akış döndürülmez. |
| `output_format` | `text` (varsayılan) veya `json`. JSON’da `exit_code`, `signal`, `timed_out`, `duration_ms`, `cwd`, `ok`, seçili akışlar ve `omitted_bytes` vardır. |
| `expected_exit_codes` | Örn. `[0,1]`: beklenmeyen çıkış, sinyal veya zaman aşımı MCP hatası olur; çıktı yine döner. Verilmezse eski çağrılardaki çıkış kodu davranışı korunur. |
| `inherit_vars` | Sadece bu işlem için eklenecek kayıtlı isimler; varsayılanı `[]`. `argv` içinde `$AD` genişletilmez; program ortam değişkenini kendisi okur. |
| `max_output_bytes` | Tutulan stdout+stderr baytlarını sınırlar. Profil tavanını aşamaz; kesilince baş/son ve atılan bayt sayısı döner. JSON/başlıklar bu bütçeye dahil değildir. |

Değişken adları büyük harfe çevrilir. `APP_`, `MY_`, `PROJECT_`, `HT_VAR_` önekli adlar aynen kullanılır; diğer adlara `HT_VAR_` eklenir (`RENK` → `HT_VAR_RENK`). `ht_add_var` gerçek adı gösterir. Mevcut değer ancak `overwrite:true` ile değiştirilir. En fazla 32 ad, değer başına 4 KiB. Değerler diske veya araç çağrı günlüğüne yazılmaz; ancak onları yazdıran bir komutun çıktısında görünür. Gizli anahtar kasası olarak kullanma. Stdio’da süreç, HTTP’de OAuth yetkilendirmesi başına tutulur (token yenilemede korunur). Aynı statik bearer’ı paylaşanlar aynı kapsamdadır. Yeniden başlatma ya da 12 saat kullanılmama değerleri temizler.

### Çöpü boşalt

1. `ht_empty_trash` → `{}`: kaç öğe olduğunu gösterir, hiçbir dosyayı silmez.
2. Sonucu kontrol ettikten sonra `{"confirm":true}`: yalnızca `.ht-trash/` içini ve `index.jsonl` dosyasını kalıcı olarak siler; **klasör kalır**. Çok köklü kurulumda `root` tam olarak tanımlanmış bir kök olmalıdır; varsayılan ilk köktür. Korumalı alt yollar varsa işlem reddedilir. Silmeden önce geri yükleme için `ht_trash` çıktısındaki `ht_move` komutunu kullan.

### Kullanıcıya dosya ver: `ht_share`

- Projede zaten bulunan bir dosya: `{"source_path":"raporlar/özet.pdf","name":"Ozet.pdf","ttl_minutes":15}`. **Kaynak taşınmaz.** Paylaşılan kopya sonradan yapılan değişikliklerden etkilenmez.
- Aracın kendi çalışma klasörü **`/_tmp/hardtools-share/`** ilk proje kökündeki `_tmp/hardtools-share/` dizinine karşılık gelir; sistemin `/_tmp` dizinine yazma izni gerekmez. Örneğin `ht_write` ile `{"path":"_tmp/hardtools-share/not.txt","content":"Merhaba","mkdirp":true}`, ardından `ht_share` ile `{"path":"not.txt"}`. `source_path` ve `path` birlikte kullanılmaz.
- HTTP: kullanıcıya **“Dosyayı indir”** bağlantısını ilet. Bağlantıya sahip herkes o dosyayı indirebilir; MCP’ye erişim kazanmaz. Stdio: dışarıya sunucu açılmaz, dosya gerçek baytlarıyla MCP kaynağı olarak döner (istemcinin ek desteğine bağlıdır). İkisinde de yetkili istemci `resources/read` kullanabilir.
- `{"action":"list"}` kendi paylaşımlarının adını, boyutunu, SHA-256 özetini, bitişini ve `id`’sini verir. `{"action":"revoke","id":"<listeden alınan id>"}` sonraki indirmeleri durdurur; alınmış kopyaları geri alamaz. Varsayılan **10 dk**, aralık 1–60 dk. Dosya başına en fazla 2 MiB ve profil okuma limiti; süreç genelinde 32 dosya / 16 MiB. Sunucu yeniden başlarsa bağlantılar biter. Yalnızca açıkça seçilen izinli normal dosyalar paylaşılır; klasör yayını yoktur.

### Görsel ara ve göster: `ht_image_search`

`{"query":"Aydın Turkey","limit":4,"orientation":"landscape","file_type":"jpeg","thumbnail_width":250}`. API anahtarı gerekmez. Sonuçlar birer kaynak sayfası, boyutlar ve varsa eser sahibi/lisans ile döner. İlk üç uygun sonuç için yalnız URL değil, MCP `image` içeriği üretilir. Önizleme alınamazsa kaynak bağlantısı kalır. Kullanım koşullarını dosyanın kaynak sayfasında doğrula.

`limit`: 1–8; `thumbnail_width`: 120, 250 veya 500; `orientation`: `landscape`, `portrait`, `square`; `file_type`: `jpeg`, `png`, `webp`. Filtreler getirilen sayfaya uygulanır. `next_offset` varsa sonraki çağrıda `offset` olarak ver; yalnızca kaynak bilgisi için `previews:false` kullan. Ağ kapalıysa sorgu yapılmaz. Alan adı izin listesi kullanıyorsan arama için `commons.wikimedia.org`, küçük görseller için `thumb.wikimedia.org` ve `upload.wikimedia.org` gerekir. Sorgu metni Commons’a gönderilir.

## Profiller

`strict` (`ht_fetch` ve görsel araması için `net.allowDomains` zorunlu, audit hatasında durur) · `balanced` (günlük geliştirme) · `open` (`command` ile kabuk sözdizimi açık). **Hiçbiri işletim sistemi sandbox’ı değildir.** Üçünde de varsayılan `shell.denyCommands` ve `shell.denyArgs` boştur. Bu, uzaktan kabuğu açmaz: `shell.enabled` ayrı bir ayardır.

Politika dosyası **yalnızca** `HARDTOOLS_CONFIG` veya `~/.hardtools/config.json` yolundan okunur, **asla çalışma alanından değil** (kötü niyetli bir repo kendi gevşek politikasını getiremesin). Bilinmeyen/typo anahtarlar hata verir. Örnek: `hardtools.config.example.json`. Öncelik: `--profile` > `HARDTOOLS_PROFILE` > dosya > `balanced`.

## Kurulum

```bash
npm ci && npm test               # kilitli bağımlılıklar + testler (derleme dahil)
npm run bundle                   # bundle/index.js (node_modules gerekmez)
```

### Claude Code (plugin)
Klasörü plugin olarak yükle (`.claude-plugin/plugin.json` + `.mcp.json` hazır; sunucu `${CLAUDE_PLUGIN_ROOT}/bundle/index.js` ile başlar). Yerelde denemek için `claude --plugin-dir ./hardtools`; yükleme sorunlarında `claude --debug`. Kök dizin varsayılan olarak sunucunun çalışma dizinidir; `strict` ve `balanced` profilleri `/` ve ev dizininin kendisini reddeder.
**Önemli:** yerleşik `Bash/Edit/Write/WebFetch` kapatılmazsa Claude onları kullanmaya devam eder ve bu eklenti güvenliği artırmaz, sadece seçenek ekler. `claude-code-settings.example.json`'a bak (sözdizimini sürümünde doğrula).

### Claude Desktop (stdio)
`claude_desktop_config.example.json` içeriğini Desktop'un MCP yapılandırmasına ekle. Desktop'ta çalışma dizini proje olmadığı için `HARDTOOLS_ROOTS` **zorunlu** pratikte.

### GitHub Actions: tek dosyayla bağlan

**Davet edildiysen:** Yayın sahibinin özelden gönderdiği kullanılmamış daveti Claude ile aynı tarayıcı profilinde bir kez aç. Açılan sayfa hangi `/mcp` adresini kullanacağını gösterir. 10 dakika içinde Claude → Settings → Connectors → Add custom connector: ad `hardtools`, URL bu `/mcp` adresi; OAuth client ID ve secret boş. **Dosya, parola, terminal veya GitHub hesabı gerekmez.**

**Yayın sahibiysen:**

1. **Bir kez:** Repo → Settings → Secrets and variables → Actions → **New repository secret**. Adı **`HARDTOOLS_CONNECT_PASSWORD`** olsun. Parola yöneticisinden en az 20 rastgele karakter (en fazla 256; tek satır, başta/sonda boşluk yok) kullan ve kendine sakla. Bu GitHub hesap parolan değildir. Parolayı normal repo variable’a veya workflow girdisine yazma.
2. **Her yayın:** Actions → hardtools MCP → Run workflow → **`serve`**. Çalışan run’ın **Artifacts → hardtools-connect** ZIP’ini indir. İçinde yalnızca **`BAGLAN.html`** var. Windows’ta *Tümünü ayıkla*, dosyayı Edge, Chrome veya Firefox ile aç, bağlantı parolanı gir. Paket ya da PowerShell kurulmaz. Public ve private repolarda hiçbir düz metin token/davet yayımlanmaz.
3. **Daveti kopyala** → aynı tarayıcıda bir kez aç (veya bir kişiye özelden gönder). **MCP adresini kopyala** → Claude connector URL alanına yapıştır. Yalnızca yetkilendirme formu ayrıca *Access token* istiyorsa karttaki ilgili bölümü aç, sayfanın alan adını doğrula ve **yalın** token’ı kopyala. Header isteyen istemciler için `Authorization` değeri `Bearer ` önekiyle kopyalanır. Bağlantı parolası yalnızca yerel HTML’ye girilir, tünele değil.

**Önceki sürümden geçiş:** Artık `age_recipient`, özel anahtar üretimi veya ayrı bir `connect.txt` yok. Eski `HARDTOOLS_AGE_RECIPIENT` yeni secret’ın yerini tutmaz. Önceden indirilmiş eski bir paketi açmak için [genel BAGLAN.html](bundle/BAGLAN.html) dosyasını **Download raw file (↓)** ile indir, kendi bilgisayarında aç. Eski ZIP’i seç veya “Eski connect.txt metnini yapıştır” bölümüne tam age metnini ya da yalnız `YWdl…` gövdesini yapıştır. Bu, access token değildir; şifreli eski paketi açmak için yine **o run’ın kendi özel anahtarı** gerekir. Yeni parola eski paketi açmaz. SSH alıcılı eski paketlerde o paketin terminal kılavuzunu kullan.

Kart canlılığı sorgulamaz. Run iptal edilirse/sonlanırsa eski URL ve token artık çalışmaz. `check-connection` yalnızca kısa bir doğrulamadır, yayın değildir. Manuel yayın ~5 saat 45 dakika açık kalır; `auto_renew` varsayılan olarak kapalıdır. Bir sonraki yayın yeni adres/token üretir. Parola değiştirilirse yeni paketler yeni parolayı, kaydedilmiş eskiler o run sırasındaki parolayı ister. Summary veya canlı log gerekmez.

### Uzak / HTTP modu (web dahil: **sınırlı**)
```bash
export HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)
node bundle/index.js --http --port 8787 --profile balanced      # 127.0.0.1'e bağlanır
```
- A static bearer token (`Authorization: Bearer <HARDTOOLS_HTTP_TOKEN>`) works for **Claude Code / Desktop** (they can send headers).
- **claude.ai web / Claude app**: the custom-connector dialog cannot send headers, so the server speaks a minimal stateless **OAuth 2.1** (RFC 9728 + RFC 8414 discovery, RFC 7591 dynamic client registration, PKCE S256). Add the connector with the `/mcp` URL and leave the OAuth client fields empty; a consent page opens and asks for `HARDTOOLS_HTTP_TOKEN`. A redeemed invite session can also authorize without entering that token (access tokens live 1 h, refresh tokens 12 h; everything dies when the server restarts with a new secret). Redirect URIs are limited to `https://claude.ai|claude.com/api/mcp/auth_callback` and loopback; add more with `HARDTOOLS_OAUTH_REDIRECT_URIS` (comma-separated, exact match).
- Verified with this repo's tests and the official MCP SDK OAuth client; **not yet verified against the live claude.ai dialog**.
- Uzak modda `ht_shell` ve yazma araçları varsayılan **kapalı** (sunucunun dosya sistemi senin makinen değil). Kendi güvendiğin yayında açmak için `serve` ile `allow_local_tools` seç veya kendi sunucunda `HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=1` kullan. TLS sonlandırma (ters vekil/tünel) senin sorumluluğunda; Host doğrulaması için `HARDTOOLS_ALLOWED_HOSTS=alanadi.com`.

## Bilinen sınırlar (özet; ayrıntı `SECURITY.md`)
Windows'ta `ht_shell` yalnızca `.exe` çalıştırır (`.cmd` shim yok), süreç ağacı `taskkill` ile öldürülür; asıl hedef Linux/macOS/WSL. `balanced` içindeki `npm test` gibi komutlar **proje betiklerini** çalıştırır. `open` profili sandbox değildir. Yol denetimi check-then-use (TOCTOU) artığı taşır.
