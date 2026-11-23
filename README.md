# hardtools

Claude'un yerleşik dosya/arama/kabuk/web araçlarının **sınırlandırılmış, denetlenebilir** karşılıkları. Tek bir MCP sunucusu; Claude Code, Claude Desktop (stdio) ve uzak MCP (HTTP) üzerinden çalışır.

> **Durum:** v0.5.2, kod AI tarafından yazıldı (bkz. `CREDITS.md`). Otomatik testler var; bağımsız insan güvenlik incelemesi yapılmadı. Pazar yerinden kurulum Claude Code CLI ile doğrulandı. MCP testleri SDK istemcisi ve ham HTTP ile yapılır; Claude Desktop ve claude.ai arayüzlerinde uçtan uca kurulum burada denenmedi.

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
| `ht_shell` | bash | `command` ile gerçek kabuk veya `argv` ile literal argümanlar; yerelde kullanıcı işlemi, HTTP’de etkinse izole `/work`; süre ve çıktı bütçeleri |
| `ht_add_var` / `ht_list_vars` / `ht_delete_var` | oturum değişkenleri | isim/değer tanımla, yalnız adları listele veya tek adı kaldır; seçilen değerler `ht_shell` alt sürecine gider |
| `ht_share` | kullanıcıya dosya ver | süreli indirme bağlantısı veya MCP dosya eki, özel çalışma klasörü, SHA-256, yeniden adlandırma, listeleme ve iptal |
| `ht_image_search` | görsel arama | genel sorguda Wikimedia Commons; Minecraft Fabric logosunda resmî proje kaynağı; gerçek küçük görsel, filtre, kaynak ve varsa lisans |
| `ht_fetch` | web fetch | SSRF korumalı (bağlantı anında IP doğrulama, her yönlendirmede yeniden doğrulama), boyut/süre/sıkıştırma-bombası limiti, `<untrusted_web_content>` sarmalı |
| `ht_status` | – | aktif politika, audit zinciri ve bağımsız doğrulama için kendi JSONL kaydını dışa aktarma |

## Yeni araçları dene

### `ht_shell` ve oturum değişkenleri

`balanced` profilde iki biçimden **birini** seç:

- `{"command":"printf 'merhaba' | tr a-z A-Z > sonuc.txt"}` gerçek bir POSIX boru hattı kurar. `ht_read` ile `sonuc.txt` içinde `MERHABA` okunur. Yerel Windows’ta `command` söz dizimi `cmd.exe`’ye aittir.
- `{"argv":["echo","a | b"]}` kabuk açmaz; `|` bir argümanın parçasıdır.

`ht_status.shell.execution` nerede çalıştığını gösterir: `host` (yerel stdio), `workspace` (izole HTTP) veya `disabled`. Yerelde `cwd` doğrulanır ama alt süreç işletim sistemi kullanıcısının izinlerine sahiptir; dosya araçlarının kök/secret kurallarını ve `ht_fetch` izin listesini devralmaz.

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

### Çöpü geri yükle veya önizle

Çöpe taşımak için `ht_trash`, geri almak için çıktısındaki `from`/`to` ile `ht_move` kullan. Hedef zaten varsa dosya ve indeks değişmez. Başarıda geri yüklenen üst düzey öğenin satırı `index.jsonl` içinden çıkarılır. Alt klasörden tek dosyayı almak, hâlâ çöpte olan klasörün satırını kaldırmaz. Eski sürümden kalan, artık diskte karşılığı olmayan satırlar sonraki başarılı çöpe taşıma/tam geri yüklemede ayıklanır.

1. `ht_empty_trash` → `{}`: gerçek üst düzey öğeleri sayar; bayat kayıtları ve indekssiz öğeleri bildirir. Önizleme indeksi düzeltmez, kilit oluşturmaz ve silmez.
2. Sonucu kontrol ettikten sonra `{"confirm":true}`: yalnızca `.ht-trash/` içini ve `index.jsonl` dosyasını kalıcı olarak siler; **klasör kalır**. Çok köklü kurulumda `root` tam olarak tanımlanmış bir kök olmalıdır; varsayılan ilk köktür. Korumalı alt yollar varsa işlem reddedilir. Silmeden önce geri yükleme için `ht_trash` çıktısındaki `ht_move` komutunu kullan.

### Kendi audit kaydını çevrimdışı doğrula

1. `ht_status` → `{"audit_export":true}`. Yanıtın ilk bölümünde `entries` ve `expected_head`, ikinci bölümünde ise gerçek dosya baytlarını taşıyan bir MCP eki vardır. Açık indirme bağlantısı oluşturulmaz; `ht_read` için kök dışına istisna yoktur.
2. `next_offset` boşsa eki `hardtools-audit.jsonl` olarak kaydet. Değilse aynı `snapshot` değerini `audit_snapshot`, dönen **bayt** konumunu `audit_offset` olarak verip `audit_export:true` ile devam et. Her `resource.blob` parçasını **ayrı ayrı** Base64’ten çöz, baytları artan `offset` sırasıyla birleştir. Sonraki çağrılar kayda eklenir ama bu kopyanın sonunu değiştirmez. Bir kapsamda son dört kopya, en fazla 15 dakika tutulur.
3. Kendi bilgisayarında, güvenilir CLI kopyanla çalıştır:

   ```sh
   node bundle/index.js --verify hardtools-audit.jsonl --expect-head "<ilk yanıttaki expected_head>"
   ```

   Başarıda `ok:true` ve kayıt sayısı, uyuşmazlıkta `ok:false` ve çıkış kodu `2` döner. `--expect-head` olmadan dosyanın sonundan **tam satırların** çıkarılması fark edilmeyebilir. Baş değerini JSONL’den ayrı sakla. Bu bir imza veya sunucunun her olayı dürüstçe kaydettiğinin kanıtı değildir.

Stdio’da mevcut sürecin zinciri; HTTP’de yalnızca mevcut OAuth onayının (veya aynı statik bearer’ı kullananların) araç/kaynak zinciri verilir. Token yenilemesi yeni kapsam açmaz. Süreç günlüğü ve başka onayların kayıtları HTTP aracıyla dışa aktarılamaz. Yeniden başlatma veya HTTP kapsamının 12 saat kullanılmaması yeni bir zincir başlatır. Kaydedilmiş çağrı argümanları proje bilgisi içerebilir; dosyanı özel tut.

### Kullanıcıya dosya ver: `ht_share`

- Projede zaten bulunan bir dosya: `{"source_path":"raporlar/özet.pdf","name":"Ozet.pdf","ttl_minutes":15}`. **Kaynak taşınmaz.** Paylaşılan kopya sonradan yapılan değişikliklerden etkilenmez.
- Aracın kendi çalışma klasörü **`/_tmp/hardtools-share/`** ilk proje kökündeki `_tmp/hardtools-share/` dizinine karşılık gelir; sistemin `/_tmp` dizinine yazma izni gerekmez. Örneğin `ht_write` ile `{"path":"_tmp/hardtools-share/not.txt","content":"Merhaba","mkdirp":true}`, ardından `ht_share` ile `{"path":"not.txt"}`. `source_path` ve `path` birlikte kullanılmaz.
- HTTP: kullanıcıya **“Dosyayı indir”** bağlantısını ilet. Bağlantıya sahip herkes o dosyayı indirebilir; MCP’ye erişim kazanmaz. Stdio: dışarıya sunucu açılmaz, dosya gerçek baytlarıyla MCP kaynağı olarak döner (istemcinin ek desteğine bağlıdır). İkisinde de yetkili istemci `resources/read` kullanabilir.
- `{"action":"list"}` kendi paylaşımlarının adını, boyutunu, SHA-256 özetini, bitişini ve `id`’sini verir. `{"action":"revoke","id":"<listeden alınan id>"}` sonraki indirmeleri durdurur; alınmış kopyaları geri alamaz. Varsayılan **10 dk**, aralık 1–60 dk. Dosya başına en fazla 2 MiB ve profil okuma limiti; süreç genelinde 32 dosya / 16 MiB. Sunucu yeniden başlarsa bağlantılar biter. Yalnızca açıkça seçilen izinli normal dosyalar paylaşılır; klasör yayını yoktur.

### Görsel ara ve göster: `ht_image_search`

`{"query":"Aydın Turkey","limit":4,"orientation":"landscape","file_type":"jpeg","thumbnail_width":250}`. API anahtarı gerekmez. Sonuçlar birer kaynak sayfası, boyutlar ve varsa eser sahibi/lisans ile döner. İlk üç uygun sonuç için yalnız URL değil, MCP `image` içeriği üretilir. Önizleme alınamazsa kaynak bağlantısı kalır. Kullanım koşullarını dosyanın kaynak sayfasında doğrula.

`limit`: 1–8; `thumbnail_width`: 120, 250 veya 500; `orientation`: `landscape`, `portrait`, `square`; `file_type`: `jpeg`, `png`, `webp`. Filtreler getirilen sayfaya uygulanır. `next_offset` varsa sonraki çağrıda `offset` olarak ver; yalnızca kaynak bilgisi için `previews:false` kullan. Ağ kapalıysa sorgu yapılmaz. Alan adı izin listesi kullanıyorsan arama için `commons.wikimedia.org`, küçük görseller için `thumb.wikimedia.org` ve `upload.wikimedia.org` gerekir. Genel arama metni Commons’a gönderilir. `{"query":"Fabric mod logo"}` bunun yerine `fabricmc.net` adresindeki [resmî Fabric projesinin](https://fabricmc.net/) 52×56 PNG logosunu kullanır; varsa izin listende bu alan adı da gerekir. Bu **Fabric API** veya rastgele bir modun ikonu değildir. Doğrulanmış mod logosu yoksa ya da önizleme doğrulanamazsa ilgisiz fotoğraf döndürülmez. Marka görseli için serbest kullanım lisansı varsayılmaz.

## Profiller

`strict` (`ht_fetch` ve görsel araması için `net.allowDomains` zorunlu, audit hatasında durur) · `balanced` (günlük geliştirme, `command` + `argv`) · `open` (`command` + `argv`). `strict` varsayılanı yalnız `argv`’dir. Mevcut özel `balanced` politikanda dolu `denyCommands`/`denyArgs` varsa açıkça `allowShellSyntax:true` demedikçe önceki `argv` davranışı korunur. **Profiller tek başına işletim sistemi sandbox’ı değildir.** Üçünde de varsayılan `shell.denyCommands` ve `shell.denyArgs` boştur. Bu, uzaktan kabuğu açmaz: `shell.enabled` ayrı bir ayardır.

Politika dosyası **yalnızca** `HARDTOOLS_CONFIG` veya `~/.hardtools/config.json` yolundan okunur, **asla çalışma alanından değil** (kötü niyetli bir repo kendi gevşek politikasını getiremesin). Bilinmeyen/typo anahtarlar hata verir. Örnek: `hardtools.config.example.json`. Öncelik: `--profile` > `HARDTOOLS_PROFILE` > dosya > `balanced`.

## Kurulum

```bash
npm ci && npm test               # kilitli bağımlılıklar + testler (derleme dahil)
npm run bundle                   # bundle/index.js (node_modules gerekmez)
```

### Pazar yerinden kurulum

**Eklentiler → Ekle → Pazar yeri ekle** penceresinde URL olarak `tickwarden/hardtools` girip **Eşitle**’yi seç. Katalog adı `hardtools-marketplace`, listelenen eklenti `hardtools`’dur. Bu alan GitHub depo adresini kullanır; buraya `/mcp` adresi, davet bağlantısı veya token yazılmaz.

Claude Code içinde aynı katalogdan yüklemek için:

```text
/plugin marketplace add tickwarden/hardtools
/plugin install hardtools@hardtools-marketplace
```

Bu eklenti **yerel stdio** kullanır: çalıştırıldığı ortamda Node.js 20+ gerekir; paketlenmiş `${CLAUDE_PLUGIN_ROOT}/bundle/index.js` için `npm install` gerekmez. **Amacın claude.ai’yi çalışan uzak MCP’ye bağlamaksa** pazar yeri yerine **Bağdaştırıcılar → Özel bağdaştırıcı ekle**’yi kullan; o oturumun `BAGLAN.html` kartındaki **MCP adresini** (`…/mcp`) gir. [Bağlantı adımları aşağıda.](#github-actions-tek-dosyayla-bağlan)

Yerel geliştirmede bir proje klasöründen `claude --plugin-dir /hardtools/deposunun/yolu` ile de deneyebilirsin; yükleme sorunlarında `claude --debug` kullan. Kök dizin varsayılan olarak sunucunun çalışma dizinidir; `strict` ve `balanced` profilleri `/` ve ev dizininin kendisini reddeder.
**Önemli:** yerleşik `Bash/Edit/Write/WebFetch` kapatılmazsa Claude onları kullanmaya devam eder ve bu eklenti güvenliği artırmaz, sadece seçenek ekler. `claude-code-settings.example.json`'a bak (sözdizimini sürümünde doğrula).

#### Eklenti ayarları (`userConfig`)

Manifest artık yalnızca zorunlu alanları değil, **kullanıcıdan istenen ayarları ve iki MCP sunucusunu** bildirir. Claude Code eklentiyi etkinleştirirken bu alanları sorar; her seçenek `/config` panelinde satır olarak da görünür (`sensitive` ve çoklu seçim hariç). Değerler `settings.json` içindeki `pluginConfigs` altında, hassas olanlar platformun güvenli kimlik deposunda tutulur.

| Seçenek | Tip / varsayılan | Sunucudaki karşılığı | Nerede etkili |
|---|---|---|---|
| `profile` | `string`, `balanced` (`balanced`/`strict`/`open`) | `HARDTOOLS_PROFILE` | Yerel ve uzak sunucu |
| `workspace_root` | `directory` (boş: çalışma dizini) | `HARDTOOLS_ROOTS` | Yerel sunucu |
| `allow_local_tools` | `boolean`, `true` | `HARDTOOLS_ALLOW_LOCAL_TOOLS` | **Kapalıyken salt okunur**: `ht_write`, `ht_edit`, `ht_shell` reddedilir |
| `allow_workspace_https` | `boolean`, `false` | `HARDTOOLS_WORKSPACE_HTTPS` | HTTP/izole çalışma modu; `ht_status.shell.network` |
| `workspace_name` | `string`, `project` | – (Actions girdisi) | Yalnızca `serve` yayını |
| `auto_renew` | `boolean`, `false` | – (Actions girdisi) | Yalnızca `serve` yayını |
| `mcp_url` | `string` | uzak sunucunun `url` alanı | Uzak bağlayıcı |
| `mcp_token` | `string`, `sensitive` | uzak sunucunun `Authorization: Bearer` başlığı | OAuth kullanmayan istemciler |

Manifestteki sunucular:

- `hardtools` — yerel `stdio`, `node ${CLAUDE_PLUGIN_ROOT}/bundle/index.js`; yukarıdaki `env` değerleri `${user_config.…}` ile doldurulur. Bu kayıt `.mcp.json`'daki eşdeğerini eklenti içinde geçersiz kılar; `.mcp.json` eklenti dışı kullanım (düz `claude mcp add`, elle çalıştırma) için aynen durur.
- `hardtools-remote` — `http`, adresi `${user_config.mcp_url}`, başlığı `${user_config.mcp_token}`. OAuth 2.1 akışı (RFC 9728/8414/7591 + PKCE) sunucu tarafında zaten var; istemci bağlanırken keşfeder, manifestte ayrıca OAuth alanı yoktur.

**Önemli sınır:** claude.ai **Chat**, adresi `${user_config.…}` içeren uzak sunucuyu ve yerel `stdio` sunucusunu yüklemez (Anthropic belgeleri: *Ignored when the URL contains the reference*). Bu yüzden yukarıdaki ayarlar Claude Code, Cowork ve masaüstü istemcisinde çalışır; **web sohbeti** için hâlâ **sabit bir HTTPS `/mcp` adresi** ve **Bağdaştırıcılar → Özel bağdaştırıcı ekle** gerekir. Davranış değişikliği yalnızca açıkça kapatıldığında olur: `allow_local_tools` verilmezse sunucu eskisi gibi profil kurallarıyla yazma ve kabuk açar.

### Claude Desktop (stdio)
`claude_desktop_config.example.json` içeriğini Desktop'un MCP yapılandırmasına ekle. Desktop'ta çalışma dizini proje olmadığı için `HARDTOOLS_ROOTS` **zorunlu** pratikte.

### GitHub Actions: tek dosyayla bağlan

**Davet edildiysen:** Yayın sahibinin özelden gönderdiği kullanılmamış daveti Claude ile aynı tarayıcı profilinde bir kez aç. Açılan sayfa hangi `/mcp` adresini kullanacağını gösterir. 10 dakika içinde Claude → Settings → Connectors → Add custom connector: ad `hardtools`, URL bu `/mcp` adresi; OAuth client ID ve secret boş. **Dosya, parola, terminal veya GitHub hesabı gerekmez.**

**Yayın sahibiysen:**

1. **Bir kez:** Repo → Settings → Secrets and variables → Actions → **New repository secret**. Adı **`HARDTOOLS_CONNECT_PASSWORD`** olsun. Parola yöneticisinden en az 20 rastgele karakter (en fazla 256; tek satır, başta/sonda boşluk yok) kullan ve kendine sakla. Bu GitHub hesap parolan değildir. Parolayı normal repo variable’a veya workflow girdisine yazma.
2. **Her yayın:** Actions → hardtools MCP → Run workflow → **`serve`**. Çalışan run’ın **Artifacts → hardtools-connect** ZIP’ini indir. İçinde yalnızca **`BAGLAN.html`** var. Windows’ta *Tümünü ayıkla*, dosyayı Edge, Chrome veya Firefox ile aç, bağlantı parolanı gir. Paket ya da PowerShell kurulmaz. Public ve private repolarda hiçbir düz metin token/davet yayımlanmaz.
3. **Daveti kopyala** → aynı tarayıcıda bir kez aç (veya bir kişiye özelden gönder). **MCP adresini kopyala** → Claude connector URL alanına yapıştır. Yalnızca yetkilendirme formu ayrıca *Access token* istiyorsa karttaki ilgili bölümü aç, sayfanın alan adını doğrula ve **yalın** token’ı kopyala. Header isteyen istemciler için `Authorization` değeri `Bearer ` önekiyle kopyalanır. Bağlantı parolası yalnızca yerel HTML’ye girilir, tünele değil.

Kabuk istiyorsan `serve` formunda **`allow_local_tools`** seç. Yayın sahibi `workspace_name` ile bu run’a özel **boş** çalışma klasörünün adını verir (varsayılan `project`; 1–48 ASCII harf/rakam, `_` veya `-`; harf ya da rakamla başlar). Bir host yolu, runner checkout’u veya önceki run’ın dosyaları seçilmez. `command` ve `argv` aynı alanda çalışır: komutun içinde `/work`, `cwd` için `.` veya alt klasör kullan. `auto_renew` seçimi ve klasör adını aktarır, dosyaları **taşımaz**. Bu seçenek `check-connection` için araçları açmaz.

**Komutlarda HTTPS çıkışı:** Yeni bir `serve` başlatırken `allow_local_tools` ile birlikte `allow_workspace_https` seç. İkincisi varsayılan olarak **kapalıdır**; mevcut oturumu değiştiren bir MCP komutu değildir. Açıkken `ht_status.shell.network` → `public-https-proxy`; kapalıyken etkin worker için `isolated`. Örnek: `ht_shell({"argv":["curl","-fsSI","https://example.com/"]})`. Git’in HTTPS taşıması da çalışır. `https_proxy` tanımayan yazılımların doğrudan internete çıkışı yoktur. Düz HTTP, SSH, UDP, yerel ağ ve metadata erişimi açılmaz. Proje dosyalarındaki veriler açık HTTPS üzerinden dışarı gönderilebilir; yalnız güvendiğin erişim sahipleriyle kullan. `auto_renew` zaten etkinse aynı seçimi aktarır; bekleme/kapanma sürelerini değiştirmez.

**Önceki sürümden geçiş:** Artık `age_recipient`, özel anahtar üretimi veya ayrı bir `connect.txt` yok. Eski `HARDTOOLS_AGE_RECIPIENT` yeni secret’ın yerini tutmaz. Önceden indirilmiş eski bir paketi açmak için [genel BAGLAN.html](bundle/BAGLAN.html) dosyasını **Download raw file (↓)** ile indir, kendi bilgisayarında aç. Eski ZIP’i seç veya “Eski connect.txt metnini yapıştır” bölümüne tam age metnini ya da yalnız `YWdl…` gövdesini yapıştır. Bu, access token değildir; şifreli eski paketi açmak için yine **o run’ın kendi özel anahtarı** gerekir. Yeni parola eski paketi açmaz. SSH alıcılı eski paketlerde o paketin terminal kılavuzunu kullan.

Kart canlılığı sorgulamaz. Run iptal edilirse/sonlanırsa eski URL ve token artık çalışmaz. `check-connection` yalnızca kısa bir doğrulamadır, yayın değildir. Manuel yayın ~5 saat 45 dakika açık kalır; `auto_renew` varsayılan olarak kapalıdır. Bir sonraki yayın yeni adres/token üretir. Parola değiştirilirse yeni paketler yeni parolayı, kaydedilmiş eskiler o run sırasındaki parolayı ister. Summary veya canlı log gerekmez.

### Uzak / HTTP modu (web dahil: **sınırlı**)
```bash
export HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)
node bundle/index.js --http --port 8787 --profile balanced      # 127.0.0.1'e bağlanır
```
- A static bearer token (`Authorization: Bearer <HARDTOOLS_HTTP_TOKEN>`) works for **Claude Code / Desktop** (they can send headers).
- **claude.ai web / Claude app**: the custom-connector dialog cannot send headers, so the server speaks a minimal stateless **OAuth 2.1** (RFC 9728 + RFC 8414 discovery, RFC 7591 dynamic client registration, PKCE S256). Add the connector with the `/mcp` URL and leave the OAuth client fields empty; the consent step then depends on configuration: with `HARDTOOLS_OAUTH_GITHUB_CLIENT_ID` (plus `HARDTOOLS_OAUTH_ALLOWED_LOGINS`/`_EMAILS`) set, `/authorize` starts **GitHub sign-in** — device flow by default (one-time code at github.com/login/device, no client secret stored) or authorization-code redirect when `HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET` is also set. Only allowlisted accounts get a code. Without GitHub configuration the fallback page asks for `HARDTOOLS_HTTP_TOKEN`. A redeemed invite session can also authorize without entering that token (access tokens live 1 h, refresh tokens 12 h; everything dies when the server restarts with a new secret). Redirect URIs are limited to `https://claude.ai|claude.com/api/mcp/auth_callback` and loopback; add more with `HARDTOOLS_OAUTH_REDIRECT_URIS` (comma-separated, exact match).
- Verified with this repo's tests and the official MCP SDK OAuth client; **not yet verified against the live claude.ai dialog**.
- HTTP’de yazma ve kabuk varsayılan **kapalı**. Kendi sunucunda `HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=1` ile ve **tek, özel bir `HARDTOOLS_ROOTS` proje klasörü** seçerek aç. Proje, audit/konfig ve yönetim dosyalarından ayrı olmalı; içine sır, host soketi veya başka bağlama noktası koyma. Bu alan aynı yayına erişenlerce paylaşılır.
- HTTP kabuğu için Linux (Debian/Ubuntu birleşik `/usr` düzeni), procfs, `--ro-bind-fd` destekleyen `/usr/bin/bwrap` ve çalışan kullanıcı ad alanları gerekir. GitHub işi dağıtım paketini kullanır. Başlangıç sınaması başarısız olursa sunucu **host kabuğuna geçmez**. Kabuksuz, yalnız dosya yazılabilen HTTP kullanımı için politikada `shell.enabled:false` ayarlanabilir. Yerel stdio bu bağımlılığı gerektirmez.
- Worker’a proje `/work`, salt okunur sistem araçları/kütüphaneleri ve Node bağlanır. `/tmp` çağrıya özeldir; host ağı hiçbir zaman paylaşılmaz. Varsayılan olarak internet çıkışı da yoktur. Kendi sunucunda izole kabuğa ek olarak `HARDTOOLS_WORKSPACE_HTTPS=1` verildiğinde yalnız proxy üzerinden genel HTTPS hedeflerine çıkılabilir. Runner’ın evi, workflow dosyaları, yönetim soketleri, token’ları ve yönetim ortamı aktarılmaz. Web verisi için `ht_fetch` kendi politikasını kullanır. TLS sonlandırma (ters vekil/tünel) ve `HARDTOOLS_ALLOWED_HOSTS` yapılandırması yayın sahibine aittir.


### Public modlar: girişsiz bağlanma ya da giriş zorunlu (0.5.2)

`HARDTOOLS_PUBLIC` sunucunun kimlik davranışını belirler. Girişsiz modlarda MCP adresi hiç 401 dönmez ve OAuth keşif belgeleri yayınlanmaz; bu yüzden claude.ai bağlayıcı eklerken **"Oturum açma gerekli"** satırını göstermez, **Ekle** ile doğrudan eklenir.

| Mod | Bağlayıcı adresi | Giriş | Araçlar |
|---|---|---|---|
| `open` | `https://<host>/mcp` | **zorunlu** — statik bearer ya da OAuth oturumu (keşif yayınlanır, 401 + `www-authenticate` döner) | **tüm araçlar (21)** |
| `open` + `HARDTOOLS_PUBLIC_TOOLS=safe` | `https://<host>/mcp` | yok | güvenli küme: `ht_read`, `ht_glob`, `ht_search`, `ht_status`, `ht_user_input`, `ht_image_search`, `ht_fetch`, `ht_share` |
| `open` + `HARDTOOLS_PUBLIC_TOOLS="ht_read,ht_glob,…"` | `https://<host>/mcp` | yok | yalnız listelenen araçlar |
| `key` | `https://<host>/c/<anahtar>` | yok — anahtar (≥32 karakter) adreste kimlik yerine geçer | **tüm araçlar (21)** |

```bash
# Fly: tüm araçlar + giriş zorunlu (claude.ai'de "Bağlan"a basınca giriş akışı çıkar)
fly secrets set HARDTOOLS_PUBLIC=open HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32) -a hardtools-mcp
# tüm araçlar, giriş istemez (adres anahtarlı):
fly secrets set HARDTOOLS_PUBLIC=key HARDTOOLS_PUBLIC_KEY=$(openssl rand -hex 32) -a hardtools-mcp
# girişsiz ama yalnız okuma (0.5.1'in open davranışı):
fly secrets set HARDTOOLS_PUBLIC=open HARDTOOLS_PUBLIC_TOOLS=safe -a hardtools-mcp
```

- **`open` + tam araç seti kasten anonim bir kapı değildir.** Yazma, silme ve kabuk araçları ancak kimlik doğrulandıktan sonra listelenir. Token ya da GitHub OAuth tanımlı değilse sunucu açılışta uyarır ve her MCP isteği 401 döner (`/healthz` → `"login":"required"`).
- claude.ai istemcisi özel başlık gönderemediği için `open` modunda giriş **OAuth ile** yapılır: `HARDTOOLS_OAUTH_GITHUB_CLIENT_ID` + `HARDTOOLS_OAUTH_ALLOWED_LOGINS` (sır gerekmez, device flow) ya da GitHub'sız kurulumda `/authorize` sayfasındaki token formu. Ayrıntı: yukarıdaki OAuth bölümü.
- **Girişsiz modlar** (`key`, `open` + araç listesi): `/.well-known/oauth-*`, `/authorize`, `/register`, `/token` **404** döner, `www-authenticate` hiç gönderilmez, `GET /connect` (ve `GET /c/<anahtar>`) yapıştırılacak adresi gösteren Türkçe sayfayı döner.
- Girişsiz modlarda statik bearer ve OAuth akışı yine çalışır: aynı sunucu hem oturumsuz bağlayıcıya hem yetkili istemciye hizmet eder.
- `key` modunda adresi bilen tam yetkiye sahiptir; adresi paylaşacaksan `open` + araç listesi daha güvenli.

### Sunucu düşerse: gözcü + keepalive (0.5.1)

- **Konteyner gözcüsü** (`deploy/fly/entrypoint.sh`): node süreci çıkarsa üstel geri çekilmeyle (1→30 sn, 60 sn'den uzun çalışmadan sonra sıfırlanır) yeniden başlatır; `/healthz` üst üste 3 kez yanıtsız kalırsa süreci öldürüp geri getirir. Her yeniden başlatma `/data/supervisor.log` ve `/data/restarts` dosyasına yazılır.
- **Süreç içi watchdog (0.5.2)**: olay döngüsü **iki ölçüm üst üste** 30 saniyeden fazla kilitlenirse süreç kendini kapatır (`audit: watchdog_exit`); tek seferlik kısa donmalar (host taşıması, CPU kıtlığı) yeniden başlatma sebebi olmaz.
- **Keepalive** (`scripts/keepalive.sh` + `.github/workflows/keepalive.yml`): 5 dakikada bir `/healthz` yoklanır. Trial hesapta makine boşta duruyorsa bu istek onu uyandırır; üç deneme de başarısız olursa `FLY_API_TOKEN` varsa machines API'siyle makine yeniden başlatılır.
  ```bash
  HARDTOOLS_URL=https://hardtools-mcp.fly.dev FLY_APP=hardtools-mcp FLY_API_TOKEN=... scripts/keepalive.sh
  ```

### `ht_user_input` v2 (0.5.1)

- `fields[]` ile **tek formda birden çok soru** (8'e kadar). Yanıtlar `$HT_USER_INPUT` (JSON) ve her alan için `$HT_USER_INPUT_<AD>` olarak komutlara geçer.
- `choices` → açılır liste, `default` → önceden dolu değer, `placeholder`/`help` → form içi açıklama, `required` → boş bırakılamaz.
- `action=get` + `wait_seconds` (**1–120**) → **uzun yoklama**: model tek çağrıda kullanıcıyı bekler, "bir daha get çağır" turu gerekmez.
- `dedupe_key` → açık bir formu yeniden kullanır (ikinci bağlantı üretmez); `action=list` açık istekleri sayar.
- Tarayıcıda **Vazgeç** düğmesi (`action=cancel` → model `status=cancelled` görür), kalan süre bilgisi ve mobil uyumlu form.
- Sır alanları: modele `<secret>` döner, denetim kaydına yazılmaz, komut çıktısında `[redacted:HT_USER_INPUT]` ile maskelenir; yanıt sayfası sırrı bir daha göstermez.
- Örnek: `ht_user_input {title:"Yeni servis", fields:[{name:"ad",title:"Ad"},{name:"port",title:"Port",kind:"number",default:"8080"},{name:"mod",title:"Mod",choices:["dev","prod"]},{name:"token",title:"Token",secret:true,required:false}], wait_seconds:60}`

### 0.5.2 değişiklikleri

- **`HARDTOOLS_PUBLIC=open` artık tüm araçları açar ama girişi zorunlu tutar**: kimliksiz istek 401 + `www-authenticate`, OAuth keşfi yayınlanır, `/healthz` içinde `"login":"required"`. Girişsiz okuma modu `HARDTOOLS_PUBLIC_TOOLS=safe` (ya da kendi listeniz) ile korunur.
- **Watchdog iki ardışık kilitlenme ölçümü ister** (30 sn × 2); tek seferlik donma yeniden başlatmaya yol açmaz.
- **`open` + tam araç seti, giriş yapılandırılmamışsa açılışta uyarır** ve istekleri reddeder — yanlışlıkla "herkese açık tam yetki" durumuna düşülmez.

### 0.5.1'de düzeltilen hatalar

- **Konteyner girişi tek süreçti** (`exec node …`): node çökerse konteyner yeniden başlayana kadar sunucu kapalı kalıyordu. Artık gözcü döngüsü içinde çalışır (bkz. yukarısı).
- **IP başına hız sınırı tablosu hiç temizlenmiyordu**: uzun ömürlü sunucuda her yeni istemci IP'si kalıcı bir kayıt bırakıyordu (bellek sızıntısı). Süresi dolmuş pencereler artık atılıyor.
- **`clear` sırları unutuyordu**: çok alanlı formda alan alan sırlar maskeleme listesinden düşmüyordu; artık `clear` hem tek değeri hem form sırlarını listeden çıkarır.
- **Durum bilgisi eksikti**: süresi dolan/iptal edilen istek "pending" gibi görünüyordu; `status` artık `pending | ready | cancelled | expired`, ayrıca `filled` bayrağı sır dolu mu sorusunu değer sızdırmadan yanıtlar.
- **`/healthz` public modu bildirmiyordu**: izleme tarafı "oturum açma isteyen" ve "istemeyen" sunucuyu ayırt edemiyordu.

## Bilinen sınırlar (özet; ayrıntı `SECURITY.md`)
Windows'ta yerel `argv` doğrudan yürütülebilir dosya ister (`.cmd` shim yok), `command` ise `cmd.exe` kullanır, süreç ağacı `taskkill` ile öldürülür; asıl hedef Linux/macOS/WSL. `balanced` içindeki `npm test` gibi komutlar **proje betiklerini** çalıştırır. `open` profili sandbox değildir. Yol denetimi check-then-use (TOCTOU) artığı taşır.
