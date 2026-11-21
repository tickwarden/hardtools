# SECURITY

## "2 kat daha güvenli" ne demek?

Yerleşik araçların iç uygulamasını göremiyorum, bu yüzden **"2×" ölçülebilir bir iddia değil** ve ben böyle bir sayı vermiyorum. Onun yerine aşağıda 26 somut, **her biri testle doğrulanan** özellik var. Her satırdaki testin bozulduğunda gerçekten başarısız olduğu, koda bilinçli hata sokularak (mutation) denendi: sınır kontrolünü, özel-IP kontrolünü ve env temizliğini kapatınca ilgili testler kırıldı.

Yerleşik araçların kendi izin sistemi/sandbox'ı varsa o da geçerlidir. hardtools onların **yerine değil, üstüne** ek bir katmandır ve yalnızca yerleşik araçlar kapatıldığında tek yol olur.

## Tehdit modeli
1. **Model hatası / istem enjeksiyonu**: model, web sayfası veya repo içeriğinden gelen talimatla zararlı bir araç çağrısı yapar.
2. **Kötü niyetli repo**: yapılandırma, PATH veya hook yoluyla kod çalıştırmaya çalışır.
3. **Yanlışlıkla hasar**: yarım kalmış çok dosyalı düzenleme, ezilen dosya, sızan gizli veri.

Kapsam dışı: ele geçirilmiş işletim sistemi, kötü niyetli kullanıcı (politikayı o yazar), çekirdek/kapsayıcı kaçışı.

## Özellikler ve kanıtları
| # | Özellik | Test (`test/*.test.mjs`) |
|---|---|---|
| 1 | Gerçek yol (realpath) kök kısıtı; `..`, mutlak yol, NUL | fs: path traversal… |
| 2 | Symlink kaçışı ve boşta (dangling) symlink yazımı engeli | fs: symlink escape… |
| 3 | `.env`, anahtar dosyaları okunamaz, listelemede ve aramada gizli | fs: secret files…, search: skips… |
| 4 | `.git`, `.claude`, `.mcp.json` (strict: workflows, vscode, devcontainer) yazılamaz | fs: writes to .git… |
| 5 | Audit/konfig dizini kök içinde olsa bile korunur | fs: the audit/config directory… |
| 6 | Politika çalışma alanından **asla** yüklenmez | config: a policy file inside the workspace… |
| 7 | Yazılan içerikte gizli veri taraması (blok/uyarı/kapalı) | fs: secrets in written content… |
| 8 | Üzerine yazma yok; `overwrite` + `if_hash` ister (görmediğini ezemezsin) | fs: write never clobbers… |
| 9 | Çok dosyalı düzenleme ya hep ya hiç (doğrulama aşaması) | edit: all-or-nothing… |
| 10 | Yazma aşamasında hata → önceki dosyalar geri alınır | edit: a failure during the commit phase… |
| 11 | Hazırlık ile yazma arasında dış değişiklik tespit edilir, hiçbir şey yazılmaz | edit: a concurrent modification… |
| 12 | İkili/geçersiz UTF-8 reddi; CRLF ve BOM korunur; `$&` literal | edit: CRLF…, edit: if_hash… |
| 13 | Boyut limitleri | fs: size limits… |
| 14 | Kabuksuz argv; `;`, `$()` literal kalır | shell: no shell interpretation… |
| 15 | `denyCommands`/`denyArgs` operatör tarafından doldurulabilir; varsayılan listeler boştur | shell: no command denylist… |
| 16 | Argüman yol sınırlaması (`/etc`, `../..`, `--x=/etc`, `~`) | shell: arg_path_outside_roots… |
| 17 | Env'den gizli veri temizliği (TOKEN/SECRET/KEY… + `HARDTOOLS_*`) | shell: secrets are scrubbed… |
| 18 | Çalışma alanı içindeki PATH girdileri atılır (repo içine konan sahte `git`) | shell: PATH entries… |
| 19 | Zaman aşımı + süreç grubu öldürme + çıktı sınırı (baş+son), deny desenleri | shell: timeout kills… |
| 20 | Arama symlink izlemez; ikili/gizli/gitignore atlanır | search: skips… |
| 21 | ReDoS: bütçe aşılınca worker öldürülür | search: a catastrophic regex… |
| 22 | SSRF: özel/loopback/link-local/metadata/IPv4-eşlemeli IPv6; `2130706433`, `0x7f.1`, `127.1` biçimleri | net: reserved…, net: literal private… |
| 23 | Yönlendirmede yeniden doğrulama; bağlantı anında IP doğrulama (DNS rebinding'e karşı); `localhost` çözümlemesi | net: live behaviour… |
| 24 | Boyut/süre/sıkıştırma-bombası (60 MB → 100 KB'ta kesilir), `ht_fetch` için yalnızca metin içerik türleri | net: live behaviour… |
| 25 | Tamper-**evident** audit zinciri (düzenleme/silme/yer değiştirme tespit edilir), gizli veri maskeleme, strict'te fail-closed | audit: hash chain… |
| 26 | Yapılandırma typo'sunda hata; kök olarak `/` ve ev dizini reddi; HTTP: güçlü token zorunlu, sabit-zamanlı karşılaştırma, Host/Origin denetimi, uzak modda kabuk+yazma kapalı | config: typo'd…, e2e/* |

Henüz **testsiz**: HTTP hız sınırlaması, `ht_fetch` içindeki enjeksiyon-sezgisinin kalitesi (sezgisel, kanıt değil), Windows davranışı.

## Kalan riskler (dürüst liste)
- **TOCTOU**: yol, kontrol edildiği an ile kullanıldığı an arasında değiştirilebilir (yarış). `O_NOFOLLOW` + geçici dosya/rename ile azaltıldı, tamamen kapatılmadı. Güvenmediğin bir süreç aynı dizinde eşzamanlı çalışıyorsa sandbox/ayrı kullanıcı kullan.
- **Komut çalıştırma proje koduna güvenmeyi gerektirir.** `git` yapılandırma/hook, `npm test` ve benzeri komutlar proje betikleri çalıştırabilir. Varsayılan `strict` profili bunları komut adıyla engellemez. Güvenilmeyen projeler için kabuğu kapat veya yalıtılmış bir kullanıcı/kapsayıcı kullan.
- **`open` profili sandbox değildir**: kabuk desenleri regex tabanlı tripwire; atlatılabilir.
- **Argüman yol denetimi sezgiseldir** (`/`, `\`, `.`, `~` içeren argümanlar). Komutun kendi iç yolu çözmesini (örn. `@dosya` sözdizimi) bilemez.
- **`ht_fetch` ile veri sızdırma**: `allowDomains` boşsa model URL sorgu dizesiyle veri taşıyabilir. `strict` allowlist'i zorunlu kılar; `balanced`'ta kendin doldur.
- **İstem enjeksiyonu çözülmüş değil**: `<untrusted_web_content>` sarmalı ve sezgisel uyarılar riski azaltır, ortadan kaldırmaz.
- **Audit tail-truncation'ı** (dosya sonunu kesme) tespit edilmez; zincir yalnızca ortadaki değişikliği yakalar. Dosya süreç başına ayrıdır; sahibi aynı kullanıcıysa yine de silebilir. Kritikse log'u uzak yere gönder.
- **Windows**: `.cmd` shim çalışmaz, `O_NOFOLLOW` yok, izin bitleri anlamsız. Asıl hedef Linux/macOS/WSL.
- **Kaynak limitleri** (CPU/bellek ulimit) kabuk komutlarına uygulanmaz; süre ve çıktı limiti vardır.
- **Remote HTTP mode**: no TLS (a reverse proxy/tunnel is required). A minimal stateless OAuth 2.1 server (`src/oauth.ts`) serves the claude.ai connector dialog; its consent page is gated by `HARDTOOLS_HTTP_TOKEN`. Tokens are HMAC-signed and derived from that secret (nothing is stored; codes are single-use only per process). The consent-failure throttle is global (a tunnel hides client IPs). The MCP endpoint is `/mcp` only; use OAuth or the Authorization header, never a token in the URL. Tested by `test/oauth.test.mjs`; not independently reviewed.

- **Bağlantı kartı**: Güvendiğin run’ın `hardtools-connect/BAGLAN.html` dosyasını yerelde aç. Yeni kartlarda yalnızca run koordinatları herkese açıktır. Her pakette rastgele 16 bayt salt + 12 bayt IV kullanılır. PBKDF2-SHA-256 (600.000 tur) ve AES-256-GCM ile davet/token korunur; sürüm, run numarası, mod, run URL’si ve endpoint ek doğrulama verisidir. Artifact indirilebildiğinden güçlü, bu işe özel bir parola gereklidir; kısa/tahmin edilebilir parola çevrimdışı tahmine açıktır. `HARDTOOLS_CONNECT_PASSWORD` yalnızca manuel yayın/test ön kontrolü ve kart oluşturma adımlarına verilir, uzun süre çalışan MCP/tünel süreçlerine, dispatch girdilerine veya artifact’a yazılmaz. Parolayı bilen kişi aynı parola ile yayımlanan kartları açabilir; misafire parola yerine tek kullanımlık davet ver. Kart dosya seçimini/şifre çözmeyi önizlemede kapatır ve CSP ile ağ isteklerini engeller. Pano geçmişi tarayıcının dışındadır. Eski age paketleri için yalnızca yerel okuma desteği kalmıştır.

## v0.2.0 araçları (ht_glob / ht_mkdir / ht_move / ht_trash)
- Hepsi `resolveSafe` ile aynı kök/symlink/korumalı yol denetimini kullanır; `ht_mkdir/move/trash` yazma politikasına (`fs.writeEnabled`) bağlıdır (uzak HTTP modunda varsayılan kapalı).
- `ht_move` dosyalarda `link()+unlink()` ile atomik no-clobber sağlar; **dizin** taşımada `exists` kontrolü ile `rename()` arasında küçük bir TOCTOU penceresi vardır. Dosya sistemleri arası taşıma (`EXDEV`) reddedilir.
- `.ht-trash/` kökün içindedir ve diskte yer kaplamaya devam eder; temizliği onaylı `ht_empty_trash` ile yapılır. Çöpteki kayıtlar `ht_search`'ün arama kapsamında olabilir (kendi `.gitignore`'una ekle).
- `ht_glob` süslü parantez (`{a,b}`) desteklemez ve büyük/küçük harfe duyarsızdır (kasıtlı: fazla-reddet).

## Kabuk ve paylaşım sınırları

- `shell.denyCommands`, `shell.denyArgs` ve `shell.shellDenyPatterns` varsayılan olarak **boş**. Açık olan kabuk, işletim sisteminin tüm güvenlik sınırlarının yerini tutmaz. `strict` ve `balanced` doğrudan `command` sözdizimini kapatır; izinli bir yorumlayıcının kendi yapabileceklerini sınırlamaz. Özellikle Git komutlarına/yıkıcı komutlara karşı yerleşik bir blok varmış gibi davranma. Uzak modda kabuk ve yazma ayrıca açıkça etkinleştirilmelidir.
- `ht_add_var` değerleri isim listesinde ve audit'te saklanmaz; yalnız seçilirse çocuğa aktarılır. Komutun kendisi bunları yazdırabilir. Aynı statik bearer aynı yetkilendirmedir; ayrı OAuth onayları ayrı değişken/paylaşım kümeleridir. Bu ayrım ortak runner dosya sistemini veya etkinleştirilmiş `ht_shell` işlemlerini birbirinden izole etmez.
- `ht_share` sabit bir dosya kopyası verir; ağ isteğinin yolunu diskte çözmez. Yalnızca açıkça oluşturulmuş, tahmin edilemez, süresi dolmamış 256 bitlik bağlantı ile HTTP indirmesi yapılabilir. Bağlantının kendisi sırdır: araç çıktısını herkese açık loglara kopyalama. İptal/son kullanma, indirilmiş kopyaları silemez. Yeni paylaşım yazma iznine, kaynak dosya okuma politikasına tabidir; tek bağlı normal dosya, boyut kotası ve gizli veri taraması uygulanır (tarama kusursuz değildir). İndirme zorunlu dosya eki, `no-store`, `nosniff` ve `no-referrer` ile döner. Ekteki dosya yine de güvenilmeyen içeriktir.
- `ht_empty_trash` yalnızca yapılandırılmış bir kökün gerçek `.ht-trash` dizinini boşaltabilir; symlink hedefleri izlenmez, başka dosya sistemine geçilmez ve korumalı yollar işlem öncesinde reddedilir. Açık onay gerektirir; bir dosya sistemi hatası ya da eşzamanlı değişiklik boşaltma sırasında olursa işlem kısmi kalabilir.
- `ht_image_search` sabit HTTPS kaynakları kullanır; tüm yönlendirme ve adresler ağ politikasına tabidir. En çok üç küçük raster döndürür; veri türü, dosya başlığındaki boyutlar, ağ bütçesi ve süre sınırı denetlenir. Sağlayıcı verileri, lisans alanları ve görseller **güvenilmeyen içeriktir**; tam bir görüntü çözücü veya içerik moderasyonu yapılmaz. Testler: `test/workspace.test.mjs`, `test/image-search.test.mjs`, `test/oauth.test.mjs`.
