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
| 15 | Blocklist (`denyCommands`: yıkıcı komutlar, sarmalayıcılar, git geçmişi/repo silme); `git -c …` gibi seçenek enjeksiyonu engeli, `denyArgs` | shell: command_denied / arg_denied… |
| 16 | Argüman yol sınırlaması (`/etc`, `../..`, `--x=/etc`, `~`) | shell: arg_path_outside_roots… |
| 17 | Env'den gizli veri temizliği (TOKEN/SECRET/KEY… + `HARDTOOLS_*`) | shell: secrets are scrubbed… |
| 18 | Çalışma alanı içindeki PATH girdileri atılır (repo içine konan sahte `git`) | shell: PATH entries… |
| 19 | Zaman aşımı + süreç grubu öldürme + çıktı sınırı (baş+son), deny desenleri | shell: timeout kills… |
| 20 | Arama symlink izlemez; ikili/gizli/gitignore atlanır | search: skips… |
| 21 | ReDoS: bütçe aşılınca worker öldürülür | search: a catastrophic regex… |
| 22 | SSRF: özel/loopback/link-local/metadata/IPv4-eşlemeli IPv6; `2130706433`, `0x7f.1`, `127.1` biçimleri | net: reserved…, net: literal private… |
| 23 | Yönlendirmede yeniden doğrulama; bağlantı anında IP doğrulama (DNS rebinding'e karşı); `localhost` çözümlemesi | net: live behaviour… |
| 24 | Boyut/süre/sıkıştırma-bombası (60 MB → 100 KB'ta kesilir), yalnızca metin içerik türleri | net: live behaviour… |
| 25 | Tamper-**evident** audit zinciri (düzenleme/silme/yer değiştirme tespit edilir), gizli veri maskeleme, strict'te fail-closed | audit: hash chain… |
| 26 | Yapılandırma typo'sunda hata; kök olarak `/` ve ev dizini reddi; HTTP: güçlü token zorunlu, sabit-zamanlı karşılaştırma, Host/Origin denetimi, uzak modda kabuk+yazma kapalı | config: typo'd…, e2e/* |

Henüz **testsiz**: HTTP hız sınırlaması, `ht_fetch` içindeki enjeksiyon-sezgisinin kalitesi (sezgisel, kanıt değil), Windows davranışı.

## Kalan riskler (dürüst liste)
- **TOCTOU**: yol, kontrol edildiği an ile kullanıldığı an arasında değiştirilebilir (yarış). `O_NOFOLLOW` + geçici dosya/rename ile azaltıldı, tamamen kapatılmadı. Güvenmediğin bir süreç aynı dizinde eşzamanlı çalışıyorsa sandbox/ayrı kullanıcı kullan.
- **`git` repo yapılandırmasını çalıştırır (v0.2.0'da DOĞRULANDI, giderilmedi):** `ht_shell` ile `git status` çalıştırmak, repo içindeki `.git/config`'te tanımlı `core.fsmonitor` komutunu çalıştırır (test: `fsmonitor = touch <dosya>` → dosya oluştu). Yani güvenilmeyen/klonlanmış bir repo allowlist'i atlayıp komut çalıştırabilir. `git add/checkout/commit` ise filtre ve hook çalıştırabilir. Salt-okunur git komutları için `-c core.fsmonitor=false -c core.hooksPath=/dev/null` ve `--no-ext-diff --no-textconv` enjekte etmek riski büyük ölçüde azaltır ama yazan komutlarda repo yapılandırmasına güvenmek kaçınılmaz. Güvenmediğin repoda `git`'i allowlist'ten çıkar veya `strict` kullan. Bu yüzden `ht_git` aracı eklenmedi.
- **`balanced` içindeki `npm test`, `cargo test`, `go test`…** repo içindeki kodu çalıştırır; blocklist bunu engelleyemez. Güvenmediğin repoda `strict` kullan.
- **`strict` blocklist'i bile** `git diff/show` ile takip edilen bir `.env` içeriğini gösterebilir (yol argümanı olarak görünmez). Gizli dosyaları repoya koyma.
- **`open` profili sandbox değildir**: kabuk desenleri regex tabanlı tripwire; atlatılabilir.
- **Argüman yol denetimi sezgiseldir** (`/`, `\`, `.`, `~` içeren argümanlar). Komutun kendi iç yolu çözmesini (örn. `@dosya` sözdizimi) bilemez.
- **`ht_fetch` ile veri sızdırma**: `allowDomains` boşsa model URL sorgu dizesiyle veri taşıyabilir. `strict` allowlist'i zorunlu kılar; `balanced`'ta kendin doldur.
- **İstem enjeksiyonu çözülmüş değil**: `<untrusted_web_content>` sarmalı ve sezgisel uyarılar riski azaltır, ortadan kaldırmaz.
- **Audit tail-truncation'ı** (dosya sonunu kesme) tespit edilmez; zincir yalnızca ortadaki değişikliği yakalar. Dosya süreç başına ayrıdır; sahibi aynı kullanıcıysa yine de silebilir. Kritikse log'u uzak yere gönder.
- **Windows**: `.cmd` shim çalışmaz, `O_NOFOLLOW` yok, izin bitleri anlamsız. Asıl hedef Linux/macOS/WSL.
- **Kaynak limitleri** (CPU/bellek ulimit) kabuk komutlarına uygulanmaz; süre ve çıktı limiti vardır.
- **Uzak HTTP modu**: OAuth yok, TLS yok (ters vekil gerekir), claude.ai web'in kimlik doğrulama beklentisi karşılanmıyor.

## v0.2.0 araçları (ht_glob / ht_mkdir / ht_move / ht_trash)
- Hepsi `resolveSafe` ile aynı kök/symlink/korumalı yol denetimini kullanır; `ht_mkdir/move/trash` yazma politikasına (`fs.writeEnabled`) bağlıdır (uzak HTTP modunda varsayılan kapalı).
- `ht_move` dosyalarda `link()+unlink()` ile atomik no-clobber sağlar; **dizin** taşımada `exists` kontrolü ile `rename()` arasında küçük bir TOCTOU penceresi vardır. Dosya sistemleri arası taşıma (`EXDEV`) reddedilir.
- `.ht-trash/` kökün içindedir ve diskte yer kaplamaya devam eder; temizliği elle yapılır. Çöpteki kayıtlar `ht_search`'ün arama kapsamında olabilir (kendi `.gitignore`'una ekle).
- `ht_glob` süslü parantez (`{a,b}`) desteklemez ve büyük/küçük harfe duyarsızdır (kasıtlı: fazla-reddet).

## Blocklist modeli (allowlist kaldırıldı)

`shell.allow` kaldırıldı; yerine `shell.denyCommands` (regex, `komutAdı arg…` satırına karşı) geldi. Bilinen sonuçlar:

- **Listede olmayan her komut çalışır** (`python3`, `node`, `curl`/`wget`, `git push` (force dahil), `make`, derleyiciler…). Blocklist bir güvenlik sınırı değildir; tüm profillerde (strict dahil) varsayılan-reddet garantisi yoktur.
- **Atlatma yolları açık:** yorumlayıcıyla satır içi kod (`python3 script.py`, `node x.js`), listede olmayan sarmalayıcılar, farklı yazımlar. `DENY_BYPASS` (sh/bash/env/xargs…) yalnızca strict ve balanced'ta argv için engellenir; `open`'da kabuk sözdizimi zaten serbesttir.
- **`open`'da `command=` için** yalnızca `shellDenyPatterns` regex tripwire'ları çalışır; bunlar kararlı bir çağıran tarafından atlatılabilir.
- **Git koruması:** `reset --hard`, `branch -D`, `gc --prune`, `gh repo delete|transfer` engellenir. `push` (force dahil), `filter-branch/filter-repo`, `update-ref` ve `gh api -X DELETE` artık engellenmez; open profilindeki `shellDenyPatterns` tripwire'ları (force push, filter-branch, `gh repo delete|rename|transfer`) yalnızca `command` (kabuk sözdizimi) için geçerlidir.
- Mevcut `core.fsmonitor` riski (yukarıda) artık `git` dışındaki daha çok komut için de geçerlidir.
