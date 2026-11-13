# hardtools

Claude'un yerleşik dosya/arama/kabuk/web araçlarının **sınırlandırılmış, denetlenebilir** karşılıkları. Tek bir MCP sunucusu; Claude Code, Claude Desktop (stdio) ve uzak MCP (HTTP) üzerinden çalışır.

> **Durum:** v0.2.0, kod AI tarafından yazıldı (bkz. `CREDITS.md`). 37 otomatik test geçiyor, ama bağımsız insan güvenlik incelemesi yapılmadı. Claude Code / Desktop / claude.ai içinde **gerçek yükleme burada denenmedi**; testler MCP SDK istemcisi ve ham HTTP ile yapıldı.

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
npm install && npm test          # 37 test (derleme dahil)
npm run bundle                   # bundle/index.js (node_modules gerekmez)
```

### Claude Code (plugin)
Klasörü plugin olarak yükle (`.claude-plugin/plugin.json` + `.mcp.json` hazır; sunucu `${CLAUDE_PLUGIN_ROOT}/bundle/index.js` ile başlar). Yerelde denemek için `claude --plugin-dir ./hardtools`; yükleme sorunlarında `claude --debug`. Kök dizin = sunucunun çalışma dizini; `/` veya ev dizini olursa **başlamayı reddeder**.
**Önemli:** yerleşik `Bash/Edit/Write/WebFetch` kapatılmazsa Claude onları kullanmaya devam eder ve bu eklenti güvenliği artırmaz, sadece seçenek ekler. `claude-code-settings.example.json`'a bak (sözdizimini sürümünde doğrula).

### Claude Desktop (stdio)
`claude_desktop_config.example.json` içeriğini Desktop'un MCP yapılandırmasına ekle. Desktop'ta çalışma dizini proje olmadığı için `HARDTOOLS_ROOTS` **zorunlu** pratikte.

### Uzak / HTTP modu (web dahil: **sınırlı**)
```bash
export HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)
node bundle/index.js --http --port 8787 --profile balanced      # 127.0.0.1'e bağlanır
```
- Sabit bearer token **Claude Code / Desktop** için uygundur (istek başlığı gönderebilirler).
- **claude.ai web** custom connector arayüzü genelde **OAuth** bekler; bu projede OAuth sunucusu **yok**. Web için önüne OAuth yapan bir geçit koymak gerekir (yapılmadı, test edilmedi).
- Uzak modda `ht_shell` ve yazma araçları varsayılan **kapalı** (sunucunun dosya sistemi senin makinen değil). Açmak: `HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=1` (önerilmez). TLS sonlandırma (ters vekil/tünel) senin sorumluluğunda; Host doğrulaması için `HARDTOOLS_ALLOWED_HOSTS=alanadi.com`.

## Bilinen sınırlar (özet; ayrıntı `SECURITY.md`)
Windows'ta `ht_shell` yalnızca `.exe` çalıştırır (`.cmd` shim yok), süreç ağacı `taskkill` ile öldürülür; asıl hedef Linux/macOS/WSL. `balanced` içindeki `npm test` gibi komutlar **proje betiklerini** çalıştırır. `open` profili sandbox değildir. Yol denetimi check-then-use (TOCTOU) artığı taşır.
