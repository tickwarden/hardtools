# Hardtools MCP — 7/24 uzak sunucu (Fly.io + özel alan adı)

Bu klasör, Hardtools'u **sürekli açık** tek bir HTTPS MCP sunucusu olarak yayınlar. GitHub Actions yayını gibi ~5 saat 45 dakika sonra kapanmaz, davet/kart üretmez; adres sabittir.

```
claude.ai / Claude Code  ──HTTPS──►  https://<alan-adın>/mcp   (Fly proxy TLS)
                                        │
                                        ├─ /mcp            MCP (OAuth 2.1 veya Bearer)
                                        ├─ /healthz        canlılık kontrolü
                                        └─ /data           kalıcı hacim (work + audit)
```

## Ne hazır, ne senin yapman gerekiyor

| Hazır (bu klasörde) | Senin hesabında olması gereken |
|---|---|
| `Dockerfile` (Node 22 + bubblewrap + git/curl), depo kökündeki `fly.toml` (7/24 ayarları, health check, volume) | Fly.io hesabı + kart |
| `entrypoint.sh` (hacmi hazırlar, token denetler), `config.json` (yazma + izole kabuk) | Alan adı (istersen) ve DNS erişimi |
| `deploy.sh` (uygulama/hacim/secret/sertifika/doğrulama) | `flyctl auth login` onayı |
| `/healthz` uç noktası (Host denetiminden önce yanıtlar) | — |

**Alan adı:** kayıt (satın alma) senin hesabında yapılır; ben ödeme/registrar işlemi yapamam. Alan adı yoksa `https://hardtools-mcp.fly.dev/mcp` adresi de geçerlidir ve claude.ai bağdaştırıcısıyla çalışır. Alan adı aldığında `--domain` ile aynı sunucuya bağlarsın.

Öneri (kayıt öncesi uygunluğu registrar'da doğrula): `hardtools-mcp.dev`, `hardtools.dev`, `mcp-hardtools.com`. `.dev` TLD'si yalnız HTTPS kabul eder; bu kurulum zaten HTTPS'dir.

## 1. Ön koşullar

```bash
curl -L https://fly.io/install.sh | sh          # flyctl
export FLYCTL_INSTALL="$HOME/.fly"; export PATH="$FLYCTL_INSTALL/bin:$PATH"
flyctl auth login                               # tarayıcıda cihaz akışı
```

Maliyet (yaklaşık, Fly fiyatlandırmasına göre): 1 paylaşımlı CPU/512 MB makine 7/24 ≈ aylık 3–5 USD; 3 GB hacim ≈ 0,30 USD. `auto_stop_machines = "off"` ve `min_machines_running = 1` olduğu için makine kapanmaz.

## 2. Dağıt

```bash
git clone https://github.com/tickwarden/hardtools && cd hardtools
bash deploy/fly/deploy.sh                       # fly.dev adresiyle
# ya da:
bash deploy/fly/deploy.sh --domain mcp.ornek.dev --region fra --size 3
```

Betik sırayla: uygulamayı oluşturur → `hardtools_data` hacmini açar → `HARDTOOLS_HTTP_TOKEN` üretir (ekrana basmaz, `deploy/fly/.env.local` dosyasına `0600` yazar) → `HARDTOOLS_ALLOWED_HOSTS` ayarlar → `flyctl deploy` → alan adı verildiyse sertifika ister → `/healthz` ile doğrular.

Uygulama adı global olarak doluysa: `bash deploy/fly/deploy.sh --app hardtools-mcp-$(openssl rand -hex 2)` ve depo kökündeki `fly.toml` içindeki `app` değerini aynı adla güncelle.

## 3. Özel alan adı + DNS

`deploy.sh --domain` sertifikayı ister; kayıtları alan adı sağlayıcında **sen** eklersin:

- Alt alan adı (`mcp.ornek.dev`): `CNAME  mcp → hardtools-mcp.fly.dev`
- Apex (`ornek.dev`): `flyctl certs show ornek.dev -a hardtools-mcp` çıktısındaki `A`/`AAAA` kayıtları
- `.dev`/`.app` gibi HSTS TLD'lerinde yalnız HTTPS kullanılır (Fly otomatik sertifika verir)

Sertifika durumu: `flyctl certs show mcp.ornek.dev -a hardtools-mcp` → `Status = Ready` olana kadar birkaç dakika sürebilir. **Alan adını ekledikten sonra `HARDTOOLS_ALLOWED_HOSTS` içinde de olmalı**, yoksa sunucu DNS-rebinding koruması gereği `403 host not allowed` döner; `deploy.sh --domain` bunu senin için ayarlar.

## 4. Claude'a bağla

- **claude.ai (web):** Ayarlar → **Bağdaştırıcılar → Özel bağdaştırıcı ekle** → ad `hardtools`, URL `https://mcp.ornek.dev/mcp` → devam → onay ekranında `HARDTOOLS_HTTP_TOKEN` değerini gir (`deploy/fly/.env.local`). OAuth keşfi (`/.well-known/oauth-authorization-server`, `/register`, PKCE S256) sunucuda hazır; istemci alanlarını boş bırak.
- **Claude Code / Desktop:** MCP listesine ekle:

```bash
claude mcp add --transport http hardtools https://mcp.ornek.dev/mcp \
  --header "Authorization: Bearer $(grep HARDTOOLS_HTTP_TOKEN deploy/fly/.env.local | cut -d= -f2)"
```

Doğrulama: sohbette `ht_status` çağır → `transport: http`, `shell.execution: workspace`, `shell.network: isolated` görünmeli.

## 5. 7/24 davranışı

- `min_machines_running = 1` + `auto_stop_machines = "off"`: makine istek gelmese de açık kalır.
- `[[http_service.checks]] path = "/healthz"`: 30 sn'de bir kontrol; üst üste başarısız olursa Fly makineyi değiştirir. `/healthz` yalnız sürüm, mod ve çalışma süresini döner; token, yol veya politika sızdırmaz.
- Sağlık kontrolü Host allowlist'inden **önce** yanıtlar; böylece beklenmeyen bir `Host` başlığı sağlıklı makineyi düşürmüş gibi göstermez.
- Makine yeniden başlarsa OAuth oturumları ve statik bearer geçerli kalır (token `secret` olarak saklanır); `/data` hacmi kalıcıdır.

## 6. Kalıcılık ve yedek

- `/data/work` → proje kökü (`HARDTOOLS_ROOTS`), `/data/audit` → denetim kaydı (`failClosed: true`, yani yazılamazsa işlem reddedilir).
- Fly hacim anlık görüntüleri: `flyctl volumes snapshots list hardtools_data -a hardtools-mcp`, elle: `flyctl volumes snapshots create hardtools_data -a hardtools-mcp`.
- Hacim tek bölgeye bağlıdır; bölge değiştirmek yeni hacim + veri taşıma ister.

## 7. Güvenlik notları

- Konteyner içinde süreç **root** çalışır (bubblewrap kullanıcı ad alanı ve `/data` yazımı için). Dışarıya yalnız 8787 açılır; TLS'i Fly proxy sonlandırır.
- HTTP modunda yazma ve kabuk yalnızca `HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=1` ile açılır (imajda varsayılan). Kapalı salt okunur mod için bu değişkeni `0` yap: `flyctl secrets set HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=0 -a hardtools-mcp`.
- `ht_shell` komutları ayrı PID/ağ ad alanında, proje kökü `/work` olarak bağlanmış şekilde çalışır; host ağı ve metadata kapalıdır. Genel HTTPS çıkışı için `HARDTOOLS_WORKSPACE_HTTPS=1` (varsayılan kapalı).
- `HARDTOOLS_HTTP_TOKEN` 32+ rastgele karakter; yalnız `flyctl secrets` içinde. Rotasyon: `flyctl secrets set HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)` → tüm istemcileri yeniden yetkilendir.
- Tek kullanıcı için tasarlandı. Birden çok kişiye açacaksan OAuth onay ekranındaki parolayı paylaşma; kişi başına ayrı sunucu ya da ayrı token kullan.

## 8. Sorun giderme

| Belirti | Neden / çözüm |
|---|---|
| `403 host not allowed` | Adres `HARDTOOLS_ALLOWED_HOSTS` içinde değil. `deploy.sh --domain` ile yeniden ayarla. |
| Makine `critical`, logda `bubblewrap`/`userns` hatası | İzole kabuk bu çekirdekte kurulamadı. `bash deploy/fly/deploy.sh --readwrite` ile yazma açık/kabuk kapalı yapılandırmaya geç; sunucu **host kabuğuna düşmez**. |
| `HARDTOOLS_HTTP_TOKEN yok veya kısa` | `flyctl secrets set HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)` |
| `/healthz` 502 | İlk açılış ~20 sn sürebilir (`grace_period`); sonra `flyctl logs` ve `flyctl checks list`. |
| OAuth onay ekranı açılmıyor | URL'nin `/mcp` ile bittiğini doğrula; `curl https://<adres>/.well-known/oauth-authorization-server` JSON dönmeli. |
| Sertifika `Not verified` | DNS kayıtları henüz yayılmamış; `flyctl certs show <domain>` çıktısını izle. |
| Token sızdı | Yeni token üret, eski istemcileri kaldır; audit kaydı `/data/audit` altında. |
