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
| `deploy.sh` (uygulama/hacim/secret/sertifika/doğrulama) + `.env.github.example` (GitHub girişi) | `flyctl auth login` onayı ve bir **GitHub OAuth App** (client ID + secret) |
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

## 4. GitHub ile giriş (önerilen OAuth, istemci sırrı gerekmez)

Onay ekranında token yapıştırmak yerine GitHub girişi kullanılır. Sunucu kendi OAuth kodlarını üretmeye devam eder; GitHub yalnızca "kim olduğunu" doğrular.

**Varsayılan akış GitHub device flow'dur:** istemci sırrı hiçbir yerde saklanmaz. Sunucu `/authorize` ekranında tek kullanımlık bir kod gösterir, kullanıcı https://github.com/login/device adresine girer, sayfa onayı yoklar ve hazır olunca Claude'a kodla döner.

1. GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**
   - Application name: `hardtools-mcp`
   - Homepage URL: `https://hardtools-mcp.fly.dev`
   - Authorization callback URL: `https://hardtools-mcp.fly.dev/oauth/github/callback` (yalnız yönlendirme akışını kullanacaksan gerekir)
   - ✔ **Enable Device Flow** ← sırsız akış için şart
2. Sadece **Client ID**'yi kopyala (sır değildir, paylaşılması güvenli).
3. `deploy/fly/.env.github` dosyasını oluştur (`.example` dosyasını kopyala, izinler `0600`):

```bash
install -m 600 deploy/fly/.env.github.example deploy/fly/.env.github
$EDITOR deploy/fly/.env.github     # CLIENT_ID + ALLOWED_LOGINS (GitHub kullanıcı adın)
bash deploy/fly/deploy.sh --app hardtools-mcp
```

`deploy.sh` bu dosyayı (ya da aynı adlı ortam değişkenlerini) Fly **secrets** olarak yazar; dosya `.gitignore` içinde, hiçbir değer stdout'a basılmaz.

| Değişken | Zorunlu | Ne işe yarar |
| --- | --- | --- |
| `HARDTOOLS_OAUTH_GITHUB_CLIENT_ID` | evet | OAuth App istemci kimliği (sır değil) |
| `HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET` | **hayır** | Doldurulursa device flow yerine tarayıcı yönlendirme akışı kullanılır |
| `HARDTOOLS_OAUTH_ALLOWED_LOGINS` | biri | virgülle GitHub kullanıcı adları |
| `HARDTOOLS_OAUTH_ALLOWED_EMAILS` | biri | virgülle doğrulanmış e-posta adresleri |

- İzin listesi boşsa sunucu **açılmaz** — "herkes girebilir" durumu oluşamaz.
- Yalnız `CLIENT_SECRET` verilirse yok sayılır (eksik yapılandırma yolu açmaz) ve token formu kalır.
- GitHub tanımlı değilken `/authorize` eski token formunu gösterir; `HARDTOOLS_HTTP_TOKEN` yalnızca **yedek** yoldur (Claude Code/Desktop başlığı, betikler).
- Güvenlik: `/oauth/github/poll` bileti 18 baytlık rastgele, imzalı state'e bağlı, tek kullanımlık ve GitHub'ın verdiği ömürle sınırlı (en fazla 15 dk). İzin listesinde olmayan hesap kod almaz; GitHub reddi/yeniden kullanım 403/410 ile kapanır, yönlendirme yapılmaz.

## 5. Claude'a bağla

- **claude.ai (web):** Ayarlar → **Bağdaştırıcılar → Özel bağdaştırıcı ekle** → ad `hardtools`, URL `https://mcp.ornek.dev/mcp` → devam → onay ekranında **GitHub ile giriş yap** (izin listesindeki hesap) → izin ver. OAuth keşfi (`/.well-known/oauth-authorization-server`, `/register`, PKCE S256) sunucuda hazır; istemci alanlarını boş bırak.
- **Claude Code / Desktop (token başlığı):**

```bash
claude mcp add --transport http hardtools https://mcp.ornek.dev/mcp \
  --header "Authorization: Bearer $(grep HARDTOOLS_HTTP_TOKEN deploy/fly/.env.local | cut -d= -f2)"
```

Doğrulama: sohbette `ht_status` çağır → `transport: http`, `shell.execution: workspace`, `shell.network: isolated` görünmeli.

Bağlantı "zaten var" hatası verirse claude.ai'deki eski/yarım kalmış `hardtools` kaydını sil ("Devam et" ile yarım kayıt oluşmuş olabilir), sonra tekrar ekle.

## 6. 7/24 davranışı

- `min_machines_running = 1` + `auto_stop_machines = "off"`: makine istek gelmese de açık kalır.
- `[[http_service.checks]] path = "/healthz"`: 30 sn'de bir kontrol; üst üste başarısız olursa Fly makineyi değiştirir. `/healthz` yalnız sürüm, mod ve çalışma süresini döner; token, yol veya politika sızdırmaz.
- Sağlık kontrolü Host allowlist'inden **önce** yanıtlar; böylece beklenmeyen bir `Host` başlığı sağlıklı makineyi düşürmüş gibi göstermez.
- Makine yeniden başlarsa OAuth oturumları ve statik bearer geçerli kalır (token `secret` olarak saklanır); `/data` hacmi kalıcıdır.

## 7. Kalıcılık ve yedek

- `/data/work` → proje kökü (`HARDTOOLS_ROOTS`), `/data/audit` → denetim kaydı (`failClosed: true`, yani yazılamazsa işlem reddedilir).
- Fly hacim anlık görüntüleri: `flyctl volumes snapshots list hardtools_data -a hardtools-mcp`, elle: `flyctl volumes snapshots create hardtools_data -a hardtools-mcp`.
- Hacim tek bölgeye bağlıdır; bölge değiştirmek yeni hacim + veri taşıma ister.

## 8. Güvenlik notları

- Konteyner içinde süreç **root** çalışır (bubblewrap kullanıcı ad alanı ve `/data` yazımı için). Dışarıya yalnız 8787 açılır; TLS'i Fly proxy sonlandırır.
- HTTP modunda yazma ve kabuk yalnızca `HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=1` ile açılır (imajda varsayılan). Kapalı salt okunur mod için bu değişkeni `0` yap: `flyctl secrets set HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=0 -a hardtools-mcp`.
- `ht_shell` komutları ayrı PID/ağ ad alanında, proje kökü `/work` olarak bağlanmış şekilde çalışır; host ağı ve metadata kapalıdır. Genel HTTPS çıkışı için `HARDTOOLS_WORKSPACE_HTTPS=1` (varsayılan kapalı).
- `HARDTOOLS_HTTP_TOKEN` 32+ rastgele karakter; yalnız `flyctl secrets` içinde. Rotasyon: `flyctl secrets set HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)` → tüm istemcileri yeniden yetkilendir.
- Tek kullanıcı için tasarlandı. Erişim `HARDTOOLS_OAUTH_ALLOWED_LOGINS`/`_EMAILS` ile sınırlanır; listeden çıkarmak o kişinin bir sonraki girişini engeller (verilmiş oturumlar `flyctl secrets set HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)` ile topluca iptal edilir).
- GitHub client secret yalnız `flyctl secrets` ve `deploy/fly/.env.github` (0600, gitignore) içinde tutulur; ekran görüntüsüne/log'a düşürülmemeli.

## 9. Sorun giderme

| Belirti | Neden / çözüm |
|---|---|
| `403 host not allowed` | Adres `HARDTOOLS_ALLOWED_HOSTS` içinde değil. `deploy.sh --domain` ile yeniden ayarla. |
| Makine `critical`, logda `bubblewrap`/`userns` hatası | İzole kabuk bu çekirdekte kurulamadı. `bash deploy/fly/deploy.sh --readwrite` ile yazma açık/kabuk kapalı yapılandırmaya geç; sunucu **host kabuğuna düşmez**. |
| `HARDTOOLS_HTTP_TOKEN yok veya kısa` | `flyctl secrets set HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32)` |
| `/healthz` 502 | İlk açılış ~20 sn sürebilir (`grace_period`); sonra `flyctl logs` ve `flyctl checks list`. |
| OAuth onay ekranı açılmıyor | URL'nin `/mcp` ile bittiğini doğrula; `curl https://<adres>/.well-known/oauth-authorization-server` JSON dönmeli. |
| Sertifika `Not verified` | DNS kayıtları henüz yayılmamış; `flyctl certs show <domain>` çıktısını izle. |
| Token sızdı | Yeni token üret, eski istemcileri kaldır; audit kaydı `/data/audit` altında. |
| Onay ekranında hâlâ token formu | `HARDTOOLS_OAUTH_GITHUB_CLIENT_ID` makineye ulaşmamış. `flyctl secrets list` “Staged” diyorsa `flyctl secrets deploy`; sonra `flyctl secrets set` ile herhangi bir değeri yeniden yaz (secret enjeksiyonu bazen ilk denemede görünmez). |
| `GitHub'dan giriş kodu alınamadı` | İki olası sebep: (1) secret'ta **Client ID değil** uygulama numarası var (`/settings/applications/4043388` gibi 7 hane); Client ID 20 karakterdir ve `Ov23li…` ile başlar. (2) OAuth App'te **Enable Device Flow** işaretsiz (General sekmesi → `Update application`). |
| Device flow'un açık olduğunu doğrula | `curl -s -X POST https://github.com/login/device/code -H 'Accept: application/json' -d "client_id=<CID>&scope=read:user"` → `device_code` dönerse hazır; `invalid_scope` ID geçerli demektir (geçersiz kapsamla denenebilir); `Not Found` ise ID yanlış. |
| GitHub hesabı reddedildi (`403`) | Giriş yapan hesap `HARDTOOLS_OAUTH_ALLOWED_LOGINS`/`_EMAILS` listesinde değil. Listeyi güncelledikten sonra `flyctl secrets deploy`. |
| `Makine 5 dk’da bir duruyor` | Fly hesabı **deneme (trial)** modunda: logda `Trial machine stopping. To run for longer than 5m0s, add a credit card`. Çözüm hesap sahibinin kart eklemesidir; `fly.toml` ayarları bunu engellemez. |
