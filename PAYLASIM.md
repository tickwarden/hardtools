# Başkası nasıl bağlanır

Üç ayrı yol var. **Plugin linki paylaşılmaz** — claude.ai'deki `claude.ai/plugins/id/plugin_…` adresi hesap kapsamlıdır; başkası açınca "Bu öğe kullanılamıyor" görür.

## 1) En kolay: uzak bağlayıcı (kurulum yok, herkes)

Herkese açık: `https://hardtools-mcp.fly.dev/mcp`

1. claude.ai → **Ayarlar → Bağlayıcılar (Connectors) → Özel bağlayıcı ekle**
2. Ad: `hardtools`
3. URL: `https://hardtools-mcp.fly.dev/mcp`
4. OAuth client ID / secret alanlarını **boş bırak** → **Bağlan**
5. Açılan sayfada **GitHub ile giriş** (herhangi bir GitHub hesabı yeter)
6. Sohbeti aç, `+` → Bağlayıcılar → `hardtools` → araçlar hazır

Claude Code için aynısı: `claude mcp add --transport http hardtools https://hardtools-mcp.fly.dev/mcp`

## 2) Claude Code'da yerel plugin (kendi makinesinde çalışır)

```
/plugin marketplace add tickwarden/hardtools
/plugin install hardtools@hardtools-marketplace
```

Kurulumdan sonra `/plugin configure hardtools@hardtools-marketplace` ile proje klasörünü seç.

## 3) Sadece davetli / özel sunucu

Kendi sunucunu kurduysan: davet kodu üret → davet linkini kişiye gönder → o link bir kez açılır, hangi `/mcp` adresini kullanacağını söyler. Ayrıntısı README'de.

## Ne paylaşılır, ne paylaşılmaz

| Paylaş | Paylaşma |
| --- | --- |
| `/mcp` adresi | `claude.ai/plugins/id/plugin_…` linki |
| Depo adresi (`tickwarden/hardtools`) | Erişim token'ı, parola |
| Davet linki (yalnızca tek kişiye) | `.env`, audit dosyaları |

## Sınırlar (bilerek)

- Giriş **her GitHub hesabına** açık (`HARDTOOLS_OAUTH_ALLOW_ANY=1`) — bu bir erişim sınırı değil, kimlik doğrulamadır. Kapatmak için değişkeni sil, `HARDTOOLS_OAUTH_ALLOWED_LOGINS` ver.
- Her sohbet kendi `/work` kökünü alır; değişkenler/sırlar hesap bazlı.
- Fly deneme makinesi 5 dakikada bir yeniden başlıyor: cevaplar diskte kalır ama kısa kesintiler olur.
