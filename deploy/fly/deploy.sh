#!/usr/bin/env bash
# Hardtools MCP'yi Fly.io'da 7/24 çalışacak şekilde kurar.
# Gizli değer üretir ama ekrana basmaz; hiçbir token depoya yazılmaz.
#
# Kullanım:
#   bash deploy/fly/deploy.sh                       # hardtools-mcp.fly.dev
#   bash deploy/fly/deploy.sh --domain mcp.ornek.dev
#   bash deploy/fly/deploy.sh --app baska-ad --region ams --size 3
#   bash deploy/fly/deploy.sh --readwrite           # izole kabuk yerine yalnız yazma
set -euo pipefail

APP="hardtools-mcp"
REGION="fra"
SIZE="3"
DOMAIN=""
CONFIG="/etc/hardtools/config.json"
CONFIG_OVERRIDE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --app) APP="${2:?}"; shift 2 ;;
    --region) REGION="${2:?}"; shift 2 ;;
    --size) SIZE="${2:?}"; shift 2 ;;
    --domain) DOMAIN="${2:?}"; shift 2 ;;
    --readwrite) CONFIG_OVERRIDE="/etc/hardtools/config-readwrite.json"; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "bilinmeyen argüman: $1" >&2; exit 2 ;;
  esac
done

command -v flyctl >/dev/null 2>&1 || { echo "flyctl gerekli: https://fly.io/docs/flyctl/install/" >&2; exit 1; }
flyctl auth whoami >/dev/null 2>&1 || { echo "önce 'flyctl auth login' (cihaz akışı) çalıştır" >&2; exit 1; }

echo "== uygulama ve hacim"
flyctl apps create "$APP" 2>/dev/null || echo "uygulama zaten var: $APP"
if ! flyctl volumes list -a "$APP" 2>/dev/null | grep -q "hardtools_data"; then
  flyctl volumes create hardtools_data --region "$REGION" --size "$SIZE" --yes -a "$APP"
fi

echo "== gizli değerler"
if ! flyctl secrets list -a "$APP" 2>/dev/null | grep -q "HARDTOOLS_HTTP_TOKEN"; then
  TOKEN="$(openssl rand -hex 32)"
  install -m 600 /dev/null deploy/fly/.env.local
  printf 'HARDTOOLS_HTTP_TOKEN=%s\n' "$TOKEN" > deploy/fly/.env.local
  flyctl secrets set HARDTOOLS_HTTP_TOKEN="$TOKEN" -a "$APP" >/dev/null
  unset TOKEN
  echo "yeni bearer token deploy/fly/.env.local dosyasına yazıldı (0600). Parola yöneticine taşı."
else
  echo "HARDTOOLS_HTTP_TOKEN zaten tanımlı; korunuyor (aynı değeri yeniden üretmiyoruz)."
fi

HOSTS="$APP.fly.dev,127.0.0.1:8787"
[ -n "$DOMAIN" ] && HOSTS="$HOSTS,$DOMAIN"
flyctl secrets set HARDTOOLS_ALLOWED_HOSTS="$HOSTS" -a "$APP" >/dev/null
if [ -n "$CONFIG_OVERRIDE" ]; then
  flyctl secrets set HARDTOOLS_CONFIG="$CONFIG_OVERRIDE" -a "$APP" >/dev/null
  echo "kabuk kapalı yapılandırma seçildi: $CONFIG_OVERRIDE"
fi

echo "== dağıtım (7/24: auto_stop kapalı, min_machines_running=1)"
flyctl deploy -a "$APP" --ha=false

if [ -n "$DOMAIN" ]; then
  echo "== özel alan adı sertifikası"
  flyctl certs add "$DOMAIN" -a "$APP" || echo "sertifika zaten istenmiş olabilir"
  echo "Aşağıdaki DNS kayıtlarını alan adı sağlayıcında oluştur:"
  flyctl certs show "$DOMAIN" -a "$APP" || true
fi

echo "== doğrulama"
echo -n "fly.dev sağlık: "; curl -fsS "https://$APP.fly.dev/healthz" || echo "(ilk açılışta 20 sn sürebilir)"
echo
[ -n "$DOMAIN" ] && { echo -n "$DOMAIN sağlık: "; curl -fsS "https://$DOMAIN/healthz" || echo "(sertifika/DNS beklemede olabilir)"; echo; }
echo "Claude bağdaştırıcısı için adres: https://${DOMAIN:-$APP.fly.dev}/mcp"
