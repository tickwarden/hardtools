#!/bin/sh
# Hardtools MCP konteyner girişi: kalıcı hacmi hazırlar ve HTTP modunu başlatır.
# Gizli değerler yalnızca ortamdan okunur; hiçbiri loga yazılmaz.
set -eu
umask 077

APP_DIR="${HARDTOOLS_APP_DIR:-/app}"
ROOT="${HARDTOOLS_ROOTS:-/data/work}"
AUDIT="${HARDTOOLS_AUDIT_DIR:-/data/audit}"

# İlk açılışta hacim boştur; kök ve audit klasörü yoksa validateRoots hata verir.
mkdir -p "$ROOT" "$AUDIT"
chmod 0700 "$AUDIT" 2>/dev/null || true

if [ -z "${HARDTOOLS_HTTP_TOKEN:-}" ] || [ "${#HARDTOOLS_HTTP_TOKEN}" -lt 32 ]; then
  echo "[hardtools] HARDTOOLS_HTTP_TOKEN yok veya 32 karakterden kısa." >&2
  # Tek tirnak: komut ikamesi calismasin, loga token degeri yazilmasin.
  echo '[hardtools] fly secrets set HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32) -a <app>' >&2
  exit 1
fi

echo "[hardtools] baslatiliyor: root=$ROOT audit=$AUDIT port=${PORT:-8787} config=${HARDTOOLS_CONFIG:-yok}"
exec node "$APP_DIR/bundle/index.js" --http --host 0.0.0.0 --port "${PORT:-8787}"
