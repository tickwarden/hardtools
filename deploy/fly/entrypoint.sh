#!/bin/sh
# Hardtools MCP konteyner girişi: kalıcı hacmi hazırlar, HTTP modunu bir gözcü altında
# başlatır. Gözcü (supervisor) node süreci çökerse geri getirir; /healthz yanıt vermezse
# süreci öldürüp yeniden başlatır. Gizli değerler yalnızca ortamdan okunur, loga yazılmaz.
set -u
umask 077

APP_DIR="${HARDTOOLS_APP_DIR:-/app}"
ROOT="${HARDTOOLS_ROOTS:-/data/work}"
AUDIT="${HARDTOOLS_AUDIT_DIR:-/data/audit}"
PORT_="${PORT:-8787}"
STATE_DIR="${HARDTOOLS_STATE_DIR:-/data}"
SUP_LOG="$STATE_DIR/supervisor.log"
RESTART_FILE="$STATE_DIR/restarts"

mkdir -p "$ROOT" "$AUDIT"
chmod 0700 "$AUDIT" 2>/dev/null || true
touch "$SUP_LOG" 2>/dev/null || SUP_LOG=/dev/null
[ -f "$RESTART_FILE" ] || echo 0 > "$RESTART_FILE" 2>/dev/null || true

if [ -z "${HARDTOOLS_HTTP_TOKEN:-}" ] || [ "${#HARDTOOLS_HTTP_TOKEN}" -lt 32 ]; then
  if [ -n "${HARDTOOLS_PUBLIC:-}" ] && [ "${HARDTOOLS_PUBLIC}" != "off" ]; then
    echo "[hardtools] HARDTOOLS_HTTP_TOKEN yok; yalnız public mod etkin." >&2
  else
    echo "[hardtools] HARDTOOLS_HTTP_TOKEN yok veya 32 karakterden kısa." >&2
    # Tek tirnak: komut ikamesi calismasin, loga token degeri yazilmasin.
    echo '[hardtools] fly secrets set HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32) -a <app>' >&2
    echo '[hardtools] ya da oturum açmadan kullanmak için: HARDTOOLS_PUBLIC=open|key + HARDTOOLS_PUBLIC_KEY' >&2
    exit 1
  fi
fi

CHILD=""
WATCH=""
STOPPING=0

terminate() {
  STOPPING=1
  echo "[hardtools] kapatma sinyali alındı; alt süreç durduruluyor" >&2
  [ -n "$WATCH" ] && kill "$WATCH" 2>/dev/null
  [ -n "$CHILD" ] && kill -TERM "$CHILD" 2>/dev/null
  [ -n "$CHILD" ] && wait "$CHILD" 2>/dev/null
  exit 0
}
trap terminate INT TERM

log_restart() {
  n=$(cat "$RESTART_FILE" 2>/dev/null || echo 0)
  n=$((n + 1))
  echo "$n" > "$RESTART_FILE" 2>/dev/null || true
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) restart=$n $1" >> "$SUP_LOG" 2>/dev/null || true
}

BACKOFF=1
while [ "$STOPPING" -eq 0 ]; do
  echo "[hardtools] başlatılıyor: root=$ROOT audit=$AUDIT port=$PORT_ config=${HARDTOOLS_CONFIG:-yok} restart=$(cat "$RESTART_FILE" 2>/dev/null || echo 0)"
  node "$APP_DIR/bundle/index.js" --http --host 0.0.0.0 --port "$PORT_" &
  CHILD=$!

  # Sağlık gözcüsü: /healthz üst üste 3 kez yanıt vermezse node'u öldür (kilitlenmiş süreç).
  (
    fails=0
    while kill -0 "$CHILD" 2>/dev/null; do
      sleep 10
      kill -0 "$CHILD" 2>/dev/null || break
      if node -e "fetch('http://127.0.0.1:$PORT_/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then
        fails=0
      else
        fails=$((fails + 1))
        echo "[hardtools] /healthz yanıt vermedi ($fails/3)" >&2
        if [ "$fails" -ge 3 ]; then
          echo "[hardtools] sağlıksız süreç öldürülüyor (pid $CHILD)" >&2
          kill -TERM "$CHILD" 2>/dev/null
          sleep 3
          kill -KILL "$CHILD" 2>/dev/null
          break
        fi
      fi
    done
  ) &
  WATCH=$!

  STARTED=$(date +%s)
  wait "$CHILD"
  CODE=$?
  [ "$STOPPING" -eq 1 ] && break
  kill "$WATCH" 2>/dev/null
  WATCH=""

  RUNTIME=$(( $(date +%s) - STARTED ))
  log_restart "exit=$CODE runtime=${RUNTIME}s"
  echo "[hardtools] node çıktı (kod=$CODE, ${RUNTIME}s); ${BACKOFF}s sonra yeniden başlatılıyor" >&2
  # Uzun süre çalıştıysa bekleme süresini sıfırla (çökme döngüsünde geri çekil).
  [ "$RUNTIME" -gt 60 ] && BACKOFF=1
  sleep "$BACKOFF"
  BACKOFF=$((BACKOFF * 2))
  [ "$BACKOFF" -gt 30 ] && BACKOFF=30
done
