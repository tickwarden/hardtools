#!/bin/sh
# hardtools keepalive: /healthz'i yoklar; sunucu kapalıysa Fly makinelerini yeniden başlatır.
#
# Kullanım:
#   scripts/keepalive.sh https://hardtools-mcp.fly.dev
#   HARDTOOLS_URL=... FLY_APP=hardtools-mcp FLY_API_TOKEN=... scripts/keepalive.sh
#
# Çıkış kodları: 0 = sağlıklı, 1 = sağlıksız ve onarılamadı, 2 = parametre hatası.
# Sır yazmaz: token yalnızca curl başlığında kullanılır.
set -u

URL="${1:-${HARDTOOLS_URL:-}}"
TRIES="${KEEPALIVE_TRIES:-3}"
GAP="${KEEPALIVE_GAP:-10}"
WAIT_AFTER="${KEEPALIVE_WAIT_AFTER:-25}"

if [ -z "$URL" ]; then
  echo "usage: $0 <base-url>   (örn. https://hardtools-mcp.fly.dev)" >&2
  exit 2
fi
URL="${URL%/}"

# Fly makinesini yeniden başlat (token yoksa sessizce atla ve 1 döndür).
fly_restart() {
  [ -n "${FLY_APP:-}" ] && [ -n "${FLY_API_TOKEN:-}" ] || return 1
  machines=$(curl -fsS -H "Authorization: Bearer $FLY_API_TOKEN" \
    "https://api.machines.dev/v1/apps/$FLY_APP/machines" 2>/dev/null) || return 1
  ids=$(printf '%s' "$machines" | tr ',' '\n' | sed -n 's/.*"id":"\([0-9a-z]\{14\}\)".*/\1/p' | sort -u)
  [ -n "$ids" ] || return 1
  ok=1
  for id in $ids; do
    if curl -fsS -X POST -H "Authorization: Bearer $FLY_API_TOKEN" \
      "https://api.machines.dev/v1/apps/$FLY_APP/machines/$id/restart" >/dev/null 2>&1; then
      echo "keepalive: $FLY_APP/$id yeniden başlatıldı"
    else
      echo "keepalive: $FLY_APP/$id yeniden başlatılamadı" >&2
      ok=0
    fi
  done
  [ "$ok" -eq 1 ]
}

check() {
  body=$(curl -fsS -m 8 "$URL/healthz" 2>/dev/null) || return 1
  echo "$body" | grep -q '"ok":true' || return 1
  echo "keepalive: sağlıklı → $body"
  return 0
}

i=1
while [ "$i" -le "$TRIES" ]; do
  check && exit 0
  echo "keepalive: deneme $i/$TRIES başarısız ($URL/healthz)" >&2
  [ "$i" -lt "$TRIES" ] && sleep "$GAP"
  i=$((i + 1))
done

# Sağlıksız: makine uykuya dalmış ya da çökmüş olabilir.
if fly_restart; then
  echo "keepalive: yeniden başlatma istendi; ${WAIT_AFTER}s bekleniyor"
  sleep "$WAIT_AFTER"
  check && exit 0
fi
echo "keepalive: sunucu sağlıksız ve onarılamadı ($URL)" >&2
exit 1
