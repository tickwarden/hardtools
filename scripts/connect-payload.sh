#!/usr/bin/env bash
# Sourced only: keep the run-specific invite and token in the owning shell.
# Call the function as a pipe into age on public repos. Never log its stdout.
connection_details() {
  local invite_url=$1 endpoint=$2 token=$3 run_url=$4
  printf 'HARDTOOLS MCP — ÖZEL BAĞLANTI BİLGİSİ | #%s (%s)\n\n' "$GITHUB_RUN_NUMBER" "$RUN_MODE"
  if [[ "$RUN_MODE" == check-connection ]]; then
    echo 'SADECE TEST — Kontrol bitince bu adres kapanır. Claude için yeni bir serve başlat.'
  fi
  printf 'Claude web: önce tek kullanımlık daveti Claude ile aynı tarayıcı profilinde aç:\n%s\n\n' "$invite_url"
  printf 'Settings → Connectors → Add custom connector\nName: hardtools\nMCP Endpoint URL: %s\n' "$endpoint"
  printf 'OAuth client ID ve secret boş kalsın. Devam edip yetkilendirmeyi tamamla.\n\n'
  printf 'Header destekleyen istemciler (davet gerekmez)\nURL: %s\nHeader name: Authorization\nHeader value: Bearer %s\n\n' "$endpoint" "$token"
  printf 'Oturum: %s\nYerel araçlar: %s | Otomatik yenileme: %s\n' "$run_url" "$ALLOW_LOCAL_TOOLS" "$AUTO_RENEW"
  echo 'Bu bilgiler yalnızca bu job açıkken geçerlidir. Daveti, tokenı ve özel anahtarı paylaşma.'
}
