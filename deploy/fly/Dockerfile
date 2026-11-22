# syntax=docker/dockerfile:1.7
# Hardtools MCP — 7/24 uzak sunucu imajı (Fly.io ve genel Docker).
# Yerelde denemek için:
#   docker build -f deploy/fly/Dockerfile -t hardtools-mcp .
#   docker run --rm -p 8787:8787 -e HARDTOOLS_HTTP_TOKEN=$(openssl rand -hex 32) \
#     -e HARDTOOLS_ALLOWED_HOSTS=127.0.0.1:8787 -v htdata:/data hardtools-mcp
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json build-bundle.mjs ./
COPY src ./src
# bundle/index.js node_modules gerektirmez; çalışma imajına yalnızca bu çıktı gider.
RUN npm run build && node build-bundle.mjs && test -s bundle/index.js

FROM node:22-bookworm-slim AS runtime
# bubblewrap: izole çalışma kabuğu (ht_shell). git/curl: izinli komutlar.
# procps: ht_shell süreç ağacı ve süre denetimi. openssl: token üretimi için değil, TLS istemcileri için.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap ca-certificates git curl procps \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/bundle ./bundle
COPY deploy/fly/config.json /etc/hardtools/config.json
COPY deploy/fly/config-readwrite.json /etc/hardtools/config-readwrite.json
COPY deploy/fly/entrypoint.sh /usr/local/bin/hardtools-entrypoint
RUN chmod 0755 /usr/local/bin/hardtools-entrypoint \
 && mkdir -p /data/work /data/audit
ENV NODE_ENV=production \
    HARDTOOLS_CONFIG=/etc/hardtools/config.json \
    HARDTOOLS_ROOTS=/data/work \
    HARDTOOLS_PROFILE=balanced \
    HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS=1
# Konteyner içinde root: bubblewrap'in kullanıcı ad alanı kurması ve /data hacmine
# yazması için gerekli. Dışarıya yalnızca 8787 açılır; TLS'i Fly proxy sonlandırır.
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/local/bin/hardtools-entrypoint"]
