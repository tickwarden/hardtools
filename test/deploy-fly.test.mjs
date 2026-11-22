// Fly.io 7/24 dağıtımı: varlıkların doğruluğu ve HTTP yüzeyinin (healthz, OAuth
// keşfi, Host denetimi) çalışan sunucuda davranışı.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const root = new URL("../", import.meta.url);
const read = (name) => fs.readFileSync(new URL(name, root), "utf8");
const flyToml = read("fly.toml");
const dockerfile = read("deploy/fly/Dockerfile");
const entrypoint = read("deploy/fly/entrypoint.sh");
const deploySh = read("deploy/fly/deploy.sh");
const config = JSON.parse(read("deploy/fly/config.json"));
const configReadWrite = JSON.parse(read("deploy/fly/config-readwrite.json"));
const pkg = JSON.parse(read("package.json"));
const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const tmp = (prefix) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));

const CONFIG_KEYS = ["audit", "fs", "shell", "net", "search", "profile", "roots"];

test("fly deploy: the machine never sleeps and Fly probes /healthz", () => {
  assert.match(flyToml, /^app = "hardtools-mcp"/m);
  assert.match(flyToml, /^primary_region = "fra"/m);
  assert.match(flyToml, /dockerfile = "deploy\/fly\/Dockerfile"/);
  assert.match(flyToml, /internal_port = 8787/);
  assert.match(flyToml, /force_https = true/);
  assert.match(flyToml, /auto_stop_machines = "off"/, "7/24 için makine durdurulmamalı");
  assert.match(flyToml, /min_machines_running = 1/);
  assert.match(flyToml, /path = "\/healthz"/);
  assert.match(flyToml, /\[\[mounts\]\]\n  source = "hardtools_data"\n  destination = "\/data"/, "kalıcı hacim bildirilmeli");
  assert.ok(!/auto_stop_machines = "(stop|suspend)"/.test(flyToml));
  assert.ok(!/(token|TOKEN|password|secret)\s*=\s*"/i.test(flyToml), "fly.toml gizli değer içermemeli");
});

test("fly deploy: image ships the bundle, bubblewrap and a health probe", () => {
  assert.match(dockerfile, /FROM node:22-bookworm-slim AS build/);
  assert.match(dockerfile, /RUN npm run build && node build-bundle\.mjs/);
  // Derleme, scripts/build-reader.mjs ve reader/ olmadan Docker içinde düşer.
  assert.match(dockerfile, /COPY scripts \.\/scripts/);
  assert.match(dockerfile, /COPY reader \.\/reader/);
  assert.match(dockerfile, /apt-get install -y --no-install-recommends bubblewrap/);
  assert.match(dockerfile, /COPY --from=build \/app\/bundle \.\/bundle/);
  assert.match(dockerfile, /ENTRYPOINT \["\/usr\/local\/bin\/hardtools-entrypoint"\]/);
  assert.match(dockerfile, /EXPOSE 8787/);
  assert.match(dockerfile, /\/healthz/);
  const dockerBody = dockerfile.split("\n").filter((line) => !line.trimStart().startsWith("#")).join("\n");
  assert.ok(!/HARDTOOLS_HTTP_TOKEN\s*=/.test(dockerBody), "token imaja gömülmemeli");
  assert.match(entrypoint, /HARDTOOLS_HTTP_TOKEN/);
  assert.match(entrypoint, /exit 1/, "token yoksa açılış reddedilmeli");
  assert.match(entrypoint, /mkdir -p "\$ROOT" "\$AUDIT"/, "ilk açılışta hacim hazırlanmalı");
  assert.match(entrypoint, /exec node "\$APP_DIR\/bundle\/index\.js" --http --host 0\.0\.0\.0/);
  assert.match(entrypoint, /APP_DIR="\$\{HARDTOOLS_APP_DIR:-\/app\}"/);
  assert.ok(!/echo[^\n]*\$\{?HARDTOOLS_HTTP_TOKEN\}/.test(entrypoint), "token değeri loga yazılmamalı");
  // Çift tırnak içindeki $(openssl ...) çalışır ve loga gerçek bir token yazar; ipucu tek tırnaklı olmalı.
  assert.match(entrypoint, /'\[hardtools\] fly secrets set HARDTOOLS_HTTP_TOKEN=\$\(openssl rand -hex 32\)/, "token ipucu komut ikamesini çalıştırmamalı");
});

test("fly deploy: runtime configs keep audit fail-closed and pick shell mode explicitly", () => {
  for (const cfg of [config, configReadWrite]) {
    for (const key of Object.keys(cfg)) assert.ok(CONFIG_KEYS.includes(key), `bilinmeyen ayar: ${key}`);
    assert.equal(cfg.audit.dir, "/data/audit");
    assert.equal(cfg.audit.failClosed, true);
    assert.equal(cfg.fs.writeEnabled, true);
  }
  assert.equal(config.shell.enabled, true);
  assert.equal(configReadWrite.shell.enabled, false);
});

test("fly deploy: the script hides the token, pins hosts and verifies the deploy", () => {
  assert.match(deploySh, /openssl rand -hex 32/);
  assert.match(deploySh, /install -m 600 \/dev\/null deploy\/fly\/\.env\.local/);
  assert.match(deploySh, /HARDTOOLS_ALLOWED_HOSTS="\$HOSTS"/);
  assert.match(deploySh, /HOSTS="\$APP\.fly\.dev,127\.0\.0\.1:8787"/);
  assert.match(deploySh, /flyctl deploy -a "\$APP" --config fly\.toml --ha=false/);
  assert.match(deploySh, /cd "\$\(cd "\$\(dirname "\$0"\)\/\.\.\/\.\." && pwd\)"/, "betik depo kökünden çalışmalı");
  assert.match(deploySh, /flyctl certs add "\$DOMAIN"/);
  assert.match(deploySh, /curl -fsS "https:\/\/\$APP\.fly\.dev\/healthz"/);
  assert.match(deploySh, /--readwrite/);
  // Token yalnızca 0600 dosyaya yazılır; stdout'a basılmaz.
  const printed = deploySh.split("\n")
    .filter((row) => !row.trimStart().startsWith("#"))
    .filter((row) => /\$\{?TOKEN\}/.test(row) && !/>\s*deploy\/fly\/\.env\.local/.test(row));
  assert.deepEqual(printed, [], "token stdout'a basılmamalı");
  assert.match(read(".gitignore"), /deploy\/fly\/\.env\.local/);
  const dockerignore = read(".dockerignore");
  assert.match(dockerignore, /^node_modules$/m);
  assert.ok(!/^deploy$/m.test(dockerignore), "deploy klasörü bağlama dahil olmalı");
});

function request(port, { method = "GET", path: target = "/", headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function startHttp(t, extraEnv = {}, { shell = false } = {}) {
  const userRoot = tmp("ht-fly-root-");
  const audit = tmp("ht-fly-audit-");
  fs.mkdirSync(audit, { recursive: true });
  const cfgPath = path.join(audit, "config.json");
  fs.writeFileSync(cfgPath, JSON.stringify({ audit: { dir: audit, failClosed: true }, fs: { writeEnabled: true }, shell: { enabled: shell } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const token = "0123456789abcdef0123456789abcdef0123456789abcdef";
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: {
      ...process.env,
      HARDTOOLS_ROOTS: userRoot,
      HARDTOOLS_CONFIG: cfgPath,
      HARDTOOLS_HTTP_TOKEN: token,
      HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS: "1",
      HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port},mcp.example.dev`,
      ...extraEnv
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  let err = "";
  child.stderr.on("data", (data) => { err += data; });
  for (let i = 0; i < 80; i++) {
    if (/listening/.test(err)) break;
    if (child.exitCode !== null) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, `sunucu başlamadı: ${err}`);
  return { port, token, error: () => err };
}

test("http: /healthz answers without auth, even for an unexpected Host, and leaks nothing", async (t) => {
  const { port, token } = await startHttp(t);
  const healthy = await request(port, { path: "/healthz" });
  assert.equal(healthy.status, 200);
  const body = JSON.parse(healthy.body);
  assert.equal(body.ok, true);
  assert.equal(body.version, pkg.version);
  assert.equal(body.shell, "disabled");
  assert.equal(body.write, true);
  assert.ok(Number.isFinite(body.uptime_s));
  assert.equal(healthy.headers["cache-control"], "no-store");

  const foreignHost = await request(port, { path: "/healthz", headers: { host: "monitor.internal" } });
  assert.equal(foreignHost.status, 200, "sağlık kontrolü Host allowlist'ine takılmamalı");

  const raw = healthy.body + JSON.stringify(body);
  assert.ok(!raw.includes(token), "token sızmamalı");
  assert.ok(!raw.includes(os.tmpdir()), "dosya yolları sızmamalı");
});

test("http: other routes still enforce the Host allowlist and auth", async (t) => {
  const { port } = await startHttp(t);
  const badHost = await request(port, { path: "/mcp", method: "POST", headers: { host: "evil.example", "content-type": "application/json" }, body: {} });
  assert.equal(badHost.status, 403);

  const noAuth = await request(port, { path: "/mcp", method: "POST", headers: { host: `127.0.0.1:${port}`, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id: 1, method: "initialize", params: {} } });
  assert.equal(noAuth.status, 401);
  assert.match(String(noAuth.headers["www-authenticate"]), /resource_metadata="http:\/\/127\.0\.0\.1:\d+\/\.well-known\/oauth-protected-resource"/);
});

test("http: OAuth discovery advertises the custom domain over https", async (t) => {
  const { port } = await startHttp(t);
  const protectedResource = await request(port, { path: "/.well-known/oauth-protected-resource", headers: { host: "mcp.example.dev" } });
  assert.equal(protectedResource.status, 200);
  assert.equal(JSON.parse(protectedResource.body).resource, "https://mcp.example.dev/mcp");

  const metadata = await request(port, { path: "/.well-known/oauth-authorization-server", headers: { host: "mcp.example.dev" } });
  assert.equal(metadata.status, 200);
  const meta = JSON.parse(metadata.body);
  assert.equal(meta.issuer, "https://mcp.example.dev");
  assert.equal(meta.authorization_endpoint, "https://mcp.example.dev/authorize");
  assert.equal(meta.token_endpoint, "https://mcp.example.dev/token");
  assert.equal(meta.registration_endpoint, "https://mcp.example.dev/register");
});

test("http: the static bearer reaches MCP and audit stays fail-closed", async (t) => {
  const { port, token } = await startHttp(t);
  const init = await request(port, {
    path: "/mcp",
    method: "POST",
    headers: { host: `127.0.0.1:${port}`, authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "fly-test", version: "0" } } }
  });
  assert.equal(init.status, 200, init.body);
  assert.match(init.body, /protocolVersion/);
});

test("http: the deployed shell mode reports the isolated workspace", { skip: !fs.existsSync("/usr/bin/bwrap") }, async (t) => {
  const { port } = await startHttp(t, {}, { shell: true });
  const healthy = await request(port, { path: "/healthz" });
  assert.equal(healthy.status, 200);
  assert.equal(JSON.parse(healthy.body).shell, "workspace", "izole kabuk /healthz içinde görünmeli");
});
