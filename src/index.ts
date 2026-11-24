#!/usr/bin/env node
// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import "./schema-runtime.js";
import { pipeline } from "node:stream/promises";
import { equalSecret } from "./credentials.js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { Audit, verifyAuditFile } from "./audit.js";
import { envFlag, loadPolicy, type Policy, type ProfileName } from "./config.js";
import { OAuth, type GithubIdp } from "./oauth.js";
import { createServer, createWorkspace } from "./server.js";
import { UserInputs } from "./user-input.js";
import { Shares } from "./share.js";
import { Variables } from "./variables.js";
import { page as uiPage, esc, PAGE_CSP } from "./ui.js";
import { ALL_TOOLS, SettingsUI, UserSettingsStore } from "./settings.js";
import { VERSION } from "./version.js";
import { probeWorkspaceHttps, probeWorkspaceShell } from "./workspace-shell.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name); if (i === -1) return undefined;
  const v = process.argv[i + 1]; return v && !v.startsWith("--") ? v : "true";
}

async function main() {
  if (arg("--version")) { console.log(VERSION); return; }
  if (arg("--verify")) { const r = verifyAuditFile(arg("--verify")!, arg("--expect-head")); console.log(JSON.stringify(r)); process.exit(r.ok ? 0 : 2); }

  const profile = arg("--profile") as ProfileName | undefined;
  const httpMode = process.argv.includes("--http");
  let policy: Policy = loadPolicy({ profile });
  if (httpMode) {
    if (!envFlag("HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS")) {
      policy = { ...policy, fs: { ...policy.fs, writeEnabled: false }, shell: { ...policy.shell, enabled: false } };
    } else if (policy.shell.enabled) {
      // Opt-in enables both shell forms in the dedicated workspace, never on the HTTP host.
      policy.shellWorker = "workspace";
      probeWorkspaceShell(policy);
    }
    if (envFlag("HARDTOOLS_WORKSPACE_HTTPS")) {
      policy.workspaceHttps = true;
      await probeWorkspaceHttps(policy); // fails closed if shell, net policy or isolation isn't available
    }
  }
  const audit = new Audit(policy.audit.dir!, policy.audit.failClosed);
  audit.write({ ev: "start", version: VERSION, profile: policy.profile, transport: httpMode ? "http" : "stdio", roots: policy.roots, shell: policy.shell.enabled, write: policy.fs.writeEnabled, ...(policy.shellWorker && { workspaceHttps: Boolean(policy.workspaceHttps) }) });
  console.error(`[hardtools] ${VERSION} profile=${policy.profile} roots=${policy.roots.join(",")} transport=${httpMode ? "http" : "stdio"} audit=${audit.file}`);

  if (!httpMode) {
    await createServer(policy, audit).connect(new StdioServerTransport());
    return;
  }

  // ---------------------------------------------------------------------------------
  // Public connector modes (0.5.2):
  //   HARDTOOLS_PUBLIC=open -> https://host/mcp      all tools, LOGIN REQUIRED (static bearer or OAuth)
  //   HARDTOOLS_PUBLIC=key  -> https://host/c/<key>  all tools, the key in the URL is the credential
  //   HARDTOOLS_PUBLIC=open + HARDTOOLS_PUBLIC_TOOLS=safe|ht_read,ht_glob,...  -> login-free, allowlisted tools
  // Login-free modes never answer 401 and never advertise OAuth metadata, so claude.ai shows no
  // "Oturum açma gerekli" button. The full tool set in open mode is deliberately *not* an anonymous
  // door: it keeps the normal login gate, exactly like a token-protected server.
  // ---------------------------------------------------------------------------------
  const publicMode = (process.env.HARDTOOLS_PUBLIC ?? "off").trim().toLowerCase();
  const isPublic = ["1", "true", "open", "key"].includes(publicMode);
  const publicKey = (process.env.HARDTOOLS_PUBLIC_KEY ?? "").trim();
  const SAFE_TOOLS = ["ht_read", "ht_glob", "ht_search", "ht_status", "ht_user_input", "ht_image_search", "ht_fetch", "ht_share"];
  const rawPublicTools = (process.env.HARDTOOLS_PUBLIC_TOOLS ?? "").trim().toLowerCase();
  let publicTools: Set<string> | null = null;
  if (isPublic) {
    if (publicMode === "key") publicTools = null;                                        // key is the credential: every tool
    else if (rawPublicTools === "all" || rawPublicTools === "") publicTools = null;      // open, full set -> login required
    else if (rawPublicTools === "safe") publicTools = new Set(SAFE_TOOLS);               // open + allowlist -> login-free
    else publicTools = new Set(rawPublicTools.split(",").map(t => t.trim()).filter(Boolean));
    if (publicMode === "key" && publicKey.length < 32) {
      console.error("[hardtools] refusing to start: HARDTOOLS_PUBLIC=key needs HARDTOOLS_PUBLIC_KEY of at least 32 characters (openssl rand -hex 32).");
      process.exit(1);
    }
  }
  // HARDTOOLS_PUBLIC_ANON=1: tam araç setini bile girişsiz açar (yalnızca bilinçli tercih;
  // adresi bilen herkes yazma/silme/kabuk araçlarını kullanabilir).
  const anonAll = ["1", "true", "yes"].includes((process.env.HARDTOOLS_PUBLIC_ANON ?? "").trim().toLowerCase());
  const loginFree = isPublic && (publicMode === "key" || publicTools !== null || anonAll);
  const loginRequired = isPublic && !loginFree;
  if (isPublic) console.error(`[hardtools] public connector mode=${publicMode}; tools=${publicTools ? [...publicTools].join(",") : "all"}; ${loginFree ? "no OAuth challenge" : "login required (bearer or OAuth)"}${anonAll && !publicTools ? " (HARDTOOLS_PUBLIC_ANON: tam set girişsiz)" : ""}`);
  const keyId = publicKey ? crypto.createHash("sha256").update(publicKey).digest("hex").slice(0, 12) : "open";
  const publicOwner = (viaKey: boolean) => (viaKey ? `public:${keyId}` : "public");

  const token = process.env.HARDTOOLS_HTTP_TOKEN ?? "";
  const hasToken = token.length >= 32;
  if (!hasToken && !isPublic) { console.error("[hardtools] refusing to start HTTP mode: set HARDTOOLS_HTTP_TOKEN to a random secret of at least 32 chars (e.g. `openssl rand -hex 32`), or run the no-login connector with HARDTOOLS_PUBLIC=open|key."); process.exit(1); }
  if (!hasToken) console.error("[hardtools] no static bearer token; the no-login connector is the only entry point.");
  const host = arg("--host") ?? "127.0.0.1"; const port = Number(arg("--port") ?? 8787);
  const allowedHosts = new Set((process.env.HARDTOOLS_ALLOWED_HOSTS ?? `127.0.0.1:${port},localhost:${port}`).split(",").map(s => s.trim().toLowerCase()).filter(Boolean));
  const hits = new Map<string, { n: number; reset: number }>();
  // claude.ai's connector dialog cannot send a custom Authorization header, so it uses OAuth.
  // Upstream GitHub login: when configured, /authorize redirects to github.com instead of
  // showing the token form, so the connector flow is a normal "Sign in with GitHub".
  const ghId = (process.env.HARDTOOLS_OAUTH_GITHUB_CLIENT_ID ?? "").trim();
  const ghSecret = (process.env.HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET ?? "").trim();
  const ghLogins = (process.env.HARDTOOLS_OAUTH_ALLOWED_LOGINS ?? "").split(",").map(s => s.trim()).filter(Boolean);
  const ghEmails = (process.env.HARDTOOLS_OAUTH_ALLOWED_EMAILS ?? "").split(",").map(s => s.trim()).filter(Boolean);
  // HARDTOOLS_OAUTH_ALLOW_ANY=1 ya da allowlist'te "*": her GitHub hesabı giriş yapabilir.
  const ghAllowAny = ["1", "true", "yes", "*"].includes((process.env.HARDTOOLS_OAUTH_ALLOW_ANY ?? "").trim().toLowerCase()) ||
    ghLogins.includes("*") || ghEmails.includes("*");
  // Durum dizini: HARDTOOLS_STATE_DIR > <audit üst dizini>/state
  const stateDir = process.env.HARDTOOLS_STATE_DIR?.trim() || (policy.audit.dir ? path.join(policy.audit.dir, "state") : undefined);
  const stateFile = (name: string) => stateDir ? path.join(stateDir, name) : undefined;
  let github: GithubIdp | undefined;
  if (ghId) {
    if (!ghLogins.length && !ghEmails.length && !ghAllowAny) {
      console.error("[hardtools] refusing to start: HARDTOOLS_OAUTH_GITHUB_CLIENT_ID is set but HARDTOOLS_OAUTH_ALLOWED_LOGINS/EMAILS is empty, so every login would be denied.");
      process.exit(1);
    }
    // Sır verilirse tarayıcı yönlendirmeli akış; verilmezse GitHub device flow (sır gerekmez).
    const ghWeb = (process.env.HARDTOOLS_OAUTH_GITHUB_WEB_BASE ?? "").trim();
    const ghApi = (process.env.HARDTOOLS_OAUTH_GITHUB_API_BASE ?? "").trim();
    github = {
      clientId: ghId, ...(ghSecret ? { clientSecret: ghSecret } : {}), allowedLogins: ghLogins.filter(v => v !== "*"), allowedEmails: ghEmails.filter(v => v !== "*"), ...(ghAllowAny ? { allowAny: true } : {}),
      ...(ghWeb ? { webBase: ghWeb } : {}), ...(ghApi ? { apiBase: ghApi } : {}),
    };
    if (ghAllowAny) console.error("[hardtools] uyarı: HARDTOOLS_OAUTH_ALLOW_ANY açık — GitHub'ın doğruladığı HER hesap bağlanabilir (allowlist yok).");
    console.error(`[hardtools] GitHub login enabled (${ghSecret ? "authorization-code redirect" : "device flow, no client secret"}); ${ghAllowAny ? "allowlist: none (herkes)" : `allowlist ${ghLogins.length} login / ${ghEmails.length} e-posta`}.`);
  } else if (ghSecret) {
    console.error("[hardtools] ignoring HARDTOOLS_OAUTH_GITHUB_CLIENT_SECRET without HARDTOOLS_OAUTH_GITHUB_CLIENT_ID.");
  }
  if (loginRequired && !hasToken && !github) {
    console.error("[hardtools] warning: HARDTOOLS_PUBLIC=open with the full tool set needs a login, but neither HARDTOOLS_HTTP_TOKEN nor GitHub OAuth is configured — every MCP request will be rejected. Set a token, configure OAuth, or use HARDTOOLS_PUBLIC_TOOLS=safe for the login-free read-only connector.");
  }
  // Durum dosyaları: /data/state/*
  // Kullanıcı ayarları (araç/ağ/allowlist) ve çıkış: grant -> login eşlemesi burada tutulur.
  const settingsStore = new UserSettingsStore({
    store: stateFile("settings.json"),
    keyPath: stateFile("settings.key"),
  });
  const oauth = new OAuth({
    token, audit: (e) => audit.write(e),
    extraRedirectUris: (process.env.HARDTOOLS_OAUTH_REDIRECT_URIS ?? "").split(",").map(s => s.trim()).filter(Boolean),
    github,
    onGrant: (grant, login) => settingsStore.bindGrant(grant, login),
    grantRevoked: (grant) => settingsStore.isRevoked(grant),
  });
  // Mint an invite URL for the first user; additional invites can be generated by calling mintInvite() again.
  // The public tunnel origin is not known at startup; invite generation is deferred to after the server starts
  // and the tunnel URL is available (workflow injects HARDTOOLS_INVITE_ORIGIN for this purpose).
  const inviteOrigin = process.env.HARDTOOLS_INVITE_ORIGIN ?? "";
  if (inviteOrigin) {
    const inviteUrl = oauth.mintInvite(inviteOrigin);
    console.error(`[hardtools] invite URL (one use; keep private): ${inviteUrl}`);
  }

  // Form yanıtları hacimde saklanır: sunucu yeniden başlarsa (Fly deneme hesabı 5 dk'da bir
  // yeniden başlatıyor) soru/cevap kaybolmaz. Sır içeren formlar bilerek yazılmaz.
  const inputStore = stateFile("inputs.json");
  // Oturum bazlı çalışma alanı: her kimlik (OAuth oturumu, /c/<anahtar>, anonim) kendi /work kökünü alır.
  // Böylece bir oturumun klonladığı depo başka oturumlarda görünmez. HARDTOOLS_PER_SESSION_WORKSPACE=0
  // ile eski (tek, paylaşılan kök) davranışa dönülür.
  const sharedInputs = new UserInputs(inputStore ? { store: inputStore } : {});
  const sharedShares = new Shares();
  const sharedVars = new Variables();
  const perSession = (process.env.HARDTOOLS_PER_SESSION_WORKSPACE ?? "1").trim() !== "0";
  const baseRoot = policy.roots[0];
  const baseIsFsRoot = Boolean(baseRoot) && baseRoot === path.parse(baseRoot).root; // "/" gibi köklerde izolasyon yapılmaz
  // Oturum kökleri taban kökün içinde tutulur (guard'ın izin verdiği tek ağaç): <kök>/u-<hash>.
  const sessionBase = baseRoot && !baseIsFsRoot ? baseRoot : undefined;
  const sessionsFile = stateFile("sessions.json");

  // MCP oturumu (sohbet) -> çalışma kökü eşlemesi. Diske yazılır: yeniden başlatmadan sonra aynı
  // oturum kimliği yine aynı dizine düşer, ama farklı sohbetler asla aynı dizini görmez.
  type SessRec = { owner: string; dir: string; last: number };
  const sessMap = new Map<string, SessRec>();
  if (sessionsFile) {
    try {
      const d = JSON.parse(fs.readFileSync(sessionsFile, "utf8")) as { items?: Array<SessRec & { sid?: string }> };
      for (const r of d.items ?? []) if (r?.sid && r?.dir) sessMap.set(r.sid, { owner: r.owner ?? "", dir: r.dir, last: r.last ?? 0 });
    } catch { /* yoksa boş başla */ }
  }
  let sessSaveTimer: ReturnType<typeof setTimeout> | undefined;
  const saveSessions = () => {
    if (!sessionsFile || sessSaveTimer) return;
    sessSaveTimer = setTimeout(() => {
      sessSaveTimer = undefined;
      try {
        const now = Date.now();
        for (const [sid, r] of sessMap) if (now - r.last > 7 * 24 * 3600_000) sessMap.delete(sid); // eski kayıtlar (dizinler kalır)
        fs.mkdirSync(path.dirname(sessionsFile), { recursive: true, mode: 0o700 });
        const tmp = sessionsFile + ".tmp";
        fs.writeFileSync(tmp, JSON.stringify({ v: 1, items: [...sessMap].map(([sid, r]) => ({ sid, ...r })) }), { mode: 0o600 });
        fs.renameSync(tmp, sessionsFile);
      } catch { /* disk hatası aracı düşürmesin */ }
    }, 250);
    sessSaveTimer.unref?.();
  };
  const mkRoot = (dir: string) => { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); return dir; };
  const accountRoot = (owner: string) => mkRoot(path.join(baseRoot, "a-" + crypto.createHash("sha256").update(owner).digest("hex").slice(0, 16)));
  const sessionRoot = (sid: string) => mkRoot(path.join(sessionBase!, "u-" + crypto.createHash("sha256").update("sid\0" + sid).digest("hex").slice(0, 16)));

  const grants = new Map<string, { policy: Policy; workspace: ReturnType<typeof createWorkspace> }>();
  const grantFor = (owner: string, dir: string) => {
    const key = owner + "\u0000" + dir;
    const cached = grants.get(key);
    if (cached) return cached;
    if (grants.size > 512) grants.clear();
    const base = policyFor(owner);
    const p = dir === baseRoot ? base : { ...base, roots: [dir] };
    const g = { policy: p, workspace: createWorkspace(undefined, { inputs: sharedInputs, shares: sharedShares, vars: sharedVars }) };
    grants.set(key, g);
    return g;
  };
  const workspace = createWorkspace(inputStore, { inputs: sharedInputs, shares: sharedShares, vars: sharedVars }); // ortak form/paylaşım kayıtları
  const srv = http.createServer(async (req, res) => {
    const send = (code: number, msg: string, headers: Record<string, string> = {}) => { res.writeHead(code, { "content-type": "application/json", ...headers }); res.end(JSON.stringify({ error: msg })); };
    try {
      const path = (req.url ?? "").split("?")[0];
      // Liveness probe for 7/24 hosts (Fly.io, systemd, Docker). It answers before the Host
      // allowlist so a monitor with an unexpected Host header cannot mark a healthy machine down.
      // It exposes no roots, tokens, paths or policy details.
      if (path === "/healthz") {
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({
          ok: true, version: VERSION,
          shell: policy.shell.enabled ? (policy.shellWorker ?? "host") : "disabled",
          write: policy.fs.writeEnabled,
          public: isPublic ? publicMode : "off",
          login: isPublic ? (loginFree ? "none" : "required") : "token",
          uptime_s: Math.round(process.uptime()),
        }));
        return;
      }
      const h = String(req.headers.host ?? "").toLowerCase();
      if (!allowedHosts.has(h)) return send(403, "host not allowed");                 // DNS-rebinding defence
      // Capability URL for ht_user_input: a random one-time id, answered by the user's browser
      // (so it must be checked before the browser-origin rejection below).
      // Ayar sayfası: tarayıcıdan açılır, bu yüzden browser-origin reddinden önce.
      if (path === "/settings" || path.startsWith("/settings/")) {
        if (await settingsUI.handle(req, res, path)) return;
      }
      if (sharedInputs.handle(req, res, path, oauth.origin(req))) return;
      // Machine-to-machine endpoint: browser origins are refused, except the consent page posting to itself.
      if (req.headers.origin && !(path === "/authorize" && req.headers.origin === oauth.origin(req))) return send(403, "browser origins are not allowed");
      const ip = req.socket.remoteAddress ?? "?"; const now = Date.now();
      if (hits.size > 4096) for (const [k, v] of hits) if (v.reset < now) hits.delete(k); // the window map must not grow forever
      const b = hits.get(ip) ?? { n: 0, reset: now + 60_000 };
      if (now > b.reset) { b.n = 0; b.reset = now + 60_000; } b.n++; hits.set(ip, b);
      if (b.n > 120) return send(429, "rate limited");

      if (sharedShares.download(req, res, path)) return;

      // No-login mode: never advertise OAuth metadata, otherwise claude.ai shows a sign-in button.
      if (loginFree) {
        if (/^\/(?:\.well-known\/|register$|authorize$|token$|oauth\/|invite\/)/.test(path)) return send(404, "not found");
        if (req.method === "GET" && (path === "/connect" || /^\/c\/[A-Za-z0-9_-]{16,128}$/.test(path))) return connectPage(req, res, path, publicMode === "key" && publicKey ? publicKey : "");
      } else if (await oauth.handle(req, res)) return;
      // OAuth discovery / registration / consent / invite / token routes are public by design.

      const keyPath = /^\/c\/([A-Za-z0-9_-]{16,128})(?:\/mcp)?$/.exec(path);
      const isMcpPath = path === "/mcp" || keyPath !== null;
      if (!isMcpPath) return send(404, "not found");

      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization ?? ""));
      // /mcp accepts an OAuth-issued access token, the run-specific static bearer, or — in
      // public mode — the connector URL itself.
      let owner: string | null = m ? (hasToken && equalSecret(m[1], token) ? "static" : oauth.accessScope(m[1])) : null;
      if (!owner && loginFree) {
        if (keyPath && publicKey && equalSecret(keyPath[1], publicKey)) owner = publicOwner(true);
        else if (path === "/mcp" && publicMode !== "key") owner = publicOwner(false);
      }
      if (!owner) {
        // login-free modlarda OAuth keşfi yok; anahtar modunda /c/<key> ipucu verilir.
        return send(401, publicMode === "key" ? "unauthorized: this connector needs its /c/<key> url" : "unauthorized",
          publicMode === "key" ? {} : { "www-authenticate": `Bearer resource_metadata="${oauth.resourceMetadataUrl(req)}"` });
      }
      // Çıkış yapılmış izinler: bağlantı anında düşsün (istemci 401 görür).
      const gid = /^grant:(.+)$/.exec(owner)?.[1];
      if (gid && settingsStore.isRevoked(gid)) return send(401, "unauthorized: signed out", { "www-authenticate": `Bearer resource_metadata="${oauth.resourceMetadataUrl(req)}"` });
      if (req.method !== "POST") return send(405, "stateless server: POST only", { allow: "POST" });
      const chunks: Buffer[] = []; let size = 0;
      for await (const c of req) { size += (c as Buffer).length; if (size > 1_000_000) return send(413, "body too large"); chunks.push(c as Buffer); }
      let body: unknown; try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return send(400, "invalid JSON"); }
      // We have already authenticated, routed and bounded the POST. Use the SDK's Web transport
      // directly instead of reparsing an arbitrary incoming URL with a second HTTP framework.
      const origin = oauth.origin(req);
      // Araç kısıtı yalnızca adsız public kimliğe uygulanır; /c/<anahtar> kimliği her zaman tam settir.
      // Oturum (sohbet) kimliği: initialize isteğinde üretilir, sonraki isteklerde başlıkta geri gelir.
      const sidHeader = /^[A-Za-z0-9_-]{8,128}$/.exec(String(req.headers["mcp-session-id"] ?? ""));
      const isInit = (body as { method?: unknown })?.method === "initialize";
      let sid: string | undefined = sidHeader?.[0];
      let workDir = baseRoot;
      if (perSession && owner !== "static" && baseRoot && !baseIsFsRoot && sessionBase) {
        const rec = sid ? sessMap.get(sid) : undefined;
        if (rec && rec.owner === owner && fs.existsSync(rec.dir)) {
          workDir = rec.dir; rec.last = Date.now(); saveSessions();           // aynı sohbet: aynı kök
        } else if (isInit && !sid) {
          sid = crypto.randomBytes(18).toString("base64url");                  // yeni sohbet: yeni kök
          workDir = sessionRoot(sid);
          sessMap.set(sid, { owner, dir: workDir, last: Date.now() }); saveSessions();
        } else {
          sid = undefined;                                                      // kimlik yok/bilinmiyor: hesap kökü
          workDir = accountRoot(owner);
        }
      }
      const grant = grantFor(owner, workDir);
      const server = createServer(grant.policy, audit.forGrant(owner), grant.workspace, owner, origin,
        {
          ...(owner === "public" ? { tools: publicTools } : {}),
          ...(sid ? { sessionId: "s-" + sid.slice(0, 12) } : {}),
          settings: { store: settingsStore, user: userFor(owner), all: ALL_TOOLS },
        });
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: sid && isInit ? () => sid! : undefined });
      if (sid && !isInit) transport.sessionId = sid; // SDK oturum kontrolünü geçmek için kimliği benimse
      const abort = new AbortController();
      res.once("close", () => { if (!res.writableFinished) abort.abort(); });
      const headers = new Headers();
      for (const key of ["accept", "content-type", "mcp-protocol-version", "mcp-session-id", "last-event-id"]) {
        const v = req.headers[key]; if (typeof v === "string") headers.set(key, v);
      }
      const request = new Request(new URL("/mcp", origin), { method: "POST", headers, signal: abort.signal });
      await server.connect(transport);
      const reply = await transport.handleRequest(request, { parsedBody: body });
      res.writeHead(reply.status, Object.fromEntries(reply.headers));
      if (reply.body) await pipeline(reply.body, res, { signal: abort.signal });
      else res.end();
    } catch (e) {
      if (res.destroyed) return; // the client disconnected during a streamed reply
      console.error("[hardtools] http error:", (e as Error).message);
      if (!res.headersSent) send(500, "internal error"); else res.destroy();
    }
  });
  /** Human page that shows the connector URL to paste into claude.ai (no login involved). */
  const settingsUI = new SettingsUI({
    store: settingsStore,
    operatorToken: hasToken ? token : undefined,
    github: github ? { clientId: github.clientId, webBase: github.webBase, apiBase: github.apiBase, allowAny: github.allowAny, allowedLogins: github.allowedLogins, allowedEmails: github.allowedEmails } : undefined,
    audit: (e) => audit.write(e),
    origin: (r) => oauth.origin(r),
  });

  /** Sahip (owner) -> ayar kullanıcısı. Ayarlar hesap düzeyinde tutulur. */
  const userFor = (owner: string): string => {
    if (owner === "static") return "operator";
    const g = /^grant:(.+)$/.exec(owner);
    if (g) return settingsStore.loginForGrant(g[1]) ?? "operator";
    return "public";
  };

  /** Kullanıcı ayarlarını politikaya uygula: kapalı ağ, allowlist, izinli komutlar. */
  const policyFor = (owner: string): Policy => {
    const user = userFor(owner);
    const us = settingsStore.get(user);
    let p: Policy = policy;
    const shell = { ...policy.shell };
    if (us.allowlistEnabled && us.allowedCommands.length) shell.allowCommands = us.allowedCommands;
    const net = { ...policy.net };
    if (!us.networkEnabled) { net.enabled = false; }
    else if (us.allowlistEnabled) {
      net.allowDomains = us.allowedUrls.map(u => { try { return new URL(u.includes("://") ? u : `https://${u}`).hostname; } catch { return u; } }).filter(Boolean);
      net.requireAllowDomains = true;
    }
    p = { ...policy, shell, net };
    return p;
  };

  const connectPage = (req: http.IncomingMessage, res: http.ServerResponse, path: string, key: string) => {
    const origin = oauth.origin(req);
    const base = key ? `${origin}/c/${key}` : `${origin}/mcp`;
    const others = key ? `${origin}/mcp` : "";
    const html = uiPage({
      title: "hardtools — bağlan",
      subtitle: "MCP",
      css: "textarea{height:3.4rem;font:13px ui-monospace,monospace}code{word-break:break-all}li{margin:.4rem 0}",
      actions: `<a class="btn ghost" href="${origin}/settings">Ayarlar</a>`,
      body: `<h1>hardtools MCP</h1>
<p>Claude → <strong>Ayarlar → Bağlayıcılar → Özel bağlayıcı ekle</strong>. Aşağıdaki adresi yapıştır ve <strong>Ekle</strong>'ye bas.</p>
<div class="card"><textarea readonly onclick="this.select()">${esc(base)}</textarea></div>
<ol><li>Ad: <code>hardtools</code></li><li>Uzak MCP sunucu adresi: <code>${esc(base)}</code></li>${others ? `<li>Anahtar gerekmez; bu adres yalnızca sınırlı araçları açar. Tam yetki için <code>/c/&lt;anahtar&gt;</code> adresini kullan.</li>` : `<li>Bu adres anahtarın kendisidir: paylaşma.</li>`}</ol>
<p class="muted">Bağlandıktan sonra araçlar sohbette görünür. Sunucu düşerse <code>/healthz</code> izleyicisi ve konteyner gözcüsü yeniden başlatır.</p>
${path !== "/connect" ? `<p class="muted"><a href="${origin}/connect">bağlanma sayfası</a> · <a href="${origin}/settings">ayarlar</a></p>` : ""}`,
    });
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "x-frame-options": "DENY", "x-content-type-options": "nosniff", "content-security-policy": PAGE_CSP });
    res.end(html);
  };

  // Wedge watchdog: if the event loop stalls for 30s the process is useless but may still look
  // alive to a TCP check, so exit and let the container supervisor / Fly restart it.
  let last = Date.now();
  let stalls = 0; // iki ölçüm üst üste kilitlenirse çık: kısa bir donma (host taşıması, CPU kıtlığı) yeniden başlatma sebebi olmasın
  setInterval(() => {
    const now = Date.now(), lag = now - last - 5000;
    last = now;
    if (lag > 30_000) {
      stalls += 1;
      console.error(`[hardtools] watchdog: event loop stalled ${Math.round(lag / 1000)}s (${stalls}/2)`);
      if (stalls >= 2) { console.error("[hardtools] watchdog: exiting for a restart"); audit.write({ ev: "watchdog_exit", lag_ms: lag }); process.exit(1); }
    } else stalls = 0;
  }, 5000).unref();

  srv.listen(port, host, () => console.error(`[hardtools] HTTP listening on http://${host}:${port}/mcp (put a TLS-terminating reverse proxy/tunnel in front for Claude web; OAuth enabled for the claude.ai connector dialog)`));
}

main().catch((e) => { console.error("[hardtools] fatal:", (e as Error).message); process.exit(1); });
