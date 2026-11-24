// AI-generated (Claude, Anthropic), 2026-11-13. Requires human security review before production use.
// The offline connection card delivers the one-use invite and static token encrypted.
//
// Minimal, stateless OAuth 2.1 authorization server for the remote (--http) mode.
//
// Why this exists: the claude.ai "custom connector" dialog has no field for a custom
// `Authorization` header. It probes the URL anonymously and then expects either an
// authless server or an OAuth flow (RFC 9728 protected-resource metadata, RFC 8414
// authorization-server metadata, RFC 7591 dynamic client registration, PKCE). A bare
// `401 {"error":"unauthorized"}` makes the dialog fail with "could not add connector".
//
// Security model:
//   - HARDTOOLS_HTTP_TOKEN is the master secret; disclose it only to the authorized recipient.
//   - Invite codes are HMAC-signed blobs derived from the master secret.
//     Each code is single-use (jti tracked in memory) and expires in 24 hours.
//   - Visiting /invite/<code> pre-authorizes that browser session via a short-lived
//     session cookie, which the consent page then consumes instead of asking for the token.
//   - Invite redemption and browser sessions are tracked per process.
import crypto from "node:crypto";
import { esc as uiEsc, page as uiPage, heading, PAGE_CSP } from "./ui.js";
import type http from "node:http";
import { equalSecret } from "./credentials.js";

const B64 = (b: Buffer | string) => Buffer.from(b).toString("base64url");
// RFC 7636 S256: the challenge is SHA-256 of the ASCII verifier, not a password verifier.
const pkceS256 = (verifier: string) => crypto.createHash("sha256").update(verifier, "ascii").digest("base64url");

const ACCESS_TTL_S  = 60 * 60;           // 1 h
const REFRESH_TTL_S = 12 * 60 * 60;      // longer than any single `serve` job (<6 h)
const CODE_TTL_S    = 60;
const CLIENT_TTL_S  = 7 * 24 * 60 * 60;
const INVITE_TTL_S  = 24 * 60 * 60;      // 24 h — invite link validity
const SESSION_TTL_S = 10 * 60;           // 10 min — time to complete OAuth after visiting invite link
const MAX_BODY      = 16_384;

/** Redirect URIs a client may register: Claude's callbacks plus loopback (native clients, MCP inspector). */
function redirectAllowed(uri: string, extra: Set<string>): boolean {
  if (extra.has(uri)) return true;
  let u: URL; try { u = new URL(uri); } catch { return false; }
  if (u.hash || u.username || u.password) return false;
  if (u.protocol === "https:" && (u.host === "claude.ai" || u.host === "claude.com") && u.pathname === "/api/mcp/auth_callback") return true;
  if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]")) return true;
  return false;
}

export interface GithubIdp {
  clientId: string;
  /**
   * OAuth App istemci sırrı. Verilirse tarayıcı yönlendirmeli (authorization code) akış kullanılır.
   * Verilmezse GitHub **device flow** kullanılır: sır gerekmez, kullanıcı github.com/login/device
   * adresine tek kullanımlık kod girer. Sır hiçbir yerde saklanmak zorunda kalmaz.
   */
  clientSecret?: string;
  /** GitHub kullanıcı adları (küçük/büyük harf farkı yok). Boş liste: yalnız e-posta eşleşmesi. */
  allowedLogins: string[];
  /** true ise allowlist uygulanmaz: GitHub'ın doğruladığı her hesap kabul edilir. */
  allowAny?: boolean;
  /** Doğrulanmış birincil e-postalar; logins boşsa kullanılır. */
  allowedEmails: string[];
  /** Testler/self-host için uç nokta tabanları. Varsayılan: https://github.com ve https://api.github.com */
  webBase?: string;
  apiBase?: string;
}

interface GhPending {
  deviceCode: string;
  userCode: string;
  verifyUri: string;
  intervalS: number;
  exp: number;
  cid: string;
  ru: string;
  cc: string;
  st: string;
  nextPoll: number;
}

export interface OAuthOptions {
  token: string;
  audit?: (entry: Record<string, unknown>) => void;
  extraRedirectUris?: string[];
  /** Verilirse /authorize, token formu yerine GitHub girişine yönlendirir. */
  github?: GithubIdp;
  /** Yeni bir izin (grant) verildiğinde çağrılır: grant -> GitHub login eşlemesi (ayarlar için). */
  onGrant?: (grant: string, login: string) => void;
  /** Çıkış yapılmış grant'lar reddedilir: bağlantı anında düşer. */
  grantRevoked?: (grant: string) => boolean;
}

export class OAuth {
  private key: Buffer;
  private usedCodes    = new Map<string, number>(); // jti -> exp (authorization code single-use)
  private usedInvites  = new Map<string, number>(); // jti -> exp (invite single-use)
  private sessions     = new Map<string, number>(); // sessionId -> exp (invite → consent bridge)
  private failures: number[] = [];
  private extra: Set<string>;
  private github?: GithubIdp;
  private usedHuman = new Map<string, number>();   // jti -> exp (insan doğrulaması tek kullanım)
  private ghPending = new Map<string, GhPending>(); // device-flow ticket -> bekleyen giriş

  constructor(private o: OAuthOptions) {
    // Existing v1 HMAC key schedule for a random per-run master key. Keeping it preserves signed grants on restart.
    this.key = crypto.createHash("sha256").update("hardtools-oauth-v1\0" + o.token).digest();
    this.extra = new Set(o.extraRedirectUris ?? []);
    this.github = o.github;
  }

  // ---- signed blobs ---------------------------------------------------------------------
  private sign(p: Record<string, unknown>): string {
    const body = B64(JSON.stringify(p));
    return `${body}.${B64(crypto.createHmac("sha256", this.key).update(body).digest())}`;
  }
  private verify(blob: unknown, type: string): Record<string, any> | null {
    if (typeof blob !== "string" || blob.length > 4096) return null;
    const [body, mac, extra] = blob.split(".");
    if (!body || !mac || extra !== undefined) return null;
    const want = B64(crypto.createHmac("sha256", this.key).update(body).digest());
    if (!equalSecret(mac, want)) return null;
    let p: any; try { p = JSON.parse(Buffer.from(body, "base64url").toString("utf8")); } catch { return null; }
    if (!p || p.t !== type || typeof p.exp !== "number" || p.exp < Date.now() / 1000) return null;
    return p;
  }
  private now() { return Math.floor(Date.now() / 1000); }

  /** True if `bearer` is an access token minted by this server. */
  accessScope(bearer: string): string | null {
    const at = this.verify(bearer.startsWith("hta.") ? bearer.slice(4) : "", "at");
    if (!at) return null;
    // One grant, not one public client_id. Preserve state across refreshes without storing bearer tokens.
    return typeof at.grant === "string" ? `grant:${at.grant}` : `legacy:${crypto.createHmac("sha256", this.key).update("scope\0").update(bearer).digest("base64url")}`;
  }
  isAccessToken(bearer: string): boolean { return this.accessScope(bearer) !== null; }

  // ---- invite codes ---------------------------------------------------------------------

  /**
   * Mint a single-use invite code valid for 24 hours.
   * Returns the one-use URL for the encrypted connection card.
   */
  mintInvite(origin: string): string {
    const jti = crypto.randomBytes(12).toString("base64url");
    const code = this.sign({ t: "inv", jti, exp: this.now() + INVITE_TTL_S });
    return `${origin}/invite/${encodeURIComponent(code)}`;
  }

  /**
   * Validate and consume an invite code.
   * Returns a short-lived session token on success, null on failure.
   */
  private redeemInvite(code: string): string | null {
    const p = this.verify(code, "inv");
    if (!p) return null;
    const nowS = this.now();
    // Purge expired entries
    for (const [k, e] of this.usedInvites) if (e < nowS) this.usedInvites.delete(k);
    if (this.usedInvites.has(p.jti)) return null; // already used
    this.usedInvites.set(p.jti, p.exp);
    // Mint a short-lived session id
    const sessionId = crypto.randomBytes(24).toString("base64url");
    this.sessions.set(sessionId, nowS + SESSION_TTL_S);
    this.o.audit?.({ ev: "invite_redeemed" });
    return sessionId;
  }

  /** Check whether a session cookie is still valid (without consuming it). */
  private hasValidSession(req: http.IncomingMessage): boolean {
    const sid = this.parseCookie(req, "ht_session");
    if (!sid) return false;
    const exp = this.sessions.get(sid);
    if (!exp || exp < this.now()) { this.sessions.delete(sid ?? ""); return false; }
    return true;
  }

  /** Consume (invalidate) the session after the authorization code is issued. */
  private consumeSession(req: http.IncomingMessage): void {
    const sid = this.parseCookie(req, "ht_session");
    if (sid) this.sessions.delete(sid);
  }

  private parseCookie(req: http.IncomingMessage, name: string): string | null {
    const header = req.headers.cookie ?? "";
    for (const part of header.split(";")) {
      const [k, ...rest] = part.trim().split("=");
      if (k.trim() === name) return decodeURIComponent(rest.join("=").trim());
    }
    return null;
  }

  // ---- helpers --------------------------------------------------------------------------
  /** Public origin. The Host header was already validated against HARDTOOLS_ALLOWED_HOSTS by the caller. */
  origin(req: http.IncomingMessage): string {
    const host = String(req.headers.host ?? "");
    const local = /^(127\.0\.0\.1|localhost|\[::1\])(:|$)/i.test(host);
    return `${local ? "http" : "https"}://${host}`;
  }
  resourceMetadataUrl(req: http.IncomingMessage) { return `${this.origin(req)}/.well-known/oauth-protected-resource`; }

  private json(res: http.ServerResponse, code: number, body: unknown, extra: Record<string, string> = {}) {
    res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store", pragma: "no-cache", ...extra });
    res.end(JSON.stringify(body));
  }
  private oerr(res: http.ServerResponse, code: number, error: string, description: string) {
    this.json(res, code, { error, error_description: description });
  }
  private async readBody(req: http.IncomingMessage): Promise<Buffer | null> {
    const chunks: Buffer[] = []; let size = 0;
    for await (const c of req) { size += (c as Buffer).length; if (size > MAX_BODY) return null; chunks.push(c as Buffer); }
    return Buffer.concat(chunks);
  }
  private async readParams(req: http.IncomingMessage): Promise<Record<string, string> | null> {
    const raw = await this.readBody(req); if (!raw) return null;
    const ct = String(req.headers["content-type"] ?? "").toLowerCase();
    const out: Record<string, string> = {};
    if (ct.includes("application/json")) {
      let j: any; try { j = JSON.parse(raw.toString("utf8")); } catch { return null; }
      if (!j || typeof j !== "object" || Array.isArray(j)) return null;
      for (const [k, v] of Object.entries(j)) if (typeof v === "string") out[k] = v;
    } else {
      for (const [k, v] of new URLSearchParams(raw.toString("utf8"))) out[k] = v;
    }
    return out;
  }

  // ---- routing --------------------------------------------------------------------------
  /** Returns true when the request was an OAuth/discovery/invite route and has been fully handled. */
  async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<boolean> {
    const path = (req.url ?? "").split("?")[0];
    const method = req.method ?? "GET";
    const origin = this.origin(req);

    if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
      if (method !== "GET") { this.oerr(res, 405, "invalid_request", "GET only"); return true; }
      this.json(res, 200, { resource: `${origin}/mcp`, authorization_servers: [origin], bearer_methods_supported: ["header"] });
      return true;
    }
    if (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/oauth-authorization-server/mcp") {
      if (method !== "GET") { this.oerr(res, 405, "invalid_request", "GET only"); return true; }
      this.json(res, 200, {
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        registration_endpoint: `${origin}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
      });
      return true;
    }
    if (path === "/register")           { await this.register(req, res); return true; }
    if (path === "/authorize")          { await this.authorize(req, res, origin); return true; }
    if (path === "/oauth/github/callback") { await this.githubCallback(req, res, origin); return true; }
    if (path === "/oauth/github/poll")     { await this.githubPoll(req, res, origin); return true; }
    if (path === "/oauth/human")           { await this.humanEndpoint(req, res); return true; }
    if (path === "/token")              { await this.tokenEndpoint(req, res); return true; }
    if (path.startsWith("/invite/"))    { await this.handleInvite(req, res, path, origin); return true; }
    return false;
  }

  // ---- /invite/<code> -------------------------------------------------------------------
  private async handleInvite(req: http.IncomingMessage, res: http.ServerResponse, path: string, origin: string) {
    if (req.method !== "GET") { this.oerr(res, 405, "invalid_request", "GET only"); return; }
    const code = decodeURIComponent(path.slice("/invite/".length));
    const sessionId = this.redeemInvite(code);
    if (!sessionId) {
      this.page(res, 410, "Bu davet kullanılmış veya süresi dolmuş. Daveti az önce açtıysan aynı tarayıcı profilinde Claude’dan devam et. Aksi halde yayın sahibiyle iletişime geç.", null);
      return;
    }
    // Establish the guest browser session; Claude initiates its own /authorize request.
    // The user still needs to complete the OAuth flow (connector dialog drives this).
    const cookieExp = new Date((this.now() + SESSION_TTL_S) * 1000).toUTCString();
    res.writeHead(200, {
      "set-cookie": `ht_session=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Expires=${cookieExp}${origin.startsWith("https") ? "; Secure" : ""}`,
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-frame-options": "DENY",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
    });
    const ep = (origin + "/mcp").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
    res.end(`<!doctype html><html lang="tr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>hardtools · Davet kabul edildi</title>
<style>body{font:16px/1.55 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#15332c}input{width:100%;box-sizing:border-box;padding:.65rem;font:inherit}</style>
<h1>Davet kabul edildi</h1><p>Başka dosya veya parola gerekmiyor. <strong>10 dakika içinde</strong> aynı tarayıcı profilinde Claude’u aç. Bu daveti tekrar açma.</p>
<ol><li><strong>Settings → Connectors → Add custom connector</strong> yolunu aç.</li><li>Ad: <b>hardtools</b>. Aşağıdaki adresi URL alanına kopyala.</li><li>OAuth client ID ve secret boş kalsın. Bağlantıyı Claude’dan tamamla.</li></ol>
<label for="ep">MCP adresi</label><input id="ep" readonly value="${ep}"></html>`);
  }

  // ---- RFC 7591 dynamic client registration (stateless: client_id is a signed blob) ------
  private async register(req: http.IncomingMessage, res: http.ServerResponse) {
    if (req.method !== "POST") return this.oerr(res, 405, "invalid_request", "POST only");
    const p = await this.readJsonObject(req);
    if (!p) return this.oerr(res, 400, "invalid_client_metadata", "body must be a JSON object under 16 KB");
    const uris = p.redirect_uris;
    if (!Array.isArray(uris) || uris.length < 1 || uris.length > 10 || !uris.every(u => typeof u === "string" && u.length < 512))
      return this.oerr(res, 400, "invalid_redirect_uri", "redirect_uris must be 1-10 URI strings");
    const bad = (uris as string[]).find(u => !redirectAllowed(u, this.extra));
    if (bad) return this.oerr(res, 400, "invalid_redirect_uri", "redirect URI not allowed (only Claude callbacks and loopback addresses)");
    const iat = this.now();
    const client_id = this.sign({ t: "c", ru: uris, exp: iat + CLIENT_TTL_S });
    const name = typeof p.client_name === "string" ? p.client_name.slice(0, 100) : undefined;
    this.o.audit?.({ ev: "oauth_register", redirect_uris: uris, client_name: name });
    this.json(res, 201, {
      client_id, client_id_issued_at: iat, redirect_uris: uris, client_name: name,
      token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
    });
  }
  private async readJsonObject(req: http.IncomingMessage): Promise<Record<string, any> | null> {
    const raw = await this.readBody(req); if (!raw) return null;
    try { const j = JSON.parse(raw.toString("utf8")); return j && typeof j === "object" && !Array.isArray(j) ? j : null; } catch { return null; }
  }

  // ---- upstream GitHub identity (removes the token-paste form) ---------------------------
  /** GitHub'a yönlendir; orijinal istek imzalı state içinde taşınır. */
  private redirectToGithub(res: http.ServerResponse, origin: string, q: Record<string, string>) {
    const state = this.sign({
      t: "idp", jti: crypto.randomBytes(12).toString("base64url"),
      cid: q.client_id, ru: q.redirect_uri, cc: q.code_challenge,
      st: typeof q.state === "string" ? q.state.slice(0, 512) : "",
      exp: this.now() + 600,
    });
    const u = new URL(`${this.ghWeb()}/login/oauth/authorize`);
    u.searchParams.set("client_id", this.github!.clientId);
    u.searchParams.set("redirect_uri", `${origin}/oauth/github/callback`);
    u.searchParams.set("scope", "read:user user:email");
    u.searchParams.set("state", state);
    u.searchParams.set("allow_signup", "false");
    this.o.audit?.({ ev: "oauth_authorize", via: "github_redirect" });
    res.writeHead(302, { location: u.toString(), "cache-control": "no-store", "referrer-policy": "no-referrer" });
    res.end();
  }

  private async ghJson(url: string, init: RequestInit): Promise<any | null> {
    try {
      const r = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
      return await r.json();
    } catch { return null; }
  }

  private ghWeb() { return (this.github?.webBase ?? "https://github.com").replace(/\/+$/, ""); }
  private ghApi() { return (this.github?.apiBase ?? "https://api.github.com").replace(/\/+$/, ""); }

  /** GitHub token'ından kimliği çöz ve izin listesiyle karşılaştır. */
  private async githubIdentity(ghToken: string): Promise<{ login: string; email: string; permitted: boolean }> {
    const headers = { authorization: `Bearer ${ghToken}`, accept: "application/vnd.github+json", "user-agent": "hardtools-oauth" };
    const user = await this.ghJson(`${this.ghApi()}/user`, { headers });
    const login = String(user?.login ?? "").toLowerCase();
    let email = String(user?.email ?? "").toLowerCase();
    if (!email) {
      const mails = await this.ghJson(`${this.ghApi()}/user/emails`, { headers });
      if (Array.isArray(mails)) {
        const primary = mails.find((m: any) => m?.primary && m?.verified) ?? mails.find((m: any) => m?.verified);
        if (primary && typeof primary.email === "string") email = primary.email.toLowerCase();
      }
    }
    const allowLogin = new Set((this.github?.allowedLogins ?? []).map(v => v.trim().toLowerCase()).filter(Boolean));
    const allowEmail = new Set((this.github?.allowedEmails ?? []).map(v => v.trim().toLowerCase()).filter(Boolean));
    // allowAny: allowlist yok sayılır, ama kimlik yine de GitHub'dan gelmiş olmalı (boş login kabul edilmez).
    const permitted = this.github?.allowAny
      ? Boolean(login)
      : (!!login && allowLogin.has(login)) || (!!email && allowEmail.has(email));
    return { login, email, permitted };
  }

  /** Device flow: GitHub'dan tek kullanımlık kod al ve bekleme sayfasını göster. */
  private async startGithubDevice(res: http.ServerResponse, q: Record<string, string>) {
    const dc = await this.ghJson(`${this.ghWeb()}/login/device/code`, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: this.github!.clientId, scope: "read:user user:email" }).toString(),
    });
    if (!dc || typeof dc.device_code !== "string" || typeof dc.user_code !== "string") {
      this.o.audit?.({ ev: "oauth_authorize", ok: false, via: "github_device", error: "device_code" });
      return this.infoPage(res, 502, "GitHub'dan giriş kodu alınamadı. Birkaç saniye sonra Claude'dan tekrar dene.", null);
    }
    const ticket = crypto.randomBytes(18).toString("base64url");
    const p: GhPending = {
      deviceCode: dc.device_code,
      userCode: String(dc.user_code),
      verifyUri: typeof dc.verification_uri === "string" ? dc.verification_uri : `${this.ghWeb()}/login/device`,
      intervalS: Math.max(5, Math.min(30, Number(dc.interval) || 5)),
      exp: this.now() + Math.max(60, Math.min(900, Number(dc.expires_in) || 900)),
      cid: q.client_id, ru: q.redirect_uri, cc: q.code_challenge,
      st: typeof q.state === "string" ? q.state.slice(0, 512) : "",
      nextPoll: 0,
    };
    this.ghPending.set(ticket, p);
    for (const [k, v] of this.ghPending) if (v.exp < this.now() - 60 || this.ghPending.size > 64) this.ghPending.delete(k);
    this.o.audit?.({ ev: "oauth_authorize", via: "github_device_start" });
    return this.waitPage(res, 200, ticket, p, "");
  }

  /** Device flow bekleme sayfası: GitHub onayını yoklar, hazır olunca Claude'a yönlendirir. */
  private async githubPoll(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (!this.github) return this.infoPage(res, 404, "GitHub girişi bu sunucuda yapılandırılmamış.", null);
    if (req.method !== "GET") return this.infoPage(res, 405, "Yalnız GET.", null);
    const ticket = new URL(req.url ?? "/", origin).searchParams.get("t") ?? "";
    const p = this.ghPending.get(ticket);
    if (!p) return this.infoPage(res, 410, "Giriş oturumu bulunamadı (sunucu yeniden başlamış olabilir). Claude'dan bağlantıyı yeniden başlat.", null);
    if (p.exp < this.now()) { this.ghPending.delete(ticket); this.o.audit?.({ ev: "oauth_authorize", ok: false, via: "github_device", error: "expired" }); return this.infoPage(res, 410, "GitHub kodu süresi doldu. Bağlantıyı yeniden başlat.", null); }
    if (Date.now() < p.nextPoll) return this.waitPage(res, 200, ticket, p, "GitHub onayı bekleniyor…");
    p.nextPoll = Date.now() + p.intervalS * 1000;

    const tok = await this.ghJson(`${this.ghWeb()}/login/oauth/access_token`, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: this.github.clientId, device_code: p.deviceCode, grant_type: "urn:ietf:params:oauth:grant-type:device_code" }).toString(),
    });
    const ghErr = typeof tok?.error === "string" ? tok.error : "";
    if (ghErr === "authorization_pending" || ghErr === "slow_down") {
      if (ghErr === "slow_down") p.intervalS = Math.min(30, p.intervalS + 5);
      return this.waitPage(res, 200, ticket, p, "GitHub onayı bekleniyor…");
    }
    if (!tok || typeof tok.access_token !== "string") {
      this.ghPending.delete(ticket);
      this.o.audit?.({ ev: "oauth_authorize", ok: false, via: "github_device", error: ghErr.slice(0, 40) || "token" });
      const denied = ghErr === "access_denied" || ghErr === "expired_token";
      return this.infoPage(res, denied ? 403 : 502, denied ? "GitHub girişi reddedildi ya da kodun süresi doldu. Bağlantıyı yeniden başlat." : "GitHub erişim anahtarı alınamadı. Tekrar dene.", null);
    }

    const who = await this.githubIdentity(tok.access_token);
    if (!who.permitted) {
      this.ghPending.delete(ticket);
      this.o.audit?.({ ev: "oauth_authorize", ok: false, via: "github_device", login: who.login.slice(0, 64), reason: "not_allowed" });
      return this.infoPage(res, 403, `Bu GitHub hesabına izin verilmiyor${who.login ? ` (${who.login.replace(/[<>"']/g, "")})` : ""}.`, null);
    }

    this.ghPending.delete(ticket);
    // GitHub onayı geldi ama kod henüz üretilmez: önce bot doğrulaması.
    return this.humanPage(res, { cid: p.cid, ru: p.ru, cc: p.cc, st: p.st, login: who.login }, "GitHub girişi tamam. Son adım: insan doğrulaması.");
  }

  private html(resOut: http.ServerResponse, code: number, body: string, extra: Record<string, string> = {}) {
    resOut.writeHead(code, {
      "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "content-security-policy": PAGE_CSP,
      ...extra,
    });
    resOut.end(uiPage({ title: "hardtools", body }));
  }

  private infoPage(res: http.ServerResponse, code: number, message: string, _q: Record<string, string> | null) {
    const esc = (v: string) => v.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
    return this.html(res, code, `<p class="e">${esc(message)}</p>`);
  }

  private waitPage(resOut: http.ServerResponse, code: number, ticket: string, p: GhPending, note: string) {
    const esc = uiEsc;
    const next = `/oauth/github/poll?t=${encodeURIComponent(ticket)}`;
    const body = `${heading("GitHub ile giriş")}
<div class="card">
<p><strong>1.</strong> Şu adresi aç: <a href="${esc(p.verifyUri)}" target="_blank" rel="noreferrer">${esc(p.verifyUri)}</a></p>
<p><strong>2.</strong> Kodu gir: <code class="code">${esc(p.userCode)}</code></p>
<p><strong>3.</strong> Bu sayfa kendiliğinden devam eder; kapatma.</p>
${note ? `<p class="muted">${esc(note)}</p>` : ""}
</div>
<p class="muted">Devam etmiyorsa <a href="${esc(next)}">buraya dokun</a>.</p>
<meta http-equiv="refresh" content="5;url=${esc(next)}">`;
    return this.html(resOut, code, body, {});
  }

  // ---- insan doğrulaması (bot kapısı) -----------------------------------------------------
  // GitHub girişi tamamlandıktan sonra, yetki kodu üretilmeden önce basit bir insan kontrolü.
  // Durum imzalı token içinde taşınır: sunucu belleğine bağlı değildir, yeniden başlatma bozmaz.
  private humanPage(resOut: http.ServerResponse, pending: { cid: string; ru: string; cc: string; st: string; login: string }, note: string) {
    const esc = uiEsc;
    const a = 2 + crypto.randomInt(8), b = 2 + crypto.randomInt(8);
    const token = this.sign({
      t: "hv", jti: crypto.randomBytes(9).toString("base64url"),
      cid: pending.cid, ru: pending.ru, cc: pending.cc, st: pending.st,
      login: pending.login.slice(0, 64), ans: String(a * b), born: Date.now(), exp: this.now() + 300,
    });
    const body = `${heading("İnsan doğrulaması", note)}
<div class="card">
<form method="post" action="/oauth/human" autocomplete="off">
  <input type="hidden" name="h" value="${esc(token)}">
  <label for="answer">${a} × ${b} kaç eder? <span class="muted">(çarpma işlemi)</span></label>
  <input id="answer" name="answer" type="text" inputmode="numeric" pattern="[0-9]{1,6}" required autofocus placeholder="sayı">
  <div style="position:absolute;left:-9999px" aria-hidden="true">
    <label for="website">Bu alanı boş bırak</label>
    <input id="website" name="website" type="text" tabindex="-1" autocomplete="off">
  </div>
  <p class="row" style="margin-top:1rem">
    <button class="primary" type="submit">Doğrula ve devam et</button>
    <span class="muted">Sorunun yanıtı ${esc(pending.login || "hesabın")} için bir kez geçerli.</span>
  </p>
</form>
</div>
<p class="muted">Doğrulama yalnızca senin tarayıcında çözülür; hiçbir üçüncü tarafa veri gitmez.</p>`;
    return this.html(resOut, 200, body, {});
  }

  private async humanEndpoint(req: http.IncomingMessage, resOut: http.ServerResponse) {
    if (req.method !== "POST") return this.infoPage(resOut, 405, "Yalnız POST.", null);
    const p = await this.readParams(req);
    if (!p) return this.infoPage(resOut, 400, "İstek okunamadı.", null);
    const t = this.verify(p.h, "hv");
    if (!t) return this.infoPage(resOut, 400, "Doğrulama süresi doldu. Claude'dan bağlantıyı yeniden başlat.", null);
    if (String(p.website ?? "").trim()) { this.o.audit?.({ ev: "oauth_human", ok: false, reason: "honeypot" }); return this.infoPage(resOut, 400, "Doğrulama başarısız.", null); }
    const humanId = String(t.jti ?? "");
    if (humanId) {
      const nowS = this.now();
      for (const [k, e] of this.usedHuman) if (e < nowS) this.usedHuman.delete(k);
      if (this.usedHuman.has(humanId)) return this.infoPage(resOut, 400, "Bu doğrulama zaten kullanıldı. Claude'dan bağlantıyı yeniden başlat.", null);
      this.usedHuman.set(humanId, Number(t.exp ?? nowS + 300));
    }
    const took = Date.now() - Number(t.born ?? 0);
    if (!Number.isFinite(took) || took < 900) { this.o.audit?.({ ev: "oauth_human", ok: false, reason: "too_fast" }); return this.infoPage(resOut, 400, "Doğrulama çok hızlı tamamlandı; tekrar dene.", null); }
    // Karşılaştırma: hem metin hem sayı olarak (boşluk, görünmez karakter, tam sayı biçimi).
    const given = String(p.answer ?? "").trim();
    const expected = String(t.ans ?? "").trim();
    const givenNum = Number.parseInt(given, 10), expectedNum = Number.parseInt(expected, 10);
    const answerOk = given !== "" && (given === expected || (Number.isFinite(givenNum) && Number.isFinite(expectedNum) && givenNum === expectedNum));
    if (!answerOk) {
      // Teşhis: yanıt hiçbir zaman tutmuyorsa sebebi loglardan görülsün (sayılar hassas değil).
      console.error(`[hardtools] human-check mismatch expected=${JSON.stringify(expected)} got=${JSON.stringify(given)} jti=${humanId.slice(0, 8)}`);
      this.o.audit?.({ ev: "oauth_human", ok: false, reason: "wrong", expected, got: given.slice(0, 32) });
      // Çıkmaz sokak yok: aynı oturum için taze bir soru üret (token tek kullanımlıktı, yenisi imzalanır).
      this.usedHuman.delete(humanId);
      return this.humanPage(resOut, {
        cid: String(t.cid ?? ""), ru: String(t.ru ?? ""), cc: String(t.cc ?? ""), st: String(t.st ?? ""), login: String(t.login ?? ""),
      }, "Yanıt yanlış. Yeni soru hazır, tekrar dene.");
    }

    const jti = crypto.randomBytes(12).toString("base64url");
    if (t.login) this.o.onGrant?.(jti, String(t.login));
    const code = this.sign({ t: "code", jti, cid: t.cid, ru: t.ru, cc: t.cc, exp: this.now() + CODE_TTL_S });
    this.o.audit?.({ ev: "oauth_authorize", ok: true, via: "github+human", login: String(t.login ?? "").slice(0, 64) });
    const back = new URL(String(t.ru));
    back.searchParams.set("code", code);
    if (t.st) back.searchParams.set("state", String(t.st));
    resOut.writeHead(302, { location: back.toString(), "cache-control": "no-store", "referrer-policy": "no-referrer" });
    resOut.end();
  }

  /** GitHub dönüşü: kodu değiştir, hesabı allowlist ile karşılaştır, kendi kodumuzu üret. */
  private async githubCallback(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (!this.github) return this.infoPage(res, 404, "GitHub girişi bu sunucuda yapılandırılmamış.", null);
    if (req.method !== "GET") return this.infoPage(res, 405, "Yalnız GET.", null);
    const q = Object.fromEntries(new URL(req.url ?? "/", origin).searchParams);
    const state = this.verify(q.state, "idp");
    if (!state) return this.infoPage(res, 400, "Giriş isteği geçersiz veya süresi dolmuş. Claude'dan bağlantıyı yeniden başlat.", null);
    if (typeof q.error === "string") { this.o.audit?.({ ev: "oauth_authorize", ok: false, via: "github", error: q.error.slice(0, 40) }); return this.infoPage(res, 400, "GitHub girişi reddedildi.", null); }
    if (typeof q.code !== "string" || !q.code) return this.infoPage(res, 400, "GitHub yetkilendirme kodu gelmedi.", null);

    if (!this.github.clientSecret) return this.infoPage(res, 400, "Bu sunucu GitHub device flow kullanıyor; /authorize üzerinden giriş yap.", null);
    const tok = await this.ghJson(`${this.ghWeb()}/login/oauth/access_token`, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: this.github.clientId, client_secret: this.github.clientSecret, code: q.code, redirect_uri: `${origin}/oauth/github/callback` }).toString(),
    });
    const ghToken = tok && typeof tok.access_token === "string" ? tok.access_token : "";
    if (!ghToken) { this.o.audit?.({ ev: "oauth_authorize", ok: false, via: "github", error: "token_exchange" }); return this.infoPage(res, 400, "GitHub erişim anahtarı alınamadı. Tekrar dene.", null); }

    const who = await this.githubIdentity(ghToken);
    if (!who.permitted) {
      this.o.audit?.({ ev: "oauth_authorize", ok: false, via: "github", login: who.login.slice(0, 64), reason: "not_allowed" });
      return this.infoPage(res, 403, `Bu GitHub hesabına izin verilmiyor${who.login ? ` (${who.login.replace(/[<>"']/g, "")})` : ""}.`, null);
    }
    const login = who.login;

    // Kod üretmeden önce bot doğrulaması.
    return this.humanPage(res, { cid: String(state.cid), ru: String(state.ru), cc: String(state.cc), st: String(state.st ?? ""), login }, "GitHub girişi tamam. Son adım: insan doğrulaması.");
  }

  // ---- authorization endpoint -----------------------------------------------------------
  private async authorize(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    let q: Record<string, string>;
    if (req.method === "GET") q = Object.fromEntries(new URL(req.url ?? "/", origin).searchParams);
    else if (req.method === "POST") { const b = await this.readParams(req); if (!b) return this.page(res, 400, "Request too large or malformed.", null); q = b; }
    else return this.oerr(res, 405, "invalid_request", "GET or POST only");

    // Validate client + redirect_uri FIRST; on failure never redirect (open-redirect protection).
    const client = this.verify(q.client_id, "c");
    if (!client) return this.page(res, 400, "Unknown or expired client. Remove the connector and add it again.", null);
    if (!q.redirect_uri || !Array.isArray(client.ru) || !client.ru.includes(q.redirect_uri))
      return this.page(res, 400, "redirect_uri does not match the registered client.", null);
    const back = (params: Record<string, string>) => {
      const u = new URL(q.redirect_uri); for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
      if (q.state) u.searchParams.set("state", q.state);
      res.writeHead(302, { location: u.toString(), "cache-control": "no-store" }); res.end();
    };
    if (q.response_type !== "code") return back({ error: "unsupported_response_type" });
    if (q.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge ?? ""))
      return back({ error: "invalid_request", error_description: "PKCE with S256 is required" });

    if (req.method === "GET") {
      // Check for valid invite session — if present, skip the token form
      if (this.hasValidSession(req)) {
        // Auto-authorize: issue the code immediately
        this.consumeSession(req);
        const jti = crypto.randomBytes(12).toString("base64url");
        const code = this.sign({ t: "code", jti, cid: q.client_id, ru: q.redirect_uri, cc: q.code_challenge, exp: this.now() + CODE_TTL_S });
        this.o.audit?.({ ev: "oauth_authorize", ok: true, via: "invite_session" });
        return back({ code });
      }
      if (this.github) {
        if (this.github.clientSecret) return this.redirectToGithub(res, origin, q);
        return this.startGithubDevice(res, q);
      }
      return this.page(res, 200, "", q);
    }

    // POST: direct token entry when the web client has no valid invite session.
    const now = Date.now(); this.failures = this.failures.filter(t => now - t < 60_000);
    if (this.failures.length >= 10) return this.page(res, 429, "Too many failed attempts. Wait a minute.", q);
    if (typeof q.access_token !== "string" || !equalSecret(q.access_token.trim(), this.o.token)) {
      this.failures.push(now); this.o.audit?.({ ev: "oauth_authorize", ok: false });
      const ciphertext = typeof q.access_token === "string" && /^(?:YWdlLWVuY3J5|-----BEGIN AGE ENCRYPTED FILE-----)/.test(q.access_token.trim());
      return this.page(res, 401, ciphertext ? "Bu şifreli bağlantı metni, access token değil. Genel BAGLAN.html dosyasında eski paketi açıp yalın token’ı kopyala." : "Wrong access token.", q);
    }
    const jti = crypto.randomBytes(12).toString("base64url");
    const code = this.sign({ t: "code", jti, cid: q.client_id, ru: q.redirect_uri, cc: q.code_challenge, exp: this.now() + CODE_TTL_S });
    this.o.audit?.({ ev: "oauth_authorize", ok: true, via: "direct_token" });
    back({ code });
  }

  private page(res: http.ServerResponse, code: number, error: string, q: Record<string, string> | null) {
    const esc = (s: string) => s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
    const keep = ["response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"];
    const hidden = q ? keep.filter(k => typeof q[k] === "string").map(k => `<input type="hidden" name="${k}" value="${esc(q[k])}">`).join("") : "";
    const form = q ? `<p>Enter the access token only, without the <code>Bearer</code> prefix. Do not paste a connection password, encrypted text, invite URL or private key.</p>
<p>Where the token comes from: a <code>fly secrets</code> deployment stores it in the server’s <code>HARDTOOLS_HTTP_TOKEN</code> secret (for example <code>deploy/fly/.env.local</code> on the machine that deployed it). A GitHub Actions publish shows it in <strong>BAGLAN.html</strong> from that run’s hardtools-connect ZIP.</p>
<form method="post" action="/authorize" autocomplete="off">${hidden}<input type="password" name="access_token" autocomplete="off" autofocus required placeholder="access token"><button type="submit">Authorize</button></form>` : "";
    res.writeHead(code, {
      "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY",
      "referrer-policy": "same-origin",
      "content-security-policy": PAGE_CSP,
    });
    res.end(uiPage({ title: "hardtools · giriş", subtitle: "OAuth", body: `${heading("Bağlantı izni")}${error ? `<p class="e">${esc(error)}</p>` : ""}${form}` }));
  }

  // ---- token endpoint ---------------------------------------------------------------------
  private async tokenEndpoint(req: http.IncomingMessage, res: http.ServerResponse) {
    if (req.method !== "POST") return this.oerr(res, 405, "invalid_request", "POST only");
    const p = await this.readParams(req);
    if (!p) return this.oerr(res, 400, "invalid_request", "malformed or oversized body");
    const mint = (cid: string, grant: string) => {
      const iat = this.now();
      return {
        access_token: "hta." + this.sign({ t: "at", cid, grant, exp: iat + ACCESS_TTL_S }), token_type: "Bearer", expires_in: ACCESS_TTL_S,
        refresh_token: this.sign({ t: "rt", cid, grant, exp: iat + REFRESH_TTL_S }),
      };
    };
    if (p.grant_type === "authorization_code") {
      const c = this.verify(p.code, "code");
      if (!c) return this.oerr(res, 400, "invalid_grant", "invalid or expired code");
      if (this.o.grantRevoked?.(String(c.jti))) return this.oerr(res, 400, "invalid_grant", "grant was revoked (signed out)");
      if (c.cid !== p.client_id || c.ru !== p.redirect_uri) return this.oerr(res, 400, "invalid_grant", "client_id or redirect_uri mismatch");
      const v = p.code_verifier ?? "";
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(v) || !equalSecret(pkceS256(v), String(c.cc))) return this.oerr(res, 400, "invalid_grant", "PKCE verification failed");
      const nowS = this.now(); for (const [k, e] of this.usedCodes) if (e < nowS) this.usedCodes.delete(k);
      if (this.usedCodes.has(c.jti)) return this.oerr(res, 400, "invalid_grant", "code already used");
      this.usedCodes.set(c.jti, c.exp);
      this.o.audit?.({ ev: "oauth_token", grant: "authorization_code" });
      return this.json(res, 200, mint(c.cid, c.jti));
    }
    if (p.grant_type === "refresh_token") {
      const r = this.verify(p.refresh_token, "rt");
      if (!r || (p.client_id && p.client_id !== r.cid)) return this.oerr(res, 400, "invalid_grant", "invalid or expired refresh token");
      if (this.o.grantRevoked?.(String(r.grant))) return this.oerr(res, 400, "invalid_grant", "grant was revoked (signed out)");
      this.o.audit?.({ ev: "oauth_token", grant: "refresh_token" });
      return this.json(res, 200, mint(r.cid, r.grant ?? crypto.randomUUID()));
    }
    this.oerr(res, 400, "unsupported_grant_type", "authorization_code or refresh_token only");
  }
}
