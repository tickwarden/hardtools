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

export interface OAuthOptions {
  token: string;
  audit?: (entry: Record<string, unknown>) => void;
  extraRedirectUris?: string[];
}

export class OAuth {
  private key: Buffer;
  private usedCodes    = new Map<string, number>(); // jti -> exp (authorization code single-use)
  private usedInvites  = new Map<string, number>(); // jti -> exp (invite single-use)
  private sessions     = new Map<string, number>(); // sessionId -> exp (invite → consent bridge)
  private failures: number[] = [];
  private extra: Set<string>;

  constructor(private o: OAuthOptions) {
    // Existing v1 HMAC key schedule for a random per-run master key. Keeping it preserves signed grants on restart.
    this.key = crypto.createHash("sha256").update("hardtools-oauth-v1\0" + o.token).digest();
    this.extra = new Set(o.extraRedirectUris ?? []);
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
<p>GitHub Actions: open <strong>BAGLAN.html</strong> from this run’s hardtools-connect ZIP on your computer. In the “Access token” section, match this page’s address and copy the token.</p>
<form method="post" action="/authorize" autocomplete="off">${hidden}<input type="password" name="access_token" autocomplete="off" autofocus required placeholder="access token"><button type="submit">Authorize</button></form>` : "";
    res.writeHead(code, {
      "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY",
      "referrer-policy": "same-origin",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
    });
    res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>hardtools</title>
<style>body{font:16px system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:0 1rem}input{display:block;width:100%;padding:.6rem;margin:.8rem 0;box-sizing:border-box}button{padding:.6rem 1.2rem}.e{color:#b00020}</style>
<h1>hardtools</h1>${error ? `<p class="e">${esc(error)}</p>` : ""}${form}`);
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
      this.o.audit?.({ ev: "oauth_token", grant: "refresh_token" });
      return this.json(res, 200, mint(r.cid, r.grant ?? crypto.randomUUID()));
    }
    this.oerr(res, 400, "unsupported_grant_type", "authorization_code or refresh_token only");
  }
}
