// Kullanıcı bazlı ayarlar: araç aç/kapat, ağ aç/kapat, komut ve URL allowlist'i.
// Kimlik = GitHub login (OAuth), "operator" (statik bearer) veya "public" (anonim bağlantı).
// OAuth grant'ları logine bağlanır; böylece sohbet değişse de ayarlar aynı kullanıcıda kalır.

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { page as uiPage, esc, heading, PAGE_CSP } from "./ui.js";
import type { LocalAccounts } from "./localauth.js";
import { randomPassword } from "./local-cli.js";
import type { OperatorHost, OperatorAccount } from "./operator-tool.js";

export const ALL_TOOLS = [
  "ht_read", "ht_write", "ht_edit", "ht_glob", "ht_search", "ht_mkdir", "ht_move", "ht_trash",
  "ht_empty_trash", "ht_shell", "ht_fetch", "ht_image_search", "ht_share", "ht_transfer_file",
  "ht_status", "ht_stop", "ht_new_shell_env", "ht_add_var", "ht_list_vars", "ht_delete_var",
  "ht_user_input", "ht_ask", "ht_undo", "ht_schedule", "ht_memory", "ht_workspace", "ht_operator", "ht_list_all_tools", "ht_manage_tool",
] as const;

export interface UserSettings {
  disabledTools: string[];
  networkEnabled: boolean;
  allowlistEnabled: boolean;
  allowedCommands: string[];
  allowedUrls: string[];
  /** ht_share için varsayılan bağlantı süresi (dakika, 1–60); 0 = araç varsayılanı. */
  shareTtlMinutes: number;
  /** ht_shell çıktı bütçesi (bayt); 0 = profil varsayılanı, politika sınırını yalnız aşağı çeker. */
  shellMaxOutputBytes: number;
  /** ht_schedule ile planlanabilecek en uzun gecikme (saniye, 0–3600). */
  scheduleMaxS: number;
  updatedAt: number;
  /** Ayarları değiştiren son eylem (arayüzde gösterilir). */
  updatedBy?: string;
}

const clampInt = (v: unknown, lo: number, hi: number) => {
  const n = Math.round(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : lo;
};

export const defaultSettings = (): UserSettings => ({
  disabledTools: [], networkEnabled: true, allowlistEnabled: false,
  shareTtlMinutes: 0, shellMaxOutputBytes: 0, scheduleMaxS: 3600,
  allowedCommands: [], allowedUrls: [], updatedAt: 0,
});

/** İstek bir tarayıcı formundan mı geliyor? (CSP form-action yalnız tarayıcıyı bağlar.) */
const browserForm = (req: http.IncomingMessage) => /text\/html/i.test(String(req.headers.accept ?? ""));

/** Yalnız aynı origin'de bir yol kabul edilir: açık yönlendirme olmaz. */
export function safeNext(v: string | null | undefined): string {
  const s = String(v ?? "").trim();
  if (!s || s.length > 2048) return "";
  if (!s.startsWith("/") || s.startsWith("//")) return "";
  if (/[\\\u0000-\u001f]/.test(s)) return "";
  return s;
}

const MAX_LIST = 200;
const norm = (v: string) => v.trim().slice(0, 512);
const uniq = (a: string[]) => [...new Set(a.map(norm).filter(Boolean))].slice(0, MAX_LIST);

export class UserSettingsStore {
  private users = new Map<string, UserSettings>();
  private grants = new Map<string, string>();  // grant id -> login
  private revoked = new Set<string>();          // çıkış yapılan grant'lar
  /** Çıkış zamanı (ms): bundan önce verilmiş oturum çerezleri geçersizdir. */
  private signedOut = new Map<string, number>();
  private store?: string;
  private keyPath?: string;
  private key?: Buffer;
  private mtime = 0;

  constructor(opts: { store?: string; keyPath?: string } = {}) {
    this.store = opts.store;
    this.keyPath = opts.keyPath;
    this.load();
  }

  // ---- kalıcılık ---------------------------------------------------------------------------
  private load() {
    try {
      if (this.store && fs.existsSync(this.store)) {
        const d = JSON.parse(fs.readFileSync(this.store, "utf8")) as { users?: Record<string, UserSettings>; grants?: Record<string, string>; revoked?: string[]; signedOut?: Record<string, number> };
        for (const [u, at] of Object.entries(d.signedOut ?? {})) this.signedOut.set(u, Number(at) || 0);
        for (const [u, s] of Object.entries(d.users ?? {})) this.users.set(u, { ...defaultSettings(), ...s });
        for (const [g, u] of Object.entries(d.grants ?? {})) this.grants.set(g, u);
        for (const g of d.revoked ?? []) this.revoked.add(g);
      }
    } catch { /* bozuk dosya: temiz başla */ }
  }

  private save() {
    if (!this.store) return;
    try {
      fs.mkdirSync(path.dirname(this.store), { recursive: true, mode: 0o700 });
      const items = Object.fromEntries(this.users);
      const grants = Object.fromEntries(this.grants);
      const tmp = this.store + ".tmp";
      const signedOut = Object.fromEntries(this.signedOut);
      fs.writeFileSync(tmp, JSON.stringify({ v: 1, users: items, grants, revoked: [...this.revoked], ...(Object.keys(signedOut).length ? { signedOut } : {}) }), { mode: 0o600 });
      fs.renameSync(tmp, this.store);
    } catch { /* disk hatası akışı düşürmesin */ }
  }

  // ---- kullanıcılar ------------------------------------------------------------------------
  /** Dosya dışarıdan değiştiyse (elle düzenleme) bellekteki kopyayı tazele. */
  private refreshIfChanged() {
    if (!this.store) return;
    try {
      const m = fs.statSync(this.store).mtimeMs;
      if (m !== this.mtime) { this.mtime = m; this.users.clear(); this.grants.clear(); this.revoked.clear(); this.load(); this.mtime = fs.statSync(this.store).mtimeMs; }
    } catch { /* dosya yoksa bellek kalsın */ }
  }

  get(user: string): UserSettings {
    this.refreshIfChanged();
    const s = this.users.get(user);
    return s ? { ...s, disabledTools: [...s.disabledTools], allowedCommands: [...s.allowedCommands], allowedUrls: [...s.allowedUrls] } : defaultSettings();
  }

  patch(user: string, p: Partial<UserSettings>, by?: string): UserSettings {
    const cur = this.get(user);
    const next: UserSettings = {
      ...cur,
      ...p,
      disabledTools: p.disabledTools ? uniq(p.disabledTools.filter(n => (ALL_TOOLS as readonly string[]).includes(n))) : cur.disabledTools,
      allowedCommands: p.allowedCommands ? uniq(p.allowedCommands) : cur.allowedCommands,
      allowedUrls: p.allowedUrls ? uniq(p.allowedUrls) : cur.allowedUrls,
      shareTtlMinutes: clampInt(p.shareTtlMinutes ?? cur.shareTtlMinutes, 0, 60),
      shellMaxOutputBytes: clampInt(p.shellMaxOutputBytes ?? cur.shellMaxOutputBytes, 0, 1 << 20),
      scheduleMaxS: clampInt(p.scheduleMaxS ?? cur.scheduleMaxS, 0, 3600),
      updatedAt: Date.now(),
      ...(by ? { updatedBy: by } : {}),
    };
    this.users.set(user, next);
    this.save();
    return next;
  }

  /** Aracı aç/kapat; değişen durumu döndürür. */
  setTool(user: string, name: string, enabled: boolean, by?: string): { settings: UserSettings; changed: boolean } {
    if (!(ALL_TOOLS as readonly string[]).includes(name)) throw new Error(`unknown tool: ${name}`);
    const cur = this.get(user);
    const has = cur.disabledTools.includes(name);
    if (enabled && !has) return { settings: cur, changed: false };
    if (!enabled && has) return { settings: cur, changed: false };
    const disabledTools = enabled ? cur.disabledTools.filter(n => n !== name) : [...cur.disabledTools, name];
    return { settings: this.patch(user, { disabledTools }, by), changed: true };
  }

  // ---- grant <-> kullanıcı -----------------------------------------------------------------
  bindGrant(grant: string, login: string) {
    if (!grant || !login) return;
    this.grants.set(grant, login.toLowerCase());
    this.revoked.delete(grant);
    this.save();
  }

  loginForGrant(grant: string): string | undefined {
    return this.grants.get(grant);
  }

  isRevoked(grant: string): boolean {
    return this.revoked.has(grant);
  }

  /** Çıkış: bu kullanıcının tüm grant'larını iptal et (MCP bağlantısı düşer). */
  revokeUser(user: string): number {
    let n = 0;
    for (const [g, u] of this.grants) if (u === user) { this.grants.delete(g); this.revoked.add(g); n++; }
    this.save();
    return n;
  }

  /** Çıkış: bu kullanıcıya ait, şu ana kadar verilmiş tüm oturum çerezleri geçersiz olur. */
  signOut(user: string): void {
    this.signedOut.set(user, Date.now());
    this.save();
  }

  /** Çerez, kullanıcının son çıkışından önce mi verilmiş? (`at` milisaniye) */
  isSignedOutBefore(user: string, atMs: number): boolean {
    const t = this.signedOut.get(user);
    return Boolean(t) && atMs < t!;
  }

  // ---- imzalı çerez -----------------------------------------------------------------------
  private signingKey(): Buffer {
    if (this.key) return this.key;
    try {
      if (this.keyPath && fs.existsSync(this.keyPath)) this.key = fs.readFileSync(this.keyPath);
    } catch { /* yeni anahtar üret */ }
    if (!this.key || this.key.length < 32) {
      this.key = crypto.randomBytes(32);
      try {
        if (this.keyPath) {
          fs.mkdirSync(path.dirname(this.keyPath), { recursive: true, mode: 0o700 });
          fs.writeFileSync(this.keyPath, this.key, { mode: 0o600 });
        }
      } catch { /* kalıcı olamasa da çalışır */ }
    }
    return this.key;
  }

  /**
   * İmzalı oturum çerezi. Sürüm 2: veriliş zamanı (`iat`) ve kimlik türü (`k`) imzaya dahildir.
   * - `iat`, yerel hesapta parola değişimi/silme sonrası eski oturumların düşmesini sağlar.
   * - `k` = "l" yerel hesap, "g" GitHub, "t" statik token: silinen yerel hesabın çerezi geçersiz olur.
   */
  cookieFor(user: string, ttlS = 12 * 3600, kind: "l" | "g" | "t" = "g"): string {
    const iat = Date.now(), exp = Math.floor(iat / 1000) + ttlS;
    const body = `2.${Buffer.from(user).toString("base64url")}.${exp}.${iat}.${kind}`;
    const sig = crypto.createHmac("sha256", this.signingKey()).update(body).digest("base64url");
    return `${body}.${sig}`;
  }

  /** Çerezden kimlik ve veriliş zamanı (saniye). Geçersiz/imzalı bozuksa null. */
  sessionFromCookie(value: string | undefined): { user: string; at: number; kind: "l" | "g" | "t" } | null {  // at = ms
    if (!value) return null;
    const parts = value.split(".");
    if (parts.length !== 6 || parts[0] !== "2") return null;
    const [ver, b64, exp, iat, kind, sig] = parts;
    const body = `${ver}.${b64}.${exp}.${iat}.${kind}`;
    const want = crypto.createHmac("sha256", this.signingKey()).update(body).digest("base64url");
    if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
    if (Number(exp) * 1000 < Date.now()) return null;
    try {
      const user = Buffer.from(b64, "base64url").toString("utf8");
      if (!user) return null;
      return { user, at: Number(iat) || 0, kind: kind === "l" ? "l" : kind === "t" ? "t" : "g" };
    } catch { return null; }
  }

  /** Bu ad bir kullanıcı kaydı olarak biliniyor mu? (Yerel hesapla çakışmayı engellemek için.) */
  hasUser(name: string): boolean {
    return this.users.has(name) || this.grants.has(name);
  }

  userFromCookie(value: string | undefined): string | null {
    return this.sessionFromCookie(value)?.user ?? null;
  }
}

// ---- HTTP arayüzü -------------------------------------------------------------------------

export interface SettingsUIOptions {
  store: UserSettingsStore;
  /** Statik token; yalnızca operatör girişinde kullanılır. */
  operatorToken?: string;
  github?: { clientId: string; webBase?: string; apiBase?: string; allowAny?: boolean; allowedLogins?: string[]; allowedEmails?: string[] };
  origin?: (req: http.IncomingMessage) => string;
  audit?: (ev: Record<string, unknown>) => void;
  /** Yerel hesaplar (GitHub olmadan giriş, GitHub bozulduğunda yedek yol). */
  local?: LocalAccounts;
  /**
   * Yönetici paneli (/operator): tarayıcıdan davet kodu üretme, hesap açma, parola sıfırlama,
   * hesap silme. `token` = HARDTOOLS_OPERATOR_TOKEN (en az 16 karakter). MCP bearer'ından
   * AYRI tutulur: tarayıcıda oturum açan biri MCP anahtarını ele geçirmemeli.
   */
  operatorPanel?: { token?: string };
  /** Bir ad GitHub login'i olarak biliniyor mu? (Yerel hesapla çakışmayı engeller.) */
  reservedLogin?: (name: string) => boolean;
  /** /workspaces: hesabın kökleri ve eski kökü devralma. */
  workspaces?: {
    current: (user: string) => string;
    list: (user: string) => { rel: string; kind: string; files: number; bytes: number; scratchFiles?: number; scratchBytes?: number; lastUsed: number; user?: string; current: boolean }[];
    adopt: (user: string, rel: string) => string;
  };
}

interface Pending { deviceCode: string; userCode: string; verifyUri: string; intervalS: number; exp: number; nextPoll: number }

export class SettingsUI {
  private o: SettingsUIOptions;
  private pending = new Map<string, Pending>();

  constructor(o: SettingsUIOptions) { this.o = o; }

  get store() { return this.o.store; }

  private origin(req: http.IncomingMessage) { return this.o.origin?.(req) ?? `http://${req.headers.host ?? "localhost"}`; }

  private html(res: http.ServerResponse, code: number, body: string, extra: Record<string, string> = {}) {
    res.writeHead(code, {
      "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY",
      "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "content-security-policy": PAGE_CSP, ...extra,
    });
    res.end(body);
  }

  private cookieUser(req: http.IncomingMessage): string | null {
    const raw = String(req.headers.cookie ?? "");
    const m = /(?:^|;\s*)ht_s=([^;]+)/.exec(raw);
    const s = this.o.store.sessionFromCookie(m?.[1]);
    if (!s) return null;
    // Çıkış yapıldıysa o andan önce verilmiş çerez (çalınmış olsa bile) artık çalışmaz.
    if (this.o.store.isSignedOutBefore(s.user, s.at)) return null;
    if (s.kind === "l") {
      const a = this.o.local?.get(s.user);
      // Silinen hesabın çerezi ya da parola değişiminden önce verilmiş çerez geçersizdir.
      if (!a) return null;
      // Milisaniye çözünürlüğü: parola değişiminden önce verilen çerez düşer, sonrası geçerli.
      if (a.pvAt && s.at < a.pvAt) return null;
    }
    return s.user;
  }

  private setCookie(res: http.ServerResponse, value: string, secure: boolean, maxAgeS: number) {
    res.setHeader("set-cookie", `ht_s=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeS}${secure ? "; Secure" : ""}`);
  }

  async handle(req: http.IncomingMessage, res: http.ServerResponse, pathname: string): Promise<boolean> {
    const origin = this.origin(req);
    if (pathname === "/settings") return this.index(req, res, origin), true;
    if (pathname === "/settings/login") return await this.startLogin(req, res, origin), true;
    if (pathname === "/settings/poll") return await this.poll(req, res, origin), true;
    if (pathname === "/settings/token") return await this.tokenLogin(req, res, origin), true;
    if (pathname === "/settings/save") return await this.save(req, res, origin), true;
    if (pathname === "/settings/logout") return await this.logout(req, res, origin), true;
    if (pathname === "/workspaces") return await this.workspacesPage(req, res, origin), true;
    if (pathname === "/") return this.dashboard(req, res, origin), true;
    if (pathname === "/local") {
      const next = new URL(req.url ?? "/", "http://x").searchParams.get("next") ?? "";
      return this.localPage(req, res, "", next), true;
    }
    if (pathname === "/local/login") return await this.localLogin(req, res, origin), true;
    if (pathname === "/local/register") return await this.localRegister(req, res, origin), true;
    if (pathname === "/local/connector") return await this.localConnector(req, res, origin), true;
    if (pathname === "/local/password") return await this.localPassword(req, res, origin), true;
    if (pathname === "/operator") return this.operatorPage(req, res), true;
    if (pathname === "/operator/login") return await this.operatorLogin(req, res, origin), true;
    if (pathname === "/operator/invite") return await this.operatorInvite(req, res, origin), true;
    if (pathname === "/operator/add") return await this.operatorAdd(req, res, origin), true;
    if (pathname === "/operator/passwd") return await this.operatorPasswd(req, res, origin), true;
    if (pathname === "/operator/unlock") return await this.operatorUnlock(req, res, origin), true;
    if (pathname === "/operator/signup") return await this.operatorSignup(req, res, origin), true;
    if (pathname === "/operator/del") return await this.operatorDel(req, res, origin), true;
    if (pathname === "/operator/logout") return await this.operatorLogout(req, res, origin), true;
    const linkMatch = /^\/operator\/link\/([A-Za-z0-9_-]{8,64})$/.exec(pathname);
    if (linkMatch) return await this.operatorLoginLinkPage(req, res, origin, linkMatch[1]), true;
    const revealMatch = /^\/operator\/r\/([A-Za-z0-9_-]{8,64})$/.exec(pathname);
    if (revealMatch) return this.operatorRevealLinkPage(req, res, revealMatch[1]), true;
    return false;
  }

  /**
   * Form gönderiminden sonra çapraz origin'e devam edilecekse 303 kullanılmaz: CSP form-action
   * yönlendirme zincirini de denetlediği için OAuth akışı (… → claude.ai) tarayıcıda kesiliyordu.
   * Bunun yerine kısa bir "devam ediliyor" sayfası döner; gezinme CSP form-action kuralına girmez.
   */
  private continuePage(res: http.ServerResponse, to: string, note: string) {
    const body = `${heading("Devam ediliyor")}
<p class="muted">${esc(note)}</p>
<div class="card"><p><a class="btn" href="${esc(to)}" data-once>Devam et</a></p>
<p class="muted" style="margin-bottom:0"><code>${esc(to)}</code></p></div>
<meta http-equiv="refresh" content="0;url=${esc(to)}">`;
    this.html(res, 200, uiPage({
      title: "Devam ediliyor", subtitle: "devam", body,
      script: `try{location.replace(${JSON.stringify(to)});}catch(e){}`,
    }));
  }

  /** Panel (/): çalışma alanları, ayarlar ve MCP adresi tek yerde; adresi kopyalama düğmesi. */
  private dashboard(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "GET") return this.html(res, 405, uiPage({ title: "Panel", body: `<p class="e">Yalnız GET.</p>` }));
    const user = this.cookieUser(req);
    const localConnector = user && this.o.local?.has(user) ? this.o.local.get(user)?.connector ?? "" : "";
    const mcpUrl = localConnector ? `${origin}/lc/${localConnector}` : `${origin}/mcp`;
    const tiles = [
      { href: "/workspaces", title: "Çalışma alanları", note: "Hesabın kökleri, eski sohbetlerin işi, devralma." },
      { href: "/settings", title: "Ayarlar", note: "Araçlar, ağ, allowlist ve oturum." },
      ...(user ? [{ href: "/settings", title: `Hesap: ${user}`, note: "Bu oturumun kimliği." }] : [{ href: "/local", title: "Yerel hesap", note: "GitHub olmadan giriş yap ya da hesap aç." }]),
    ].map(t => `<a class="tile" href="${t.href}"><b>${esc(t.title)}</b><span>${esc(t.note)}</span></a>`).join("");
    const body = `${heading("Panel", user ? `Giriş: ${user}` : "Bağlantı adresini kopyala, sayfalara göz at.")}
<div class="card">
<h2 style="margin-top:0">MCP adresi</h2>
<p class="muted">Bu adresi Claude'da “Connector ekle” alanına yapıştır. Başkası da kopyalayıp kendi hesabıyla ekleyebilir;${localConnector ? " bu adres yalnızca senin yerel hesabına bağlıdır." : " giriş kendi hesabıyla yapılır."} Bu hesaba bağlı <strong>tüm sohbetler aynı çalışma alanını</strong> görür; başka hesabın dosyaları görünmez.</p>
<div class="copybox"><input id="mcp" type="text" readonly value="${esc(mcpUrl)}"><button type="button" data-copy="#mcp">Kopyala</button></div>
<p class="muted" style="margin-bottom:0">${localConnector ? 'Anahtar sızdıysa <a href="/local">yerel hesap sayfasından</a> yenileyebilirsin.' : `Sunucu: <code>${esc(origin)}</code>`}</p>
</div>
<h2>Sayfalar</h2>
<div class="tiles">${tiles}</div>
${user ? `<form method="post" action="/settings/logout" style="margin:0"><p class="muted" style="margin:0"><button class="ghost" type="submit">çıkış yap</button></p></form>` : `<p class="muted"><a href="/settings">giriş yap</a> · <a href="/local">yerel hesap</a></p>`}`;
    this.html(res, 200, uiPage({ title: "Panel", subtitle: "panel", body }));
  }

  /** /local — yerel hesap girişi ve (izinliyse) kayıt. */
  /** Form gövdesi ya da adres çubuğundan gelen `next` (yalnız aynı origin yolu kabul edilir). */
  private formNext(req: http.IncomingMessage, body?: URLSearchParams | null): string {
    const fromBody = body?.get("next");
    if (fromBody) return safeNext(fromBody);
    const q = new URL(req.url ?? "/", "http://x").searchParams.get("next");
    return q ? safeNext(q) : "";
  }

  private localPage(req: http.IncomingMessage, res: http.ServerResponse, notice = "", next = "") {
    const la = this.o.local;
    const canReg = Boolean(la?.canRegister());
    const keep = safeNext(next);
    const me = this.cookieUser(req);
    const mine = me && la?.has(me) ? la.get(me) : undefined;
    const body = `${heading("Yerel hesap", "GitHub hesabın yoksa ya da GitHub girişi çalışmıyorsa buradan gir.")}
${notice ? `<p class="${notice.startsWith("Hata") ? "e" : "ok"}">${esc(notice)}</p>` : ""}
${mine ? `<div class="card">
<h2 style="margin-top:0">Giriş: ${esc(mine.user)}</h2>
<p class="muted">Bu tarayıcı ${esc(mine.user)} hesabıyla giriş yapmış. Bağlantı adresin:</p>
<div class="copybox"><input id="lc" type="text" readonly value="${esc(this.origin(req) + "/lc/" + mine.connector)}"><button type="button" data-copy="#lc">Kopyala</button></div>
<form method="post" action="/local/connector"><p><button type="submit" data-once>Bağlantı anahtarını yenile</button></p></form>
<p class="muted" style="margin-bottom:0"><form method="post" action="/settings/logout" style="display:inline"><button class="ghost" type="submit">çıkış yap</button></form> · <a href="/">panel</a></p>
</div>` : `<div class="card">
<h2 style="margin-top:0">Giriş</h2>
<form method="post" action="/local/login" autocomplete="on">
  ${keep ? `<input type="hidden" name="next" value="${esc(keep)}">` : ""}
  <label for="lu">Kullanıcı adı</label>
  <input id="lu" name="user" type="text" autocomplete="username" required>
  <label for="lp">Parola</label>
  <input id="lp" name="password" type="password" autocomplete="current-password" required>
  <p><button class="primary" type="submit">Giriş yap</button></p>
</form>
<p class="muted" style="margin-bottom:0">Parolanı unuttuysan <a href="/operator">yönetici paneli</a> yenisini üretir; hesabın hiç yoksa aşağıdan aç.</p>`}
</div>
${mine ? "" : canReg ? `<div class="card">
<h2 style="margin-top:0">Hesap aç</h2>
<p class="muted">${la?.count() === 0 ? "Bu sunucuda henüz yerel hesap yok: ilk hesabı sen açacaksın." : "Yeni yerel hesap aç."} Parola en az 10 karakter, iki tür karakter içermeli.</p>
<form method="post" action="/local/register" autocomplete="off">
  ${keep ? `<input type="hidden" name="next" value="${esc(keep)}">` : ""}
  <label for="ru">Kullanıcı adı (3-32 karakter)</label>
  <input id="ru" name="user" type="text" autocomplete="username" required>
  <label for="rp">Parola</label>
  <input id="rp" name="password" type="password" autocomplete="new-password" required>
  <p><button type="submit">Hesap aç</button></p>
</form>
</div>` : `<div class="card">
<h2 style="margin-top:0">Hesap aç</h2>
<p class="muted">Bu sunucuda kayıt <strong>davet koduna</strong> bağlı (${la?.count() ?? 0} yerel hesap var). Kodu yönetici üretir; sen yalnızca bir kez kullanabilirsin.</p>
<form method="post" action="/local/register" autocomplete="off">
  ${keep ? `<input type="hidden" name="next" value="${esc(keep)}">` : ""}
  <label for="rc">Davet kodu</label>
  <input id="rc" name="code" type="text" placeholder="XXXX-XXXX" autocomplete="off" required>
  <label for="ru">Kullanıcı adı (3-32 karakter)</label>
  <input id="ru" name="user" type="text" autocomplete="username" required>
  <label for="rp">Parola</label>
  <input id="rp" name="password" type="password" autocomplete="new-password" required>
  <p><button type="submit">Hesap aç</button></p>
</form>
<p class="muted" style="margin-bottom:0">Kod yoksa <a href="/operator">yönetici panelinden</a> üret (tarayıcıdan; terminal gerekmez).</p>
</div>`}
${mine ? `<div class="card">
<h2 style="margin-top:0">Parola değiştir</h2>
<form method="post" action="/local/password" autocomplete="off">
  <label for="cp">Mevcut parola</label>
  <input id="cp" name="current" type="password" autocomplete="current-password" required>
  <label for="np">Yeni parola</label>
  <input id="np" name="next" type="password" autocomplete="new-password" required>
  <p><button type="submit">Parolayı değiştir</button></p>
</form>
</div>` : ""}
<p class="muted"><a href="/">panel</a> · <a href="/settings/login">GitHub ile giriş</a> · <a href="/operator">yönetici paneli</a></p>`;
    this.html(res, 200, uiPage({ title: "Yerel hesap", subtitle: "local", body }));
  }

  /** Form gönderimi aynı origin'den mi? Origin yoksa/webview "null" ise kabul edilir. */
  private sameOriginForm(req: http.IncomingMessage, origin: string): boolean {
    const o = req.headers.origin;
    if (!o || o === "null") return true;
    try { return new URL(o).origin === new URL(origin).origin; } catch { return false; }
  }

  private async localLogin(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "POST") return this.localPage(req, res);
    if (!this.sameOriginForm(req, origin)) return this.localPage(req, res, "Hata: form başka bir siteden gönderildi.", this.formNext(req));
    const la = this.o.local;
    if (!la) return this.localPage(req, res, "Hata: bu sunucuda yerel hesaplar kapalı.", this.formNext(req));
    const p = await this.body(req);
    const keep = this.formNext(req, p);
    const user = (p?.get("user") ?? "").trim().toLowerCase();
    const pw = p?.get("password") ?? "";
    const r = la.verify(user, pw);
    if (!r.ok) {
      this.o.audit?.({ ev: "local_login_failed", user });
      // Hata sayfası `next`i korur: OAuth akışındaki kullanıcı yazım hatası yüzünden akışı kaybetmez.
      return this.localPage(req, res, `Hata: ${r.error}`, keep);
    }
    this.o.audit?.({ ev: "local_login", user });
    this.setCookie(res, this.o.store.cookieFor(user, 12 * 3600, "l"), origin.startsWith("https://"), 12 * 3600);
    const to = keep;
    if (to && browserForm(req)) return this.continuePage(res, to, "Giriş tamam. Bağlantı akışına dönülüyor…");
    res.writeHead(303, { location: to || "/", "cache-control": "no-store" }); res.end();
  }

  private async localRegister(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "POST") return this.localPage(req, res);
    if (!this.sameOriginForm(req, origin)) return this.localPage(req, res, "Hata: form başka bir siteden gönderildi.", this.formNext(req));
    const la = this.o.local;
    if (!la) return this.localPage(req, res, "Hata: bu sunucuda yerel hesaplar kapalı.", this.formNext(req));
    const openReg = la.canRegister();
    const p = await this.body(req);
    const keep = this.formNext(req, p);
    const user = (p?.get("user") ?? "").trim().toLowerCase();
    // Kayıt "first" modunda kapalıysa tek kullanımlık davet kodu gerekir: kullanıcı
    // "Kullanıcı adı veya parola yanlış" hatasında kilitli kalmasın.
    if (!openReg) {
      const code = p?.get("code") ?? "";
      if (!code.trim()) return this.localPage(req, res, "Hata: kayıt davet koduna bağlı; kodu yaz.", keep);
      if (!la.redeemInvite(code)) return this.localPage(req, res, "Hata: davet kodu geçersiz ya da süresi dolmuş.", keep);
    }
    const r = la.create(user, p?.get("password") ?? "", (n) => Boolean(this.o.reservedLogin?.(n)));
    if (!r.ok) return this.localPage(req, res, `Hata: ${r.error}`, keep);
    this.o.audit?.({ ev: "local_account_created", user: r.account.user });
    this.setCookie(res, this.o.store.cookieFor(r.account.user, 12 * 3600, "l"), origin.startsWith("https://"), 12 * 3600);
    const to = keep;
    if (to && browserForm(req)) return this.continuePage(res, to, "Hesap açıldı. Bağlantı akışına dönülüyor…");
    res.writeHead(303, { location: to || "/", "cache-control": "no-store" }); res.end();
  }

  /** Oturum sahibi kendi parolasını değiştirir (mevcut parola doğrulanır). */
  private async localPassword(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "POST") return this.localPage(req, res);
    if (!this.sameOriginForm(req, origin)) return this.localPage(req, res, "Hata: form başka bir siteden gönderildi.");
    const user = this.cookieUser(req);
    const la = this.o.local;
    if (!user || !la?.has(user)) return this.localPage(req, res, "Hata: parola değiştirmek için giriş yap.");
    const p = await this.body(req);
    const r = la.changePassword(user, p?.get("current") ?? "", p?.get("next") ?? "");
    if (!r.ok) return this.localPage(req, res, `Hata: ${r.error}`);
    this.o.audit?.({ ev: "local_password_changed", user });
    this.setCookie(res, this.o.store.cookieFor(user, 12 * 3600, "l"), origin.startsWith("https://"), 12 * 3600);
    return this.localPage(req, res, "Parola değişti.");
  }

  /** Bağlantı anahtarını yenile (sızmışsa eski adres çalışmaz). */
  private async localConnector(req: http.IncomingMessage, res: http.ServerResponse, _origin: string) {
    if (req.method !== "POST") return this.localPage(req, res);
    const user = this.cookieUser(req);
    const la = this.o.local;
    if (!user || !la?.has(user)) return this.localPage(req, res, "Hata: yerel hesap oturumu yok.");
    la.rotateConnector(user);
    this.o.audit?.({ ev: "local_connector_rotated", user });
    res.writeHead(303, { location: "/", "cache-control": "no-store" }); res.end();
  }

  /** /workspaces — hangi hesap hangi kökte, ne kadar iş var, eski kökü devral. */
  private async workspacesPage(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const user = this.cookieUser(req);
    if (!user) return this.loginPage(res, "Çalışma alanlarını görmek için giriş yap.");
    const cur = () => this.o.workspaces?.current(user) ?? "";
    const ws = this.o.workspaces;
    if (!ws) return this.html(res, 404, uiPage({ title: "Çalışma alanları", body: `<p class="e">Bu sunucuda çalışma alanı listesi kapalı.</p>` }));
    let notice = "";
    if (req.method === "POST") {
      // Oturum çerezi SameSite=Lax olsa da kendi origin dışından gelen formu reddet (derinlemesine savunma).
      if (!this.sameOriginForm(req, origin)) notice = "Hata: form başka bir siteden gönderildi.";
      else {
        const p = await this.body(req);
        const dir = p?.get("adopt");
        if (!dir) notice = "Hata: devralınacak dizin seçilmedi.";
        else { try { notice = ws.adopt(user, dir); } catch (e) { notice = `Hata: ${(e as Error).message}`; } }
      }
    }
    const rows = ws.list(user);
    const kb = (n: number) => n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : n < 1 << 30 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
    const body = `${heading("Çalışma alanları", "Bu hesaba bağlı tüm Claude sohbetleri aynı çalışma alanını görür (hesabında tek kök). Aşağıdaki eski dizinler önceki sürümlerden kalan işlerdir: Devral, seçilen dizinin dosyalarını hesap köküne taşır; var olanın üzerine yazmaz. Kabuk iskeleti (.hardtools) ve geri dönüşüm kutusu taşınmaz.")}
${notice ? `<p class="${notice.startsWith("Hata") ? "e" : "ok"}">${esc(notice)}</p>` : ""}
<div class="card"><div class="tablewrap"><table>
<thead><tr><th>Dizin</th><th>Tür</th><th>Dosya</th><th>Boyut</th><th>Son kullanım</th><th></th></tr></thead>
<tbody>${rows.map(r => `<tr${r.current ? ' style="font-weight:600"' : ""}>
<td><code>${esc(r.rel)}</code>${r.current ? ' <span class="pill">bu hesap</span>' : ""}${esc(r.rel) === path.basename(cur()) ? ' <span class="pill on">etkin</span>' : ""}</td>
<td>${r.kind === "account" ? "hesap" : "sohbet"}${r.user ? ` · ${esc(r.user)}` : ""}</td>
<td>${r.files}${r.scratchFiles ? ` <span class="muted">(+${r.scratchFiles} iskelet)</span>` : ""}</td><td>${kb(r.bytes)}${r.scratchBytes ? ` <span class="muted">+ ${kb(r.scratchBytes)} iskelet</span>` : ""}</td><td>${new Date(r.lastUsed).toISOString().replace("T", " ").slice(0, 16)}</td>
<td>${r.current ? "" : `<form method="post" action="/workspaces" style="margin:0" onsubmit="return confirm('${esc(r.rel)} dizinindeki dosyalar hesap köküne taşınacak. Var olan dosyalar korunur. Devam?')"><input type="hidden" name="adopt" value="${esc(r.rel)}"><button type="submit" data-once>Devral</button></form>`}</td>
</tr>`).join("") || `<tr><td colspan="6" class="muted">Kayıt yok.</td></tr>`}</tbody></table></div></div>
<p class="muted">Aynı listeyi modelden de isteyebilirsin: <code>ht_workspace {"action":"list"}</code> · devam: <code>ht_workspace {"action":"adopt","dir":"u-…"}</code></p>
<p class="muted"><a href="/">panel</a> · <a href="/settings">ayarlar</a></p>`;
    this.html(res, 200, uiPage({ title: "Çalışma alanları", subtitle: "workspaces", body, wide: true }));
  }

  // ---- Yönetici (operatör) paneli ---------------------------------------------------------
  //
  // Neden var: davet kodu, parola sıfırlama ve hesap açma yalnızca CLI ile yapılabiliyordu.
  // Fly.io panosunda web terminal yok (kaldırıldı), yani yalnızca tarayıcısı olan biri kod
  // üretemiyordu. Panel HARDTOOLS_OPERATOR_TOKEN ile korunur; MCP bearer'ından AYRIDIR:
  // tarayıcıda oturum açan biri MCP anahtarını ele geçirmemeli.

  private opReveals = new Map<string, { text: string; note: string; exp: number }>();
  private opFails = new Map<string, { n: number; until: number }>();
  /** Çıkış yapılan panel oturumları: çerez kopyalanmış olsa da süresi dolana kadar geçersiz kalır. */
  private opRevoked = new Map<string, number>();
  /** ht_operator için tarayıcıda onaylanmış "araç oturumu" (grant). */
  private opGrantExp = 0;
  /** Tek kullanımlık giriş bağlantıları (id → son kullanma). */
  private opLoginLinks = new Map<string, number>();
  /** Tek seferlik gösterim bağlantıları (parola/kod): panel oturumu gerektirmez. */
  private opRevealLinks = new Map<string, { text: string; note: string; exp: number }>();
  private static readonly OP_MAX_FAILS = 6;

  private opSecret(): string { return (this.o.operatorPanel?.token ?? "").trim(); }
  /** Panel yalnız gerçek bir anahtar tanımlıysa açılır (kısa/boş değer paneli kilitlemez, kapatır). */
  private opEnabled(): boolean { return this.opSecret().length >= 16; }

  /** Çerez imzası anahtarı = operatör anahtarının özeti → anahtar değişince tüm panel oturumları düşer. */
  private opMac(exp: string, jti: string): string {
    return crypto.createHmac("sha256", crypto.createHash("sha256").update(this.opSecret()).digest())
      .update(`ht_op|${exp}|${jti}`).digest("base64url");
  }

  /** Çerezden (exp, jti) çiftini okur; imza ve süre geçerliyse döner. */
  private opCookieParts(req: http.IncomingMessage): { exp: string; jti: string } | null {
    if (!this.opEnabled()) return null;
    const m = /(?:^|;\s*)ht_op=([^;]+)/.exec(String(req.headers.cookie ?? ""));
    const [exp, jti, mac] = (m?.[1] ?? "").split(".");
    if (!exp || !jti || !mac) return null;
    if (!/^\d{1,16}$/.test(exp) || Number(exp) <= Date.now()) return null;
    const now = Date.now();
    for (const [k, v] of this.opRevoked) if (v < now) this.opRevoked.delete(k);
    if (this.opRevoked.has(jti)) return null;
    const want = Buffer.from(this.opMac(exp, jti)), got = Buffer.from(mac);
    if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
    return { exp, jti };
  }

  private opAuthed(req: http.IncomingMessage): boolean { return this.opCookieParts(req) !== null; }

  private opSetCookie(res: http.ServerResponse, origin: string) {
    const exp = String(Date.now() + 3600_000);
    const jti = crypto.randomBytes(9).toString("base64url");
    res.setHeader("set-cookie", `ht_op=${exp}.${jti}.${this.opMac(exp, jti)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600${origin.startsWith("https://") ? "; Secure" : ""}`);
  }

  /**
   * Üretilen kod/parola POST yanıtında değil, kısa ömürlü bir kimlikle gösterilir:
   * sayfa yenilendiğinde form yeniden gönderilmez (ikinci hesap/kod üretilmez).
   */
  private opReveal(text: string, note: string): string {
    const now = Date.now();
    for (const [k, v] of this.opReveals) if (v.exp < now) this.opReveals.delete(k);
    if (this.opReveals.size > 50) this.opReveals.clear();
    const id = crypto.randomBytes(9).toString("base64url");
    this.opReveals.set(id, { text, note, exp: now + 180_000 });
    return id;
  }

  private opThrottled(ip: string): boolean {
    const f = this.opFails.get(ip);
    return Boolean(f && f.n >= SettingsUI.OP_MAX_FAILS && f.until > Date.now());
  }

  private opFail(ip: string) {
    const now = Date.now();
    const f = this.opFails.get(ip);
    if (!f || f.until <= now) this.opFails.set(ip, { n: 1, until: now + 10 * 60_000 });
    else { f.n += 1; f.until = now + 10 * 60_000; }
    if (this.opFails.size > 512) this.opFails.clear();
  }

  // ---- ht_operator köprüsü: panelin yaptığı her şey, sohbetten ----------------------------

  private opGrantActive(): boolean { return this.opEnabled() && this.opGrantExp > Date.now(); }
  private opGrantLeftS(): number { return Math.max(0, Math.round((this.opGrantExp - Date.now()) / 1000)); }
  private opGrantOpen(seconds = 1800) { this.opGrantExp = Date.now() + seconds * 1000; }

  private opLoginLink(origin: string): { url: string; minutes: number } {
    const now = Date.now();
    for (const [k, v] of this.opLoginLinks) if (v < now) this.opLoginLinks.delete(k);
    if (this.opLoginLinks.size > 20) this.opLoginLinks.clear();
    const id = crypto.randomBytes(12).toString("base64url");
    const minutes = 15;
    this.opLoginLinks.set(id, now + minutes * 60_000);
    return { url: `${origin}/operator/link/${id}`, minutes };
  }

  private opRevealLink(origin: string, text: string, note: string): { url: string; minutes: number } {
    const now = Date.now();
    for (const [k, v] of this.opRevealLinks) if (v.exp < now) this.opRevealLinks.delete(k);
    if (this.opRevealLinks.size > 50) this.opRevealLinks.clear();
    const id = crypto.randomBytes(12).toString("base64url");
    const minutes = 5;
    this.opRevealLinks.set(id, { text, note, exp: now + minutes * 60_000 });
    return { url: `${origin}/operator/r/${id}`, minutes };
  }

  private accountsAsRows(): OperatorAccount[] {
    const la = this.o.local;
    if (!la) return [];
    return la.list().map((u) => {
      const a = la.get(u)!;
      return { user: a.user, createdAt: a.createdAt, lastLogin: a.lastLogin, locked: la.isLocked(u), connector: a.connector };
    });
  }

  /** ht_operator aracının gördüğü yüzey: panelin TÜM işlevleri buradan geçer. */
  operatorHost(): OperatorHost {
    const la = () => this.o.local;
    const reserved = this.o.reservedLogin ?? (() => false);
    return {
      enabled: () => this.opEnabled(),
      checkToken: (t: string) => {
        if (!this.opEnabled()) return false;
        const want = Buffer.from(this.opSecret()), got = Buffer.from(String(t ?? "").trim());
        return want.length === got.length && crypto.timingSafeEqual(want, got);
      },
      grantActive: () => this.opGrantActive(),
      grantLeftS: () => this.opGrantLeftS(),
      loginLink: (origin: string) => this.opLoginLink(origin),
      revealLink: (origin: string, text: string, note: string) => this.opRevealLink(origin, text, note),
      accounts: () => this.accountsAsRows(),
      account: (u: string) => this.accountsAsRows().find((a) => a.user === u.trim().toLowerCase()),
      upsertAccount: (user: string, password: string) => {
        const store = la();
        if (!store) return { ok: false as const, error: "bu sunucuda yerel hesaplar kapalı" };
        const u = user.trim().toLowerCase();
        const exists = store.has(u);
        let last = "";
        // Üretilen parola kullanıcı adını içerebilir: politikaya takılırsa yenisini dene.
        for (let i = 0; i < 5; i++) {
          const pw = password || randomPassword(20);
          const r = exists ? store.adminSetPassword(u, pw) : store.create(u, pw, reserved);
          if (r.ok) return { ok: true as const, created: !exists, password: pw };
          last = r.error ?? "işlem başarısız";
          if (password) break;
        }
        return { ok: false as const, error: last };
      },
      removeAccount: (u: string) => Boolean(la()?.remove(u)),
      unlockAccount: (u: string) => Boolean(la()?.unlock(u)),
      rotateConnector: (u: string) => la()?.rotateConnector(u) ?? null,
      createInvite: (ttlMin: number) => {
        const store = la();
        if (!store) throw new Error("yerel hesaplar kapalı");
        return store.createInvite(Math.max(5, ttlMin) * 60_000);
      },
      inviteCount: () => la()?.inviteCount() ?? 0,
      signupInfo: () => la()?.signupInfo() ?? { mode: "kapalı", source: "env" },
      setSignup: (mode) => {
        const store = la();
        if (!store) throw new Error("yerel hesaplar kapalı");
        return store.setSignup(mode);
      },
      logout: () => { this.opGrantExp = 0; this.opRevoked.clear(); },
      audit: (ev: Record<string, unknown>) => this.o.audit?.(ev),
    };
  }

  private opDisabledPage(req: http.IncomingMessage, res: http.ServerResponse) {
    const body = `${heading("Yönetici paneli kapalı", "Davet kodu ve hesap işlemleri için bir yönetici anahtarı tanımla.")}
<div class="card">
<p>Sunucuda <code>HARDTOOLS_OPERATOR_TOKEN</code> tanımlı değil (en az 16 karakter). Yalnızca tarayıcın varsa:</p>
<ol>
<li>Fly.io panosunda uygulamayı aç → <b>Secrets</b> → <b>Add secret</b>.</li>
<li>Ad: <code>HARDTOOLS_OPERATOR_TOKEN</code> · Değer: en az 16 karakter rastgele bir metin.</li>
<li>Kaydet → makine yeniden başlar (<b>Machines</b> → <b>Restart</b> de yeter).</li>
<li>Bu sayfayı yenile ve anahtarı gir.</li>
</ol>
<p class="muted" style="margin-bottom:0">Terminalin varsa: <code>flyctl secrets set HARDTOOLS_OPERATOR_TOKEN="$(openssl rand -hex 24)" -a &lt;uygulama&gt;</code></p>
</div>
<p class="muted"><a href="/local">yerel hesap</a> · <a href="/">panel</a></p>`;
    this.html(res, 200, uiPage({ title: "Yönetici paneli", subtitle: "operator", body }));
  }

  private operatorPage(req: http.IncomingMessage, res: http.ServerResponse, notice = "", kind: "ok" | "err" = "ok") {
    if (!this.opEnabled()) return this.opDisabledPage(req, res);
    const origin = this.origin(req);
    const authed = this.opAuthed(req);
    const noticeHtml = notice ? `<p class="${kind === "err" ? "e" : "ok"}">${esc(notice)}</p>` : "";
    const revealId = new URL(req.url ?? "/", "http://x").searchParams.get("reveal");
    const rev = revealId ? this.opReveals.get(revealId) : undefined;
    const revealHtml = rev
      ? `<div class="card"><p class="muted" style="margin-top:0">${esc(rev.note)} — bu değer 3 dakika boyunca görünür, sonra bir daha gösterilmez.</p>
<div class="copybox"><input id="rev" type="text" readonly value="${esc(rev.text)}"><button type="button" data-copy="#rev">Kopyala</button></div></div>`
      : "";

    if (!authed) {
      const body = `${heading("Yönetici girişi", "Davet kodu üretmek ve hesapları yönetmek için yönetici anahtarını gir.")}
${noticeHtml}
<div class="card">
<form method="post" action="/operator/login" autocomplete="off">
  <label for="opt">Yönetici anahtarı (<code>HARDTOOLS_OPERATOR_TOKEN</code>)</label>
  <input id="opt" name="token" type="password" autocomplete="off" required autofocus>
  <p class="row" style="margin-bottom:0"><button class="primary" type="submit">Giriş</button><a class="btn" href="/local">yerel hesap</a></p>
</form>
</div>
<p class="muted">Anahtar sunucuda <code>HARDTOOLS_OPERATOR_TOKEN</code> olarak tanımlıdır (Fly.io → Secrets). Kaybettiysen panodan yeni bir değer gir; makine yeniden başlarken eski oturumlar da düşer.</p>`;
      return this.html(res, 200, uiPage({ title: "Yönetici girişi", subtitle: "operator", body }));
    }

    const la = this.o.local;
    const accounts = la ? la.list().map((u) => la.get(u)!).filter(Boolean) : [];
    const when = (t: number) => (t ? new Date(t).toISOString().replace("T", " ").slice(0, 16) : "—");
    const rows = accounts.map((a) => `<tr>
<td><code>${esc(a.user)}</code></td>
<td>${when(a.createdAt)}</td>
<td>${when(a.lastLogin)}</td>
<td>${la && la.isLocked(a.user) ? '<span class="pill off">kilitli</span>' : '<span class="pill on">açık</span>'}</td>
<td>
<form method="post" action="/operator/passwd" style="margin:0" onsubmit="return confirm('${esc(a.user)} için yeni bir parola üretilsin mi? Eski parola ve açık oturumlar geçersiz olur.')"><input type="hidden" name="user" value="${esc(a.user)}"><button type="submit" data-once>Parola sıfırla</button></form>
<form method="post" action="/operator/unlock" style="margin:0"><input type="hidden" name="user" value="${esc(a.user)}"><button type="submit" data-once>Kilidi aç</button></form>
<form method="post" action="/operator/del" style="margin:0" onsubmit="return confirm('${esc(a.user)} hesabı silinsin mi? MCP adresi çalışmayı bırakır; dosyaları diskte kalır.')"><input type="hidden" name="user" value="${esc(a.user)}"><button type="submit" data-once>Sil</button></form>
</td></tr>`).join("");

    const viaTool = new URL(req.url ?? "/", "http://x").searchParams.get("tool") === "1";
    const toolHtml = viaTool
      ? `<p class="ok">Yönetici oturumu açıldı. <code>ht_operator</code> aracı 30 dakika boyunca anahtarsız çalışır.</p>` : "";
    const signup = la?.signupInfo();
    const body = `${heading("Yönetici paneli", "Davet kodu, hesap ve parola işlemleri. Bu sayfa MCP anahtarıyla değil, ayrı bir yönetici anahtarıyla korunur.")}
${noticeHtml}${toolHtml}${revealHtml}
<div class="card">
<h2 style="margin-top:0">Davet kodu üret</h2>
<p class="muted">Tek kullanımlıktır; kod yalnızca bir kez gösterilir ve süresi dolunca geçersiz olur. Kullanıcı kodu <a href="/local">/local</a> sayfasındaki <b>Hesap aç</b> bölümüne yazar.</p>
<form method="post" action="/operator/invite">
  <label for="ttl">Geçerlilik</label>
  <select id="ttl" name="ttl">
    <option value="30">30 dakika</option>
    <option value="1440" selected>24 saat</option>
    <option value="10080">7 gün</option>
    <option value="43200">30 gün</option>
  </select>
  <p style="margin-bottom:0"><button class="primary" type="submit" data-once>Kod üret</button></p>
</form>
<p class="muted" style="margin-bottom:0">Bekleyen kod: <b>${la ? la.inviteCount() : 0}</b> · Hesap: <b>${accounts.length}</b> · Araç oturumu: <b>${this.opGrantActive() ? this.opGrantLeftS() + " sn" : "yok"}</b></p>
</div>
<div class="card">
<h2 style="margin-top:0">Hesap aç (kodsuz)</h2>
<form method="post" action="/operator/add" autocomplete="off">
  <label for="nu">Kullanıcı adı</label>
  <input id="nu" name="user" type="text" required placeholder="kucuk-harf-ve-rakam">
  <label for="np">Parola <span class="muted">(boş bırakırsan güçlü parola üretilir)</span></label>
  <input id="np" name="password" type="password" autocomplete="new-password" placeholder="boş = üret">
  <p style="margin-bottom:0"><button class="primary" type="submit" data-once>Hesabı aç</button></p>
</form>
</div>
<div class="card">
<h2 style="margin-top:0">Kayıt modu</h2>
<p class="muted">Şu an: <b>${esc(signup?.mode ?? "—")}</b> (${signup?.source === "operator" ? "operatör seçimi" : "ortam değişkeni"}). <code>first</code> = yalnızca hiç hesap yokken kayıt; <code>open</code> = herkese açık; <code>off</code> = kayıt kapalı (yalnızca panel/araç hesap açar).</p>
<form method="post" action="/operator/signup">
  <label for="sg">Yeni mod</label>
  <select id="sg" name="signup">
    <option value="first"${signup?.mode === "first" ? " selected" : ""}>first — ilk hesap</option>
    <option value="open"${signup?.mode === "open" ? " selected" : ""}>open — herkese açık</option>
    <option value="off"${signup?.mode === "off" ? " selected" : ""}>off — kapalı</option>
    <option value="env">ortam değişkenine dön</option>
  </select>
  <p style="margin-bottom:0"><button type="submit" data-once>Kaydet</button></p>
</form>
</div>
<div class="card">
<h2 style="margin-top:0">Hesaplar</h2>
<div class="tablewrap"><table>
<thead><tr><th>Hesap</th><th>Oluşturma</th><th>Son giriş</th><th>Durum</th><th></th></tr></thead>
<tbody>${rows || `<tr><td colspan="5" class="muted">Hesap yok.</td></tr>`}</tbody></table></div>
<p class="muted" style="margin-bottom:0">"Parola sıfırla" güçlü bir parola üretir ve bir kez gösterir; parola hiçbir yerde saklanmaz (yalnızca scrypt özeti).</p>
</div>
<form method="post" action="/operator/logout" style="margin:0"><p class="muted" style="margin:0"><button class="ghost" type="submit">yönetici çıkışı</button></p></form>
<p class="muted"><a href="/">panel</a> · <a href="/local">yerel hesap</a> · <a href="/workspaces">çalışma alanları</a></p>`;
    this.html(res, 200, uiPage({ title: "Yönetici paneli", subtitle: "operator", body, wide: true }));
    void origin;
  }

  /**
   * ht_operator "login" bağlantısı: tek kullanımlık, 15 dakika. Kullanıcı tarayıcıda anahtarı
   * yazınca 30 dakikalık araç oturumu (grant) + panel çerezi açılır.
   */
  private async operatorLoginLinkPage(req: http.IncomingMessage, res: http.ServerResponse, origin: string, id: string) {
    if (!this.opEnabled()) return this.opDisabledPage(req, res);
    const exp = this.opLoginLinks.get(id);
    const valid = typeof exp === "number" && exp > Date.now();
    const notice = (msg: string, kind: "ok" | "err" = "ok") => {
      const body = `${heading(valid ? "Yönetici girişi" : "Bağlantının süresi doldu", valid ? "Bu bağlantı tek kullanımlıktır ve 15 dakika geçerlidir." : "Yeni bir bağlantı üretmek için sohbetten ht_operator {\"action\":\"login\"} çalıştır.")}
<p class="${kind === "err" ? "e" : "ok"}">${esc(msg)}</p>
${valid ? `<div class="card">
<form method="post" action="/operator/link/${esc(id)}" autocomplete="off">
  <label for="opt">Yönetici anahtarı (<code>HARDTOOLS_OPERATOR_TOKEN</code>)</label>
  <input id="opt" name="token" type="password" autocomplete="off" required autofocus>
  <p class="row" style="margin-bottom:0"><button class="primary" type="submit">Giriş yap</button><a class="btn" href="/operator">panele git</a></p>
</form></div>` : ""}
<p class="muted"><a href="/operator">yönetici paneli</a> · <a href="/local">yerel hesap</a></p>`;
      this.html(res, valid ? 200 : 410, uiPage({ title: "Yönetici girişi", subtitle: "operator", body }));
    };

    if (req.method !== "POST") return notice("");
    if (!valid) return notice("Bu bağlantı kullanılamaz.", "err");
    if (!this.sameOriginForm(req, origin)) return notice("Form başka bir siteden gönderildi.", "err");
    const ip = req.socket.remoteAddress ?? "?";
    if (this.opThrottled(ip)) {
      this.o.audit?.({ ev: "operator_login_throttled", ip, via: "tool_link" });
      return notice("Çok fazla hatalı deneme; 10 dakika sonra tekrar dene.", "err");
    }
    const p = await this.body(req);
    const given = Buffer.from((p?.get("token") ?? "").trim());
    const want = Buffer.from(this.opSecret());
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
      this.opFail(ip);
      this.o.audit?.({ ev: "operator_login_failed", ip, via: "tool_link" });
      return notice("Anahtar yanlış.", "err");
    }
    this.opFails.delete(ip);
    this.opLoginLinks.delete(id);          // tek kullanımlık
    this.opGrantOpen(1800);                // araç oturumu: 30 dakika
    this.o.audit?.({ ev: "operator_login", ip, via: "tool_link" });
    this.opSetCookie(res, origin);
    res.writeHead(303, { location: "/operator?tool=1", "cache-control": "no-store" }); res.end();
  }

  /** Tek seferlik gösterim bağlantısı: parola ya da davet kodunun tamamı burada görünür. */
  private operatorRevealLinkPage(req: http.IncomingMessage, res: http.ServerResponse, id: string) {
    const now = Date.now();
    for (const [k, v] of this.opRevealLinks) if (v.exp < now) this.opRevealLinks.delete(k);
    const r = this.opRevealLinks.get(id);
    const body = r
      ? `${heading("Tek seferlik bilgi", "Bu sayfa yalnızca kısa bir süre açıktır; bağlantıyı kimseyle paylaşma.")}
<div class="card"><p class="muted" style="margin-top:0">${esc(r.note)}</p>
<div class="copybox"><input id="rv" type="text" readonly value="${esc(r.text)}"><button type="button" data-copy="#rv">Kopyala</button></div>
<p class="muted" style="margin-bottom:0">Kalan süre: ${Math.max(0, Math.round((r.exp - now) / 1000))} sn · <a href="/operator">yönetici paneli</a></p></div>`
      : `${heading("Bağlantı geçersiz", "Süresi dolmuş ya da daha önce kullanılmış olabilir.")}
<p class="muted">Yeni bir bağlantı için sohbetten ilgili ht_operator çağrısını yeniden çalıştır.</p>
<p class="muted"><a href="/operator">yönetici paneli</a></p>`;
    this.html(res, r ? 200 : 410, uiPage({ title: "Tek seferlik bilgi", subtitle: "operator", body }));
  }

  private async operatorLogin(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "POST" || !this.opEnabled()) return this.operatorPage(req, res);
    if (!this.sameOriginForm(req, origin)) return this.operatorPage(req, res, "Hata: form başka bir siteden gönderildi.", "err");
    const ip = req.socket.remoteAddress ?? "?";
    if (this.opThrottled(ip)) {
      this.o.audit?.({ ev: "operator_login_throttled", ip });
      return this.operatorPage(req, res, "Hata: çok fazla hatalı deneme; 10 dakika sonra tekrar dene.", "err");
    }
    const p = await this.body(req);
    const given = Buffer.from((p?.get("token") ?? "").trim());
    const want = Buffer.from(this.opSecret());
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
      this.opFail(ip);
      this.o.audit?.({ ev: "operator_login_failed", ip });
      return this.operatorPage(req, res, "Hata: anahtar yanlış.", "err");
    }
    this.opFails.delete(ip);
    this.o.audit?.({ ev: "operator_login", ip });
    this.opSetCookie(res, origin);
    res.writeHead(303, { location: "/operator", "cache-control": "no-store" }); res.end();
  }

  /** POST + yetki denetimi ortak ön adımı. */
  private async opGuard(req: http.IncomingMessage, res: http.ServerResponse, origin: string): Promise<URLSearchParams | null | false> {
    if (!this.opAuthed(req)) { this.operatorPage(req, res, "Hata: yönetici oturumu yok.", "err"); return false; }
    if (req.method !== "POST") { this.operatorPage(req, res); return false; }
    if (!this.sameOriginForm(req, origin)) { this.operatorPage(req, res, "Hata: form başka bir siteden gönderildi.", "err"); return false; }
    return await this.body(req);
  }

  private opRedirect(res: http.ServerResponse, path: string) {
    res.writeHead(303, { location: path, "cache-control": "no-store" }); res.end();
  }

  private async operatorInvite(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const p = await this.opGuard(req, res, origin);
    if (p === false) return;
    const la = this.o.local;
    if (!la) return this.operatorPage(req, res, "Hata: bu sunucuda yerel hesaplar kapalı.", "err");
    const mins = Math.min(43200, Math.max(5, Math.round(Number(p?.get("ttl")) || 1440)));
    const code = la.createInvite(mins * 60_000);
    this.o.audit?.({ ev: "operator_invite_created", ttl_min: mins });
    return this.opRedirect(res, `/operator?reveal=${this.opReveal(code, `Tek kullanımlık kayıt kodu (${mins} dakika) — /local → Hesap aç`)}`);
  }

  private async operatorAdd(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const p = await this.opGuard(req, res, origin);
    if (p === false) return;
    const la = this.o.local;
    if (!la) return this.operatorPage(req, res, "Hata: bu sunucuda yerel hesaplar kapalı.", "err");
    const user = (p?.get("user") ?? "").trim().toLowerCase();
    const given = (p?.get("password") ?? "").trim();
    const reserved = this.o.reservedLogin ?? (() => false);
    let last = "";
    for (let i = 0; i < (given ? 1 : 4); i++) {
      const pw = given || randomPassword(20);
      const r = la.create(user, pw, reserved);
      if (r.ok) {
        this.o.audit?.({ ev: "operator_account_created", user });
        return this.opRedirect(res, `/operator?reveal=${this.opReveal(`${user} / ${pw}`, "Yeni hesap: kullanıcı adı / parola")}`);
      }
      last = r.error;
      // Üretilen parola kullanıcı adını içerebilir: politikaya takılırsa yenisini dene.
      if (given) break;
    }
    return this.operatorPage(req, res, `Hata: ${last}`, "err");
  }

  private async operatorPasswd(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const p = await this.opGuard(req, res, origin);
    if (p === false) return;
    const la = this.o.local;
    const user = (p?.get("user") ?? "").trim().toLowerCase();
    if (!la || !la.has(user)) return this.operatorPage(req, res, "Hata: böyle bir hesap yok.", "err");
    const pw = (p?.get("password") ?? "").trim() || randomPassword(20);
    const r = la.adminSetPassword(user, pw);
    if (!r.ok) return this.operatorPage(req, res, `Hata: ${r.error}`, "err");
    this.o.audit?.({ ev: "operator_password_reset", user });
    return this.opRedirect(res, `/operator?reveal=${this.opReveal(`${user} / ${pw}`, "Yeni parola — eski parola ve açık oturumlar geçersiz")}`);
  }

  private async operatorSignup(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const p = await this.opGuard(req, res, origin);
    if (p === false) return;
    const la = this.o.local;
    if (!la) return this.operatorPage(req, res, "Hata: bu sunucuda yerel hesaplar kapalı.", "err");
    const v = String(p?.get("signup") ?? "").trim().toLowerCase();
    if (!["first", "open", "off", "env"].includes(v)) return this.operatorPage(req, res, "Hata: geçersiz kayıt modu.", "err");
    const r = la.setSignup(v === "env" ? null : (v as "first" | "open" | "off"));
    this.o.audit?.({ ev: "operator_signup_mode", mode: r.mode, source: r.source });
    return this.operatorPage(req, res, `Kayıt modu: ${r.mode} (${r.source === "operator" ? "operatör" : "ortam"})`);
  }

  private async operatorUnlock(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const p = await this.opGuard(req, res, origin);
    if (p === false) return;
    const la = this.o.local;
    const user = (p?.get("user") ?? "").trim().toLowerCase();
    if (!la || !la.has(user)) return this.operatorPage(req, res, "Hata: böyle bir hesap yok.", "err");
    la.unlock(user);
    this.o.audit?.({ ev: "operator_unlock", user });
    return this.operatorPage(req, res, `Kilidi açıldı: ${user}`);
  }

  private async operatorDel(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const p = await this.opGuard(req, res, origin);
    if (p === false) return;
    const la = this.o.local;
    const user = (p?.get("user") ?? "").trim().toLowerCase();
    if (!la || !la.has(user)) return this.operatorPage(req, res, "Hata: böyle bir hesap yok.", "err");
    la.remove(user);
    this.o.audit?.({ ev: "operator_account_deleted", user });
    return this.operatorPage(req, res, `${user} silindi. Disk üzerindeki dosyaları silinmedi (çalışma alanı kökü elle silinebilir).`);
  }

  private async operatorLogout(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "POST") return this.operatorPage(req, res);
    if (!this.sameOriginForm(req, origin)) return this.operatorPage(req, res, "Hata: form başka bir siteden gönderildi.", "err");
    // Sunucu tarafında da iptal: çerez kopyalanmışsa çıkış onu da düşürür.
    const parts = this.opCookieParts(req);
    if (parts) {
      this.opRevoked.set(parts.jti, Number(parts.exp));
      if (this.opRevoked.size > 256) this.opRevoked.clear();
    }
    // Panelden çıkış yönetici araç oturumunu da kapatır (aynı operatör kimliği).
    this.opGrantExp = 0;
    this.o.audit?.({ ev: "operator_logout" });
    this.opClearCookie(res);
    return this.opRedirect(res, "/operator");
  }

  private opClearCookie(res: http.ServerResponse) {
    res.setHeader("set-cookie", "ht_op=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
  }

  private async body(req: http.IncomingMessage): Promise<URLSearchParams | null> {
    const chunks: Buffer[] = []; let size = 0;
    for await (const c of req) { size += (c as Buffer).length; if (size > 64 * 1024) return null; chunks.push(c as Buffer); }
    return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
  }

  private loginPage(res: http.ServerResponse, error = "") {
    const gh = Boolean(this.o.github?.clientId);
    const body = `${heading("Ayarlar · giriş", "Ayarlar hesabına bağlıdır: araçlar, ağ ve allowlist senin hesabında saklanır.")}
${error ? `<p class="e">${esc(error)}</p>` : ""}
<div class="card">
<h2 style="margin-top:0">GitHub ile giriş</h2>
${gh ? `<p class="muted">Claude'da bağlanırken kullandığın GitHub hesabıyla gir; ayarların o hesaba bağlanır.</p>
<p><a class="btn" href="/settings/login" data-once>GitHub ile giriş yap</a></p>`
    : `<p class="muted">Bu sunucuda GitHub girişi yapılandırılmamış. Operatör token'ı ile gir.</p>`}
</div>
<div class="card">
<h2 style="margin-top:0">GitHub hesabın yok mu?</h2>
<p class="muted">Yerel hesapla girebilirsin. GitHub girişi bozulduğunda da bu yol çalışır.</p>
<form method="post" action="/local/login" autocomplete="on">
  <label for="lu">Kullanıcı adı</label>
  <input id="lu" name="user" type="text" autocomplete="username" required>
  <label for="lp">Parola</label>
  <input id="lp" name="password" type="password" autocomplete="current-password" required>
  <p class="row"><button class="primary" type="submit">Yerel hesapla gir</button><a class="btn" href="/local">Hesap aç</a></p>
</form>
</div>
<div class="card">
<h2 style="margin-top:0">Operatör girişi</h2>
<form method="post" action="/settings/token" autocomplete="off">
  <label for="t">Erişim token'ı (<code>HARDTOOLS_HTTP_TOKEN</code> — <code>Bearer</code> öneki olmadan)</label>
  <input id="t" name="token" type="password" autocomplete="off" required>
  <p><button class="primary" type="submit">Giriş</button></p>
</form>
</div>`;
    this.html(res, 200, uiPage({ title: "Ayarlar · giriş", subtitle: "settings", body }));
  }

  private index(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "GET") return this.html(res, 405, uiPage({ title: "Ayarlar", body: `<p class="e">Yalnız GET.</p>` }));
    const user = this.cookieUser(req);
    if (!user) return this.loginPage(res);
    const s = this.o.store.get(user);
    const toolRows = ALL_TOOLS.map(name => {
      const enabled = !s.disabledTools.includes(name);
      return `<label class="chip"><input type="checkbox" name="tool" value="${esc(name)}"${enabled ? " checked" : ""}> <code>${esc(name)}</code></label>`;
    }).join("");
    const cmdRows = s.allowedCommands.map((c, i) => `<li><code>${esc(c)}</code><form method="post" action="/settings/save" style="margin:0"><input type="hidden" name="removeCommand" value="${esc(c)}"><button class="ghost" type="submit" data-once>Kaldır</button></form></li>`).join("");
    const urlRows = s.allowedUrls.map(u => `<li><code>${esc(u)}</code><form method="post" action="/settings/save" style="margin:0"><input type="hidden" name="removeUrl" value="${esc(u)}"><button class="ghost" type="submit" data-once>Kaldır</button></form></li>`).join("");

    const body = `${heading("Ayarlar", `Kullanıcı: ${user}`)}
<p class="muted"><a href="/">panel</a> · <a href="/workspaces">çalışma alanları</a></p>
<form method="post" action="/settings/save" autocomplete="off">

<div class="card">
<h2 style="margin-top:0">Araçlar</h2>
<p class="muted">Kapattığın araçlar MCP listesinde görünmez ve çağrılamaz. <code>ht_list_all_tools</code> ve <code>ht_manage_tool</code> her zaman açıktır.</p>
<div class="grid">${toolRows}</div>
</div>

<div class="card">
<h2 style="margin-top:0">Ağ istekleri</h2>
<label class="chip"><input type="checkbox" name="networkEnabled" value="1"${s.networkEnabled ? " checked" : ""}> <span>İnternet istekleri açık (<code>ht_fetch</code>, <code>ht_image_search</code>)</span></label>
<label class="chip" style="margin-top:.5rem"><input type="checkbox" name="allowlistEnabled" value="1"${s.allowlistEnabled ? " checked" : ""}> <span>Allowlist zorunlu olsun (aşağıdakiler dışına çıkma)</span></label>
<p class="muted" style="margin-top:.6rem">Allowlist açıkken yalnızca listelenen alan adlarına ve yalnızca listelenen komutlara izin verilir.</p>
</div>

<p class="row"><button class="primary" type="submit">Kaydet</button><span class="muted">Son güncelleme: ${s.updatedAt ? esc(new Date(s.updatedAt).toISOString().replace("T", " ").slice(0, 19)) : "—"}</span></p>
</form>

<div class="card">
<h2 style="margin-top:0">İzinli komutlar</h2>
<p class="muted">Liste yalnızca "Allowlist zorunlu olsun" açıkken uygulanır. Joker desteklenir: <code>*</code> (hepsi), <code>git*</code> (git ile başlayanlar), <code>py?hon</code>.</p>
<ul class="clean">${cmdRows || `<li class="muted">Henüz kayıt yok.</li>`}</ul>
<form method="post" action="/settings/save" autocomplete="off" style="margin:0">
  <input type="hidden" name="form" value="list">
  <label for="newCommand">Komut ekle</label>
  <input id="newCommand" name="addCommand" type="text" placeholder="ör. git, node, git*, *">
  <p class="row" style="margin-top:.6rem"><button class="primary" type="submit" data-once>Komut ekle</button></p>
</form>
</div>

<div class="card">
<h2 style="margin-top:0">Araç bütçeleri</h2>
<p class="muted">Bu değerler yalnızca profilin izin verdiği sınırı <strong>aşağı çeker</strong>; politika hiçbir zaman gevşetilmez.</p>
<label for="shareTtlMinutes">Paylaşım bağlantısı süresi (dakika; 0 = araç varsayılanı)</label>
<input id="shareTtlMinutes" name="shareTtlMinutes" type="number" min="0" max="60" step="1" value="${s.shareTtlMinutes || 0}">
<label for="shellMaxOutputBytes">Kabuk çıktı bütçesi (bayt; 0 = profil varsayılanı)</label>
<input id="shellMaxOutputBytes" name="shellMaxOutputBytes" type="number" min="0" max="1048576" step="1024" value="${s.shellMaxOutputBytes || 0}">
<label for="scheduleMaxS">Zamanlanmış çağrı için en uzun gecikme (saniye, 0–3600)</label>
<input id="scheduleMaxS" name="scheduleMaxS" type="number" min="0" max="3600" step="60" value="${s.scheduleMaxS ?? 3600}">
</div>

<div class="card">
<h2 style="margin-top:0">İzinli URL / alan adları</h2>
<p class="muted">Ağ allowlist'i yalnızca "Allowlist zorunlu olsun" açıkken uygulanır; liste boşsa kısıt uygulanmaz. Joker desteklenir: <code>*</code>, <code>*.github.com</code>, <code>api*.example.com</code>.</p>
<ul class="clean">${urlRows || `<li class="muted">Henüz kayıt yok.</li>`}</ul>
<form method="post" action="/settings/save" autocomplete="off" style="margin:0">
  <input type="hidden" name="form" value="list">
  <label for="newUrl">URL veya alan adı ekle</label>
  <input id="newUrl" name="addUrl" type="text" placeholder="ör. api.github.com, *.github.com, *">
  <p class="row" style="margin-top:.6rem"><button class="primary" type="submit" data-once>URL ekle</button></p>
</form>
</div>

<div class="card">
<h2 style="margin-top:0">Çıkış</h2>
<p class="muted">Çıkış yapınca bu hesabın MCP erişim anahtarları sunucuda iptal edilir: bağlantı hemen düşer. Ardından Claude'da <strong>Ayarlar → Bağlayıcılar → hardtools → Kaldır</strong> ile listeden sil.</p>
<form method="post" action="/settings/logout" autocomplete="off">
  <button class="primary" type="submit" data-once>Çıkış yap ve bağlantıyı kes</button>
</form>
</div>
<p class="muted"><a href="${esc(origin)}/connect">bağlanma sayfası</a></p>`;
    this.html(res, 200, uiPage({ title: "Ayarlar", subtitle: "settings", body, actions: `<form method="post" action="/settings/logout" style="margin:0"><button class="ghost" type="submit" data-once>Çıkış</button></form>` }));
  }

  private async save(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "POST") return this.html(res, 405, uiPage({ title: "Ayarlar", body: `<p class="e">Yalnız POST.</p>` }));
    const user = this.cookieUser(req);
    if (!user) return this.loginPage(res, "Oturum sona erdi, tekrar giriş yap.");
    const p = await this.body(req);
    if (!p) return this.html(res, 413, uiPage({ title: "Ayarlar", body: `<p class="e">İstek çok büyük.</p>` }));
    const cur = this.o.store.get(user);

    const removeCommand = p.get("removeCommand"), removeUrl = p.get("removeUrl");
    if (removeCommand) { this.o.store.patch(user, { allowedCommands: cur.allowedCommands.filter(c => c !== removeCommand) }, user); return this.redirect(res, origin); }
    if (removeUrl) { this.o.store.patch(user, { allowedUrls: cur.allowedUrls.filter(u => u !== removeUrl) }, user); return this.redirect(res, origin); }

    // Yalnız liste formu (komut/URL ekle): araç ve ağ ayarlarına DOKUNMA. Aksi hâlde form
    // onay kutularını taşımadığı için "komut ekle" bütün araçları kapatıyordu.
    if (p.get("form") === "list") {
      const addCmd = p.get("addCommand"), addUrl = p.get("addUrl");
      const allowedCommands = addCmd ? uniq([...cur.allowedCommands, addCmd]) : cur.allowedCommands;
      const allowedUrls = addUrl ? uniq([...cur.allowedUrls, addUrl]) : cur.allowedUrls;
      this.o.store.patch(user, { allowedCommands, allowedUrls }, user);
      this.o.audit?.({ ev: "settings_save", user, list: true });
      return this.redirect(res, origin);
    }

    const tools = p.getAll("tool");
    const disabledTools = ALL_TOOLS.filter(n => !tools.includes(n));
    const addCommand = p.get("addCommand"), addUrl = p.get("addUrl");
    const allowedCommands = addCommand ? uniq([...cur.allowedCommands, addCommand]) : cur.allowedCommands;
    const allowedUrls = addUrl ? uniq([...cur.allowedUrls, addUrl]) : cur.allowedUrls;
    const networkEnabled = p.get("networkEnabled") === "1", allowlistEnabled = p.get("allowlistEnabled") === "1";
    const shareTtlMinutes = clampInt(p.get("shareTtlMinutes") ?? 0, 0, 60);
    const shellMaxOutputBytes = clampInt(p.get("shellMaxOutputBytes") ?? 0, 0, 1 << 20);
    const scheduleMaxS = clampInt(p.get("scheduleMaxS") ?? 3600, 0, 3600);
    this.o.store.patch(user, { disabledTools, networkEnabled, allowlistEnabled, allowedCommands, allowedUrls, shareTtlMinutes, shellMaxOutputBytes, scheduleMaxS }, user);
    this.o.audit?.({ ev: "settings_save", user, tools: ALL_TOOLS.length - disabledTools.length, network: networkEnabled, allowlist: allowlistEnabled });
    return this.redirect(res, origin);
  }

  private redirect(res: http.ServerResponse, origin: string) {
    res.writeHead(303, { location: `${origin}/settings`, "cache-control": "no-store" });
    res.end();
  }

  private async logout(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    // Bağlantıyla gelindiğinde 405 göstermek çıkmaz sokaktı: onay düğmesi olan bir sayfa dön.
    if (req.method !== "POST") return this.html(res, 200, uiPage({ title: "Çıkış", subtitle: "settings", body: `${heading("Çıkış yap")}
<div class="card"><p class="muted">Bu tarayıcıdaki oturum kapatılacak. Oturumu kapatmak için düğmeye bas.</p>
<form method="post" action="/settings/logout"><p><button class="primary" type="submit">Çıkış yap</button></p></form>
<p class="muted" style="margin-bottom:0"><a href="${esc(origin)}/">panel</a></p></div>` }));
    const user = this.cookieUser(req);
    let revoked = 0;
    if (user) { revoked = this.o.store.revokeUser(user); this.o.store.signOut(user); }
    this.o.audit?.({ ev: "settings_logout", user: user ?? "-", revoked });
    res.setHeader("set-cookie", "ht_s=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    const body = `${heading("Çıkış yapıldı")}
<div class="card">
<p>${revoked} MCP oturumu sunucuda iptal edildi; bağlantı düştü.</p>
<p><strong>Son adım (Claude tarafı):</strong> Claude → <strong>Ayarlar → Bağlayıcılar</strong> → <code>hardtools</code> → <strong>Kaldır</strong>. Sunucu, Claude'un listesindeki kaydı silemez; kaldırma işlemi istemcide yapılır.</p>
<p><a class="btn" href="${esc(origin)}/settings">Tekrar giriş</a></p>
</div>`;
    this.html(res, 200, uiPage({ title: "Çıkış", subtitle: "settings", body }));
  }

  private async tokenLogin(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "POST") return this.loginPage(res);
    const p = await this.body(req);
    const given = String(p?.get("token") ?? "").trim();
    const want = this.o.operatorToken ?? "";
    if (!want || given.length !== want.length || !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(want)))
      return this.loginPage(res, "Token yanlış.");
    const user = "operator";
    this.setCookie(res, this.o.store.cookieFor(user, 12 * 3600, "t"), origin.startsWith("https://"), 12 * 3600);
    this.o.audit?.({ ev: "settings_login", user, via: "token" });
    return this.redirect(res, origin);
  }

  // ---- GitHub device flow (ayarlar için) ----------------------------------------------------
  private gh() { return (this.o.github?.webBase ?? "https://github.com").replace(/\/+$/, ""); }
  private ghApi() { return (this.o.github?.apiBase ?? "https://api.github.com").replace(/\/+$/, ""); }

  private async startLogin(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const gh = this.o.github;
    if (!gh?.clientId) return this.loginPage(res, "GitHub girişi yapılandırılmamış.");
    const dc = await this.ghJson(`${this.gh()}/login/device/code`, {
      method: "POST", headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: gh.clientId, scope: "read:user user:email" }).toString(),
    });
    if (!dc || typeof dc.device_code !== "string") return this.loginPage(res, "GitHub'dan kod alınamadı, tekrar dene.");
    const t = crypto.randomBytes(18).toString("base64url");
    this.pending.set(t, {
      deviceCode: dc.device_code, userCode: String(dc.user_code),
      verifyUri: typeof dc.verification_uri === "string" ? dc.verification_uri : `${this.gh()}/login/device`,
      intervalS: Math.max(5, Math.min(30, Number(dc.interval) || 5)),
      exp: Date.now() + 600_000, nextPoll: 0,
    });
    for (const [k, v] of this.pending) if (v.exp < Date.now() || this.pending.size > 32) this.pending.delete(k);
    const next = `/settings/poll?t=${encodeURIComponent(t)}`;
    const body = `${heading("GitHub ile giriş")}
<div class="card">
<p><strong>1.</strong> <a href="${esc(this.pending.get(t)!.verifyUri)}" target="_blank" rel="noreferrer">${esc(this.pending.get(t)!.verifyUri)}</a> adresini aç.</p>
<p><strong>2.</strong> Kodu gir: <code class="code">${esc(this.pending.get(t)!.userCode)}</code></p>
<p><strong>3.</strong> Bu sayfa kendiliğinden devam eder.</p>
</div>
<meta http-equiv="refresh" content="5;url=${esc(next)}">`;
    this.html(res, 200, uiPage({ title: "Ayarlar · GitHub", subtitle: "settings", body }));
  }

  private async poll(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    const t = new URL(req.url ?? "/", origin).searchParams.get("t") ?? "";
    const p = this.pending.get(t);
    if (!p) return this.loginPage(res, "Giriş oturumu bulunamadı, tekrar dene.");
    if (p.exp < Date.now()) { this.pending.delete(t); return this.loginPage(res, "Kodun süresi doldu, tekrar dene."); }
    if (Date.now() < 0) return this.loginPage(res);
    if (Date.now() < p.nextPoll) return this.html(res, 200, uiPage({ title: "Bekleniyor", body: `<p class="muted">GitHub onayı bekleniyor…</p><meta http-equiv="refresh" content="5;url=/settings/poll?t=${encodeURIComponent(t)}">` }));
    p.nextPoll = Date.now() + p.intervalS * 1000;

    const tok = await this.ghJson(`${this.gh()}/login/oauth/access_token`, {
      method: "POST", headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: this.o.github!.clientId, device_code: p.deviceCode, grant_type: "urn:ietf:params:oauth:grant-type:device_code" }).toString(),
    });
    const err = typeof tok?.error === "string" ? tok.error : "";
    if (err === "authorization_pending" || err === "slow_down") {
      if (err === "slow_down") p.intervalS = Math.min(30, p.intervalS + 5);
      return this.html(res, 200, uiPage({ title: "Bekleniyor", body: `<p class="muted">GitHub onayı bekleniyor…</p><meta http-equiv="refresh" content="5;url=/settings/poll?t=${encodeURIComponent(t)}">` }));
    }
    if (!tok || typeof tok.access_token !== "string") { this.pending.delete(t); return this.loginPage(res, "GitHub girişi reddedildi ya da süresi doldu."); }

    const headers = { authorization: `Bearer ${tok.access_token}`, accept: "application/vnd.github+json", "user-agent": "hardtools-settings" };
    const who = await this.ghJson(`${this.ghApi()}/user`, { headers });
    const login = String(who?.login ?? "").toLowerCase();
    if (!login) { this.pending.delete(t); return this.loginPage(res, "GitHub kimliği okunamadı."); }
    const allowed = this.o.github?.allowAny
      ? true
      : (this.o.github?.allowedLogins ?? []).map(v => v.toLowerCase()).includes(login);
    if (!allowed) { this.pending.delete(t); return this.loginPage(res, `Bu GitHub hesabına izin verilmiyor (${login}).`); }

    this.pending.delete(t);
    this.setCookie(res, this.o.store.cookieFor(login), origin.startsWith("https://"), 12 * 3600);
    this.o.audit?.({ ev: "settings_login", user: login, via: "github" });
    return this.redirect(res, origin);
  }

  private async ghJson(url: string, init: RequestInit): Promise<any | null> {
    try { const r = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) }); return await r.json(); } catch { return null; }
  }
}
