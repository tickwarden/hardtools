// Kullanıcı bazlı ayarlar: araç aç/kapat, ağ aç/kapat, komut ve URL allowlist'i.
// Kimlik = GitHub login (OAuth), "operator" (statik bearer) veya "public" (anonim bağlantı).
// OAuth grant'ları logine bağlanır; böylece sohbet değişse de ayarlar aynı kullanıcıda kalır.

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { page as uiPage, esc, heading, PAGE_CSP } from "./ui.js";
import type { LocalAccounts } from "./localauth.js";

export const ALL_TOOLS = [
  "ht_read", "ht_write", "ht_edit", "ht_glob", "ht_search", "ht_mkdir", "ht_move", "ht_trash",
  "ht_empty_trash", "ht_shell", "ht_fetch", "ht_image_search", "ht_share", "ht_transfer_file",
  "ht_status", "ht_stop", "ht_new_shell_env", "ht_add_var", "ht_list_vars", "ht_delete_var",
  "ht_user_input", "ht_ask", "ht_undo", "ht_schedule", "ht_memory", "ht_workspace", "ht_list_all_tools", "ht_manage_tool",
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

const MAX_LIST = 200;
const norm = (v: string) => v.trim().slice(0, 512);
const uniq = (a: string[]) => [...new Set(a.map(norm).filter(Boolean))].slice(0, MAX_LIST);

export class UserSettingsStore {
  private users = new Map<string, UserSettings>();
  private grants = new Map<string, string>();  // grant id -> login
  private revoked = new Set<string>();          // çıkış yapılan grant'lar
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
        const d = JSON.parse(fs.readFileSync(this.store, "utf8")) as { users?: Record<string, UserSettings>; grants?: Record<string, string>; revoked?: string[] };
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
      fs.writeFileSync(tmp, JSON.stringify({ v: 1, users: items, grants, revoked: [...this.revoked] }), { mode: 0o600 });
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

  cookieFor(user: string, ttlS = 12 * 3600): string {
    const exp = Math.floor(Date.now() / 1000) + ttlS;
    const body = `${Buffer.from(user).toString("base64url")}.${exp}`;
    const sig = crypto.createHmac("sha256", this.signingKey()).update(body).digest("base64url");
    return `${body}.${sig}`;
  }

  /** Bu ad bir kullanıcı kaydı olarak biliniyor mu? (Yerel hesapla çakışmayı engellemek için.) */
  hasUser(name: string): boolean {
    return this.users.has(name) || this.grants.has(name);
  }

  userFromCookie(value: string | undefined): string | null {
    if (!value) return null;
    const parts = value.split(".");
    if (parts.length !== 3) return null;
    const [b64, exp, sig] = parts;
    const body = `${b64}.${exp}`;
    const want = crypto.createHmac("sha256", this.signingKey()).update(body).digest("base64url");
    if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
    if (Number(exp) * 1000 < Date.now()) return null;
    try { return Buffer.from(b64, "base64url").toString("utf8") || null; } catch { return null; }
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
    return this.o.store.userFromCookie(m?.[1]);
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
    if (pathname === "/local") return this.localPage(req, res, ""), true;
    if (pathname === "/local/login") return await this.localLogin(req, res, origin), true;
    if (pathname === "/local/register") return await this.localRegister(req, res, origin), true;
    if (pathname === "/local/connector") return await this.localConnector(req, res, origin), true;
    return false;
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
<p class="muted">Bu adresi Claude'da “Connector ekle” alanına yapıştır. Başkası da kopyalayıp kendi hesabıyla ekleyebilir;${localConnector ? " bu adres yalnızca senin yerel hesabına bağlıdır." : " giriş kendi hesabıyla yapılır."}</p>
<div class="copybox"><input id="mcp" type="text" readonly value="${esc(mcpUrl)}"><button type="button" data-copy="#mcp">Kopyala</button></div>
<p class="muted" style="margin-bottom:0">${localConnector ? 'Anahtar sızdıysa <a href="/local">yerel hesap sayfasından</a> yenileyebilirsin.' : `Sunucu: <code>${esc(origin)}</code>`}</p>
</div>
<h2>Sayfalar</h2>
<div class="tiles">${tiles}</div>
${user ? `<p class="muted"><a href="/settings/logout">çıkış yap</a></p>` : `<p class="muted"><a href="/settings">giriş yap</a> · <a href="/local">yerel hesap</a></p>`}`;
    this.html(res, 200, uiPage({ title: "Panel", subtitle: "panel", body }));
  }

  /** /local — yerel hesap girişi ve (izinliyse) kayıt. */
  private localPage(req: http.IncomingMessage, res: http.ServerResponse, notice = "") {
    const la = this.o.local;
    const canReg = Boolean(la?.canRegister());
    const body = `${heading("Yerel hesap", "GitHub hesabın yoksa ya da GitHub girişi çalışmıyorsa buradan gir.")}
${notice ? `<p class="${notice.startsWith("Hata") ? "e" : "ok"}">${esc(notice)}</p>` : ""}
<div class="card">
<h2 style="margin-top:0">Giriş</h2>
<form method="post" action="/local/login" autocomplete="on">
  <label for="lu">Kullanıcı adı</label>
  <input id="lu" name="user" type="text" autocomplete="username" required>
  <label for="lp">Parola</label>
  <input id="lp" name="password" type="password" autocomplete="current-password" required>
  <p><button class="primary" type="submit">Giriş yap</button></p>
</form>
</div>
${canReg ? `<div class="card">
<h2 style="margin-top:0">Hesap aç</h2>
<p class="muted">${la?.count() === 0 ? "Bu sunucuda henüz yerel hesap yok: ilk hesabı sen açacaksın." : "Yeni yerel hesap aç."} Parola en az 10 karakter, iki tür karakter içermeli.</p>
<form method="post" action="/local/register" autocomplete="off">
  <label for="ru">Kullanıcı adı (3-32 karakter)</label>
  <input id="ru" name="user" type="text" autocomplete="username" required>
  <label for="rp">Parola</label>
  <input id="rp" name="password" type="password" autocomplete="new-password" required>
  <p><button type="submit">Hesap aç</button></p>
</form>
</div>` : `<p class="muted">Yeni hesap açma kapalı. Operatör yeni bir yerel hesap açabilir.</p>`}
<p class="muted"><a href="/">panel</a> · <a href="/settings/login">GitHub ile giriş</a></p>`;
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
    if (!this.sameOriginForm(req, origin)) return this.localPage(req, res, "Hata: form başka bir siteden gönderildi.");
    const la = this.o.local;
    if (!la) return this.localPage(req, res, "Hata: bu sunucuda yerel hesaplar kapalı.");
    const p = await this.body(req);
    const user = (p?.get("user") ?? "").trim().toLowerCase();
    const pw = p?.get("password") ?? "";
    const r = la.verify(user, pw);
    if (!r.ok) {
      this.o.audit?.({ ev: "local_login_failed", user });
      return this.localPage(req, res, `Hata: ${r.error}`);
    }
    this.o.audit?.({ ev: "local_login", user });
    this.setCookie(res, this.o.store.cookieFor(user), origin.startsWith("https://"), 12 * 3600);
    res.writeHead(303, { location: "/", "cache-control": "no-store" }); res.end();
  }

  private async localRegister(req: http.IncomingMessage, res: http.ServerResponse, origin: string) {
    if (req.method !== "POST") return this.localPage(req, res);
    if (!this.sameOriginForm(req, origin)) return this.localPage(req, res, "Hata: form başka bir siteden gönderildi.");
    const la = this.o.local;
    if (!la || !la.canRegister()) return this.localPage(req, res, "Hata: yeni yerel hesap açma kapalı.");
    const p = await this.body(req);
    const user = (p?.get("user") ?? "").trim().toLowerCase();
    const r = la.create(user, p?.get("password") ?? "", (n) => Boolean(this.o.reservedLogin?.(n)));
    if (!r.ok) return this.localPage(req, res, `Hata: ${r.error}`);
    this.o.audit?.({ ev: "local_account_created", user: r.account.user });
    this.setCookie(res, this.o.store.cookieFor(r.account.user), origin.startsWith("https://"), 12 * 3600);
    res.writeHead(303, { location: "/", "cache-control": "no-store" }); res.end();
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
      const p = await this.body(req);
      const dir = p?.get("adopt");
      if (!dir) notice = "Devralınacak dizin seçilmedi.";
      else { try { notice = ws.adopt(user, dir); } catch (e) { notice = `Hata: ${(e as Error).message}`; } }
    }
    const rows = ws.list(user);
    const kb = (n: number) => n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : n < 1 << 30 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
    const body = `${heading("Çalışma alanları", "Hesabın kökleri ve eski sohbetlerin bıraktığı işler. Devral, seçilen dizinin dosyalarını hesap köküne taşır; var olanın üzerine yazmaz. Kabuk iskeleti (.hardtools) ve geri dönüşüm kutusu taşınmaz.")}
${notice ? `<p class="ok">${esc(notice)}</p>` : ""}
<div class="card"><div class="tablewrap"><table>
<thead><tr><th>Dizin</th><th>Tür</th><th>Dosya</th><th>Boyut</th><th>Son kullanım</th><th></th></tr></thead>
<tbody>${rows.map(r => `<tr${r.current ? ' style="font-weight:600"' : ""}>
<td><code>${esc(r.rel)}</code>${r.current ? ' <span class="pill">bu hesap</span>' : ""}${esc(r.rel) === path.basename(cur()) ? ' <span class="pill on">etkin</span>' : ""}</td>
<td>${r.kind === "account" ? "hesap" : "sohbet"}${r.user ? ` · ${esc(r.user)}` : ""}</td>
<td>${r.files}${r.scratchFiles ? ` <span class="muted">(+${r.scratchFiles} iskelet)</span>` : ""}</td><td>${kb(r.bytes)}${r.scratchBytes ? ` <span class="muted">+ ${kb(r.scratchBytes)} iskelet</span>` : ""}</td><td>${new Date(r.lastUsed).toISOString().replace("T", " ").slice(0, 16)}</td>
<td>${r.current ? "" : `<form method="post" action="/workspaces" style="margin:0"><input type="hidden" name="adopt" value="${esc(r.rel)}"><button type="submit" data-once>Devral</button></form>`}</td>
</tr>`).join("") || `<tr><td colspan="6" class="muted">Kayıt yok.</td></tr>`}</tbody></table></div></div>
<p class="muted">Aynı listeyi modelden de isteyebilirsin: <code>ht_workspace {"action":"list"}</code> · devam: <code>ht_workspace {"action":"adopt","dir":"u-…"}</code></p>
<p class="muted"><a href="/">panel</a> · <a href="/settings">ayarlar</a></p>`;
    this.html(res, 200, uiPage({ title: "Çalışma alanları", subtitle: "workspaces", body, wide: true }));
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
    if (req.method !== "POST") return this.html(res, 405, uiPage({ title: "Ayarlar", body: `<p class="e">Yalnız POST.</p>` }));
    const user = this.cookieUser(req);
    let revoked = 0;
    if (user) revoked = this.o.store.revokeUser(user);
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
    this.setCookie(res, this.o.store.cookieFor(user), origin.startsWith("https://"), 12 * 3600);
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
