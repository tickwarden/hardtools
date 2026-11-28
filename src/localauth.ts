// Yerel hesaplar: GitHub olmadan giriş. İki durum için var:
//   1) GitHub hesabı olmayan kullanıcılar paneli kullanabilsin.
//   2) GitHub girişi bozulduğunda / erişilemediğinde operatör ve kullanıcılar kilitli kalmasın.
// Parolalar scrypt ile (kullanıcı başına rastgele tuz) saklanır; düz metin hiçbir yere yazılmaz.
// Kimlik: owner kimliği `local:<ad>`, kullanıcı adı `<ad>` — GitHub login'leriyle çakışırsa reddedilir.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/** Tek kullanımlık kayıt daveti (yalnız özet saklanır). */
interface Invite { hash: string; exp: number }

export interface LocalAccount {
  user: string;
  salt: string;
  hash: string;
  createdAt: number;
  lastLogin: number;
  /** MCP bağlantı anahtarı (yüksek entropili, yalnızca sahibine gösterilir). */
  connector: string;
  /** Parolanın son değişme zamanı: bundan önce verilmiş oturum çerezleri geçersizdir. */
  pvAt?: number;
}

const USER_RE = /^[a-z0-9][a-z0-9_.-]{2,31}$/;
const MIN_PASSWORD = 10;
const MAX_ACCOUNTS = 200;
/** Bu sayıya ulaşan hatalı deneme hesabı geçici olarak kilitler. */
const MAX_FAILS = 8;
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;

const normUser = (v: unknown) => String(v ?? "").trim().toLowerCase();
/** Davet kodu: büyük harf, yalnızca harf/rakam (tire ve boşluk yok sayılır). */
const normCode = (v: unknown) => String(v ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");

/** Parola politikası: en az 10 karakter, kullanıcı adını içermemeli, tek karakter türü olmamalı. */
export function passwordProblem(user: string, password: string): string | null {
  const pw = String(password ?? "");
  if (pw.length < MIN_PASSWORD) return `Parola en az ${MIN_PASSWORD} karakter olmalı.`;
  if (pw.length > 200) return "Parola çok uzun.";
  if (pw.toLowerCase().includes(user.toLowerCase())) return "Parola kullanıcı adını içermemeli.";
  const kinds = [/[a-zçğıöşü]/, /[A-ZÇĞİÖŞÜ]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  if (kinds < 2) return "Parola en az iki tür karakter içermeli (harf, rakam, işaret).";
  return null;
}

export class LocalAccounts {
  private items = new Map<string, LocalAccount>();
  private invites: Invite[] = [];
  private fails = new Map<string, { n: number; until: number }>();
  private file?: string;
  /** Dosyanın son görülen hâli: operatör CLI'ı dosyayı değiştirdiğinde sunucu kendini tazeler. */
  private stamp = "";

  /**
   * @param opts.store  Hesap dosyası (durum dizininde, 0600). Yoksa hesaplar yalnızca bellekte tutulur.
   * @param opts.signup "first" (varsayılan: yalnızca hiç hesap yokken kayıt), "open", "off".
   */
  constructor(private opts: { store?: string; signup?: string } = {}) {
    this.file = opts.store;
    this.load();
  }

  /**
   * Hesap dosyası dışarıdan (operatör CLI'ı) değiştiyse yeniden yükle.
   * Sunucu bellekteki kopyayı kullanıyor; CLI ile açılan hesap/davet kodu yeniden
   * başlatma beklemeden geçerli olmalı (canlıda tam bu yüzden "kod geçersiz" oluyordu).
   */
  private refresh(): void {
    if (!this.file) return;
    try {
      const st = fs.statSync(this.file);
      const sig = `${st.mtimeMs}:${st.size}`;
      if (sig !== this.stamp) this.load();
    } catch { /* dosya yok: bellek hâli geçerli */ }
  }

  private get signupMode(): "first" | "open" | "off" {
    const v = (this.opts.signup ?? "first").trim().toLowerCase();
    return v === "open" || v === "off" ? v : "first";
  }

  /** Kayıt sayfası gösterilsin mi? ("first" modunda yalnızca ilk hesap için.) */
  canRegister(): boolean {
    this.refresh();
    const mode = this.signupMode;
    if (mode === "off") return false;
    if (mode === "open") return this.items.size < MAX_ACCOUNTS;
    return this.items.size === 0;
  }

  count(): number { this.refresh(); return this.items.size; }

  list(): string[] { this.refresh(); return [...this.items.keys()].sort(); }

  get(user: string): LocalAccount | undefined { this.refresh(); return this.items.get(normUser(user)); }

  /** Bu kullanıcı adı yerel bir hesap mı? (GitHub login'leriyle çakışma denetimi için.) */
  has(user: string): boolean { this.refresh(); return this.items.has(normUser(user)); }

  /** Bağlantı anahtarından kullanıcı adı (MCP /lc/<anahtar> yolu). */
  userForConnector(token: string): string | null {
    this.refresh();
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(token)) return null;
    for (const a of this.items.values()) {
      if (a.connector.length === token.length && crypto.timingSafeEqual(Buffer.from(a.connector), Buffer.from(token))) return a.user;
    }
    return null;
  }

  connectorFor(user: string): string | null { this.refresh(); return this.items.get(normUser(user))?.connector ?? null; }

  /**
   * Hesap oluşturur. `reserved` içindeki adlar (bilinen GitHub login'leri) reddedilir:
   * aynı ad iki kimlik türünde birleşirse ayarlar/çalışma alanı karışırdı.
   */
  create(user: string, password: string, reserved: (name: string) => boolean = () => false): { ok: true; account: LocalAccount } | { ok: false; error: string } {
    this.refresh();
    const u = normUser(user);
    if (!USER_RE.test(u)) return { ok: false, error: "Kullanıcı adı 3-32 karakter olmalı; küçük harf, rakam, nokta, tire, alt çizgi." };
    if (this.items.has(u)) return { ok: false, error: "Bu kullanıcı adı zaten var." };
    if (reserved(u)) return { ok: false, error: "Bu ad GitHub hesabına ait; başka bir ad seç." };
    const pwProblem = passwordProblem(u, password);
    if (pwProblem) return { ok: false, error: pwProblem };
    if (this.items.size >= MAX_ACCOUNTS) return { ok: false, error: "Hesap sınırına ulaşıldı." };
    const salt = crypto.randomBytes(16).toString("base64url");
    const hash = crypto.scryptSync(String(password), salt, 64, SCRYPT).toString("base64url");
    const account: LocalAccount = {
      user: u, salt, hash, createdAt: Date.now(), lastLogin: 0,
      connector: crypto.randomBytes(32).toString("base64url"),
    };
    this.items.set(u, account);
    this.save();
    return { ok: true, account };
  }

  /** Parola doğrulama; hatalı denemeler kullanıcı başına 10 dakika kilitler. */
  verify(user: string, password: string): { ok: boolean; error?: string } {
    this.refresh();
    const u = normUser(user);
    const now = Date.now();
    const f = this.fails.get(u);
    // Yalnızca eşiğe ulaşan denemeler kilitler: tek yazım hatası doğru parolayı bloklamamalı
    // (yerel hesap, GitHub bozulduğunda acil giriş yolu; kilit burada işe yaramaz hâle gelmemeli).
    if (f && f.n >= MAX_FAILS && f.until > now) return { ok: false, error: "Çok fazla hatalı deneme; birkaç dakika sonra tekrar dene." };
    const a = this.items.get(u);
    if (!a) return { ok: false, error: "Kullanıcı adı veya parola yanlış." };
    const want = Buffer.from(a.hash, "base64url");
    const got = crypto.scryptSync(String(password ?? ""), a.salt, 64, SCRYPT);
    const ok = want.length === got.length && crypto.timingSafeEqual(want, got);
    if (!ok) {
      const n = (f && f.until > now ? f.n : 0) + 1;
      this.fails.set(u, { n, until: n >= MAX_FAILS ? now + 10 * 60_000 : now + 60_000 });
      return { ok: false, error: "Kullanıcı adı veya parola yanlış." };
    }
    this.fails.delete(u);
    a.lastLogin = now;
    this.save();
    return { ok: true };
  }

  /** Parola değiştirme (mevcut parola doğrulanarak). */
  changePassword(user: string, current: string, next: string): { ok: boolean; error?: string } {
    const u = normUser(user);
    const v = this.verify(u, current);
    if (!v.ok) return v;
    const problem = passwordProblem(u, next);
    if (problem) return { ok: false, error: problem };
    const a = this.items.get(u)!;
    a.salt = crypto.randomBytes(16).toString("base64url");
    a.hash = crypto.scryptSync(String(next), a.salt, 64, SCRYPT).toString("base64url");
    a.pvAt = Date.now();
    this.save();
    return { ok: true };
  }

  /** Bağlantı anahtarını yeniler (sızdıysa eski URL çalışmaz). */
  rotateConnector(user: string): string | null {
    this.refresh();
    const a = this.items.get(normUser(user));
    if (!a) return null;
    a.connector = crypto.randomBytes(32).toString("base64url");
    this.save();
    return a.connector;
  }

  /** Tek kullanımlık kayıt kodu üretir; kodu yalnızca bir kez döndürür (dosyada özeti durur). */
  createInvite(ttlMs = 24 * 3600_000): string {
    const code = Array.from({ length: 8 }, () => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[crypto.randomInt(32)]).join("");
    const hash = crypto.createHash("sha256").update(normCode(code)).digest("base64url");
    this.invites = this.invites.filter((i) => i.exp > Date.now());
    this.invites.push({ hash, exp: Date.now() + Math.max(ttlMs, 60_000) });
    this.save();
    return `${code.slice(0, 4)}-${code.slice(4)}`;
  }

  inviteCount(): number { this.refresh(); return this.invites.filter((i) => i.exp > Date.now()).length; }

  /** Kodu doğrular ve tüketir. Geçersiz/süresi dolmuşsa false. */
  redeemInvite(code: string): boolean {
    this.refresh();
    const hash = crypto.createHash("sha256").update(normCode(code)).digest("base64url");
    const now = Date.now();
    const i = this.invites.findIndex((v) => v.exp > now && v.hash.length === hash.length &&
      crypto.timingSafeEqual(Buffer.from(v.hash), Buffer.from(hash)));
    if (i === -1) return false;
    this.invites.splice(i, 1);
    this.save();
    return true;
  }

  /** Operatörün parola sıfırlaması (mevcut parolayı bilmeden). */
  adminSetPassword(user: string, next: string): { ok: boolean; error?: string } {
    this.refresh();
    const u = normUser(user);
    const a = this.items.get(u);
    if (!a) return { ok: false, error: "Böyle bir hesap yok." };
    const problem = passwordProblem(u, next);
    if (problem) return { ok: false, error: problem };
    a.salt = crypto.randomBytes(16).toString("base64url");
    a.hash = crypto.scryptSync(String(next), a.salt, 64, SCRYPT).toString("base64url");
    a.pvAt = Date.now();
    this.fails.delete(u);
    this.save();
    return { ok: true };
  }

  /** Hesabı siler (bağlantı anahtarı da geçersiz olur). */
  remove(user: string): boolean {
    this.refresh();
    const ok = this.items.delete(normUser(user));
    if (ok) this.save();
    return ok;
  }

  /** Hesap hatalı denemeler yüzünden kilitli mi? (Panelde gösterilir.) */
  isLocked(user: string): boolean {
    const f = this.fails.get(normUser(user));
    return Boolean(f && f.n >= MAX_FAILS && f.until > Date.now());
  }

  /** Kilitliyse aç (hatalı deneme sayacı bellektedir; yeniden başlatma da temizler). */
  unlock(user: string): boolean {
    return this.fails.delete(normUser(user));
  }

  private load(): void {
    if (!this.file) return;
    // Dosya doğruluk kaynağıdır: eski bellek hâli birleştirilmez, yoksa silinen hesap geri gelir.
    this.items = new Map();
    this.invites = [];
    // Operatör müdahalesi (parola sıfırlama, hesap açma/silme) hatalı deneme kilidini de açar.
    this.fails.clear();
    try {
      const d = JSON.parse(fs.readFileSync(this.file, "utf8")) as { items?: LocalAccount[]; invites?: Invite[] };
      if (Array.isArray(d.invites)) this.invites = d.invites.filter((i) => i && typeof i.hash === "string" && typeof i.exp === "number");
      for (const a of d.items ?? []) {
        if (a && typeof a.user === "string" && typeof a.hash === "string" && typeof a.salt === "string") {
          this.items.set(normUser(a.user), { ...a, user: normUser(a.user), connector: a.connector ?? "" });
        }
      }
    } catch { /* dosya yoksa boş başla */ }
    try { const st = fs.statSync(this.file); this.stamp = `${st.mtimeMs}:${st.size}`; } catch { this.stamp = ""; }
  }

  private save(): void {
    if (!this.file) return;
    try {
      const dir = path.dirname(this.file);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = `${this.file}.tmp`;
      const live = this.invites.filter((i) => i.exp > Date.now());
      fs.writeFileSync(tmp, JSON.stringify({ v: 1, items: [...this.items.values()], ...(live.length ? { invites: live } : {}) }), { mode: 0o600 });
      fs.renameSync(tmp, this.file);
      fs.chmodSync(this.file, 0o600);
      const st = fs.statSync(this.file); this.stamp = `${st.mtimeMs}:${st.size}`;
    } catch { /* disk hatası giriş akışını düşürmesin */ }
  }
}
