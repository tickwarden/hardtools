// Yerel hesaplar: GitHub olmadan giriş. İki durum için var:
//   1) GitHub hesabı olmayan kullanıcılar paneli kullanabilsin.
//   2) GitHub girişi bozulduğunda / erişilemediğinde operatör ve kullanıcılar kilitli kalmasın.
// Parolalar scrypt ile (kullanıcı başına rastgele tuz) saklanır; düz metin hiçbir yere yazılmaz.
// Kimlik: owner kimliği `local:<ad>`, kullanıcı adı `<ad>` — GitHub login'leriyle çakışırsa reddedilir.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface LocalAccount {
  user: string;
  salt: string;
  hash: string;
  createdAt: number;
  lastLogin: number;
  /** MCP bağlantı anahtarı (yüksek entropili, yalnızca sahibine gösterilir). */
  connector: string;
}

const USER_RE = /^[a-z0-9][a-z0-9_.-]{2,31}$/;
const MIN_PASSWORD = 10;
const MAX_ACCOUNTS = 200;
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;

const normUser = (v: unknown) => String(v ?? "").trim().toLowerCase();

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
  private fails = new Map<string, { n: number; until: number }>();
  private file?: string;

  /**
   * @param opts.store  Hesap dosyası (durum dizininde, 0600). Yoksa hesaplar yalnızca bellekte tutulur.
   * @param opts.signup "first" (varsayılan: yalnızca hiç hesap yokken kayıt), "open", "off".
   */
  constructor(private opts: { store?: string; signup?: string } = {}) {
    this.file = opts.store;
    this.load();
  }

  private get signupMode(): "first" | "open" | "off" {
    const v = (this.opts.signup ?? "first").trim().toLowerCase();
    return v === "open" || v === "off" ? v : "first";
  }

  /** Kayıt sayfası gösterilsin mi? ("first" modunda yalnızca ilk hesap için.) */
  canRegister(): boolean {
    const mode = this.signupMode;
    if (mode === "off") return false;
    if (mode === "open") return this.items.size < MAX_ACCOUNTS;
    return this.items.size === 0;
  }

  count(): number { return this.items.size; }

  list(): string[] { return [...this.items.keys()].sort(); }

  get(user: string): LocalAccount | undefined { return this.items.get(normUser(user)); }

  /** Bu kullanıcı adı yerel bir hesap mı? (GitHub login'leriyle çakışma denetimi için.) */
  has(user: string): boolean { return this.items.has(normUser(user)); }

  /** Bağlantı anahtarından kullanıcı adı (MCP /lc/<anahtar> yolu). */
  userForConnector(token: string): string | null {
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(token)) return null;
    for (const a of this.items.values()) {
      if (a.connector.length === token.length && crypto.timingSafeEqual(Buffer.from(a.connector), Buffer.from(token))) return a.user;
    }
    return null;
  }

  connectorFor(user: string): string | null { return this.items.get(normUser(user))?.connector ?? null; }

  /**
   * Hesap oluşturur. `reserved` içindeki adlar (bilinen GitHub login'leri) reddedilir:
   * aynı ad iki kimlik türünde birleşirse ayarlar/çalışma alanı karışırdı.
   */
  create(user: string, password: string, reserved: (name: string) => boolean = () => false): { ok: true; account: LocalAccount } | { ok: false; error: string } {
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
    const u = normUser(user);
    const now = Date.now();
    const f = this.fails.get(u);
    if (f && f.until > now) return { ok: false, error: "Çok fazla hatalı deneme; birkaç dakika sonra tekrar dene." };
    const a = this.items.get(u);
    if (!a) return { ok: false, error: "Kullanıcı adı veya parola yanlış." };
    const want = Buffer.from(a.hash, "base64url");
    const got = crypto.scryptSync(String(password ?? ""), a.salt, 64, SCRYPT);
    const ok = want.length === got.length && crypto.timingSafeEqual(want, got);
    if (!ok) {
      const n = (f?.until && f.until <= now ? 0 : f?.n ?? 0) + 1;
      this.fails.set(u, { n, until: n >= 8 ? now + 10 * 60_000 : now + 60_000 });
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
    this.save();
    return { ok: true };
  }

  /** Bağlantı anahtarını yeniler (sızdıysa eski URL çalışmaz). */
  rotateConnector(user: string): string | null {
    const a = this.items.get(normUser(user));
    if (!a) return null;
    a.connector = crypto.randomBytes(32).toString("base64url");
    this.save();
    return a.connector;
  }

  private load(): void {
    if (!this.file) return;
    try {
      const d = JSON.parse(fs.readFileSync(this.file, "utf8")) as { items?: LocalAccount[] };
      for (const a of d.items ?? []) {
        if (a && typeof a.user === "string" && typeof a.hash === "string" && typeof a.salt === "string") {
          this.items.set(normUser(a.user), { ...a, user: normUser(a.user), connector: a.connector ?? "" });
        }
      }
    } catch { /* dosya yoksa boş başla */ }
  }

  private save(): void {
    if (!this.file) return;
    try {
      const dir = path.dirname(this.file);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = `${this.file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ v: 1, items: [...this.items.values()] }), { mode: 0o600 });
      fs.renameSync(tmp, this.file);
      fs.chmodSync(this.file, 0o600);
    } catch { /* disk hatası giriş akışını düşürmesin */ }
  }
}
