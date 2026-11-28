// ht_operator — yönetici (operatör) işlemlerini MCP üzerinden yapmak.
//
// Neden var: panel (/operator) tarayıcı gerektirir; sohbetten "davet kodu üret", "parola sıfırla",
// "hesap sil" gibi işlemleri yapmak için tarayıcıya geçmek gerekiyordu. Bu araç panelin TÜM
// işlevlerini sohbetten yapar.
//
// Yetki: HARDTOOLS_OPERATOR_TOKEN olmadan araç HİÇ çalışmaz. İki yol:
//   1) action="login" → tek kullanımlık link üretilir; kullanıcı linki tarayıcıda açıp anahtarı
//      yazar, sunucu 30 dakikalık bir "araç oturumu" (grant) açar. Sonraki çağrılar anahtarsız çalışır.
//   2) Çağrıya `token` alanı eklenir (sohbete yazmak istemeyenler için 1. yol önerilir).
// Yıkıcı işlemler (hesap silme, parola sıfırlama, çıkış) `confirm` ister.
//
// Sırlar sohbete düşmez: üretilen parola/davet kodu SENSRÜLÜ gösterilir, tamamı tek kullanımlık
// bir bağlantıda (`/operator/r/<id>`) açılır.

export interface OperatorAccount {
  user: string;
  createdAt: number;
  lastLogin: number;
  locked: boolean;
  /** MCP bağlantı anahtarı; yalnızca sensürlü biçimde gösterilir. */
  connector: string;
}

/** Aracın ihtiyaç duyduğu her şey (SettingsUI + LocalAccounts sarmalar). */
export interface OperatorHost {
  /** HARDTOOLS_OPERATOR_TOKEN tanımlı ve yeterince uzun mu? */
  enabled(): boolean;
  /** Verilen anahtar doğru mu? (sabit zamanlı) */
  checkToken(token: string): boolean;
  /** Tarayıcıda açılmış araç oturumu var mı? */
  grantActive(): boolean;
  grantLeftS(): number;
  /** Tek kullanımlık giriş bağlantısı (tarayıcıda anahtar yazılınca araç oturumu açılır). */
  loginLink(origin: string): { url: string; minutes: number };
  /** Bir değeri (parola/kod) tek seferlik bağlantıyla göster. */
  revealLink(origin: string, text: string, note: string): { url: string; minutes: number };
  accounts(): OperatorAccount[];
  account(user: string): OperatorAccount | undefined;
  /** Parola verilmezse güçlü parola üretilir; üretilen parola döner. */
  upsertAccount(user: string, password: string): { ok: true; created: boolean; password: string } | { ok: false; error: string };
  removeAccount(user: string): boolean;
  unlockAccount(user: string): boolean;
  rotateConnector(user: string): string | null;
  createInvite(ttlMin: number): string;
  inviteCount(): number;
  signupInfo(): { mode: string; source: string };
  setSignup(mode: "first" | "open" | "off" | null): { mode: string; source: string };
  logout(): void;
  audit(ev: Record<string, unknown>): void;
}

export interface OperatorArgs {
  action?: "login" | "get" | "set" | "logout";
  confirm?: string;
  token?: string;
  user?: string;
  password?: string;
  invite?: boolean;
  ttl_minutes?: number;
  unlock?: boolean;
  rotate_connector?: boolean;
  signup?: "first" | "open" | "off" | "env";
}

/** Bir sırrı sohbette gösterilebilir hâle getirir: ilk 4 + son 2 karakter. */
export function censor(v: string, head = 4, tail = 2): string {
  const s = String(v ?? "");
  if (s.length <= head + tail + 2) return "•".repeat(Math.max(4, s.length));
  // DİKKAT: slice(-0) === slice(0) — tail=0 "tamamını" döndürürdü; ayrı ele alınmalı.
  const t = tail > 0 ? s.slice(-tail) : "";
  return `${s.slice(0, head)}${"•".repeat(6)}${t}`;
}

/** `user / password` biçimindeki metni değil, yalnızca kullanıcı adını ve sensürlü parolayı göster. */
const iso = (t: number) => (t ? new Date(t).toISOString().replace("T", " ").slice(0, 16) : "—");

const NOT_CONFIGURED = `HARDTOOLS_OPERATOR_TOKEN tanımlı değil: ht_operator çalışmaz.
Tanımlamak için (tarayıcıdan): Fly.io panosu → uygulama → Secrets → Add secret →
ad: HARDTOOLS_OPERATOR_TOKEN, değer: en az 16 karakter → kaydet (makine yeniden başlar).
Terminal varsa: flyctl secrets set HARDTOOLS_OPERATOR_TOKEN="$(openssl rand -hex 24)" -a <uygulama>`;

const NEED_LOGIN = `Bu işlem için yönetici oturumu gerekli.
Yapılacak: ht_operator {"action":"login"} → dönen bağlantıyı tarayıcıda aç → operatör anahtarını yaz.
Alternatif: çağrıya "token" alanını ekle (anahtar HARDTOOLS_OPERATOR_TOKEN).`;

export function htOperator(host: OperatorHost, a: OperatorArgs, ctx: { origin: string }): string {
  const action = a.action ?? "get";
  if (!host.enabled()) {
    host.audit({ ev: "operator_tool_denied", reason: "not_configured", action });
    return NOT_CONFIGURED;
  }

  // --- login: tek kullanımlık giriş bağlantısı ---------------------------------------------
  if (action === "login") {
    if (host.grantActive()) {
      return `Zaten açık bir yönetici oturumu var (${host.grantLeftS()} sn kaldı). İşlemlere geçebilirsin.
Oturumu kapatmak için: ht_operator {"action":"logout","confirm":"logout"}`;
    }
    const link = host.loginLink(ctx.origin);
    host.audit({ ev: "operator_tool_login_link" });
    return `Yönetici girişi için bağlantı (${link.minutes} dakika geçerli, tek kullanımlık):
${link.url}

Yapılacak: bağlantıyı tarayıcıda aç → operatör anahtarını (HARDTOOLS_OPERATOR_TOKEN) yaz → giriş.
Giriş yapılınca 30 dakika boyunca ht_operator anahtarsız çalışır; panel oturumu da açılır.`;
  }

  // --- yetki -------------------------------------------------------------------------------
  const tokenGiven = (a.token ?? "").trim();
  let why = "";
  if (tokenGiven) {
    if (!host.checkToken(tokenGiven)) {
      host.audit({ ev: "operator_tool_denied", reason: "bad_token", action });
      return `Hata: operatör anahtarı yanlış. ${NEED_LOGIN}`;
    }
  } else if (!host.grantActive()) {
    host.audit({ ev: "operator_tool_denied", reason: "no_grant", action });
    return NEED_LOGIN;
  }

  // --- logout ------------------------------------------------------------------------------
  if (action === "logout") {
    if ((a.confirm ?? "").trim().toLowerCase() !== "logout") {
      return `Çıkışı onaylamak için confirm alanına "logout" yaz: ht_operator {"action":"logout","confirm":"logout"}`;
    }
    const wasActive = host.grantActive();
    host.logout();
    host.audit({ ev: "operator_tool_logout" });
    return wasActive ? "Yönetici oturumu kapatıldı (araç oturumu ve panel çerezi geçersiz)." : "Açık yönetici oturumu yoktu; yine de çerez/oturum temizlendi.";
  }

  // --- get ---------------------------------------------------------------------------------
  if (action === "get") {
    const u = (a.user ?? "").trim().toLowerCase();
    if (a.invite) {
      const ttl = Math.min(43200, Math.max(5, Math.round(Number(a.ttl_minutes) || 1440)));
      const code = host.createInvite(ttl);
      const link = host.revealLink(ctx.origin, code, `Tek kullanımlık kayıt kodu (${ttl} dakika)`);
      host.audit({ ev: "operator_tool_invite", ttl_min: ttl });
      return `Davet kodu üretildi (${ttl} dakika, tek kullanımlık): ${censor(code, 4, 0)}
Kod sohbete yazılmaz. Tamamını görmek için (tek seferlik, ${link.minutes} dakika):
${link.url}

Kullanıcı kodu /local → "Hesap aç" bölümüne yazar. Bekleyen kod sayısı: ${host.inviteCount()}`;
    }
    if (u) {
      const acc = host.account(u);
      if (!acc) return `Hesap yok: ${u}. Mevcut hesaplar için: ht_operator {"action":"get"}`;
      return JSON.stringify({
        hesap: acc.user,
        oluşturma: iso(acc.createdAt),
        son_giris: iso(acc.lastLogin),
        kilitli: acc.locked,
        mcp_adresi: `${ctx.origin}/lc/${censor(acc.connector, 6, 4)}`,
        not: "MCP adresinin tamamı yalnızca hesabın sahibine gösterilir (panelde /local).",
      }, null, 2);
    }
    const rows = host.accounts();
    const signup = host.signupInfo();
    return JSON.stringify({
      hesaplar: rows.map((r) => ({ hesap: r.user, olusturma: iso(r.createdAt), son_giris: iso(r.lastLogin), kilitli: r.locked, mcp: `lc/${censor(r.connector, 6, 4)}` })),
      hesap_sayisi: rows.length,
      bekleyen_davet: host.inviteCount(),
      kayit_modu: `${signup.mode} (${signup.source === "operator" ? "operatör" : "ortam"})`,
      yonetici_oturumu: host.grantActive() ? `${host.grantLeftS()} sn` : "yok",
      not: "Parola ve MCP anahtarı hiçbir zaman tam gösterilmez; davet kodu için invite=true kullan.",
    }, null, 2);
  }

  // --- set: ayarlar + hesap işlemleri ------------------------------------------------------
  const u = (a.user ?? "").trim().toLowerCase();
  const confirm = (a.confirm ?? "").trim().toLowerCase();
  const pw = (a.password ?? "").trim();

  if (a.signup !== undefined) {
    const target = a.signup === "env" ? null : a.signup;
    if (target === "off" && confirm !== "off") {
      return `Kaydı tamamen kapatmak için onay gerekli: ht_operator {"action":"set","signup":"off","confirm":"off"}`;
    }
    const s = host.setSignup(target);
    host.audit({ ev: "operator_tool_signup", mode: s.mode, source: s.source });
    return `Kayıt modu: ${s.mode} (${s.source === "operator" ? "operatör" : "ortam"}).
${s.mode === "off" ? "Yeni hesap yalnızca panelden/araçtan açılabilir (davet kodu da kabul edilmez)." : s.mode === "open" ? "Herkese açık kayıt: /local sayfasında form görünür." : "Yalnızca hiç hesap yokken kayıt açık; aksi hâlde davet kodu gerekir."}`;
  }

  if (!u) {
    return `Hesap işlemi için "user" gerekli.
Örnekler:
  aç/parola: ht_operator {"action":"set","user":"ali","password":""}   (boş parola = üret)
  parola:    ht_operator {"action":"set","user":"ali","password":"Yeni-Parola-9x","confirm":"ali"}
  sil:       ht_operator {"action":"set","user":"ali","confirm":"ali"}
  kilit aç:  ht_operator {"action":"set","user":"ali","unlock":true}
  anahtar:   ht_operator {"action":"set","user":"ali","rotate_connector":true,"confirm":"ali"}
  ayar:      ht_operator {"action":"set","signup":"open"}`;
  }

  const existing = host.account(u);

  if (a.unlock) {
    if (!existing) return `Hesap yok: ${u}`;
    host.unlockAccount(u);
    host.audit({ ev: "operator_tool_unlock", user: u });
    return `Kilidi açıldı: ${u}`;
  }

  if (a.rotate_connector) {
    if (!existing) return `Hesap yok: ${u}`;
    if (confirm !== u) return `Bağlantı anahtarını yenilemek için onay gerekli: confirm alanına "${u}" yaz (eski MCP adresi çalışmayı bırakır).`;
    const next = host.rotateConnector(u);
    if (!next) return `Hesap yok: ${u}`;
    const link = host.revealLink(ctx.origin, next, `${u} için yeni MCP bağlantı anahtarı`);
    host.audit({ ev: "operator_tool_rotate", user: u });
    return `Bağlantı anahtarı yenilendi: ${u} → /lc/${censor(next, 6, 4)}
Tamamı için (tek seferlik, ${link.minutes} dakika): ${link.url}`;
  }

  // Silme: confirm kullanıcı adıyla eşleşmeli.
  const wantsDelete = confirm === u && !pw;
  if (wantsDelete) {
    if (!existing) return `Hesap yok: ${u}`;
    host.removeAccount(u);
    host.audit({ ev: "operator_tool_delete", user: u });
    return `${u} silindi. MCP adresi çalışmayı bıraktı; disk üzerindeki dosyalar silinmedi (çalışma alanı kökü elle silinebilir, /workspaces).`;
  }

  // Hesap aç ya da parola sıfırla.
  if (existing && pw && confirm !== u) {
    return `Parola sıfırlama mevcut oturumları düşürür. Onay için confirm alanına "${u}" yaz:
ht_operator {"action":"set","user":"${u}","password":"…","confirm":"${u}"}`;
  }
  if (existing && !pw && confirm !== u) {
    return `"${u}" zaten var. Parolasını sıfırlamak için confirm alanına "${u}" yaz (yeni güçlü parola üretilir):
ht_operator {"action":"set","user":"${u}","confirm":"${u}"}`;
  }
  const r = host.upsertAccount(u, pw);
  if (!r.ok) return `Hata: ${r.error}`;
  const link = host.revealLink(ctx.origin, `${u} / ${r.password}`, `${u} için parola`);
  host.audit({ ev: r.created ? "operator_tool_account_created" : "operator_tool_password_reset", user: u });
  return `${r.created ? "Hesap açıldı" : "Parola sıfırlandı"}: ${u}
Parola: ${censor(r.password, 3, 2)}  (sohbete tam yazılmaz)
Tamamını görmek için (tek seferlik, ${link.minutes} dakika): ${link.url}
${r.created ? "" : "Eski parola ve açık oturumlar geçersiz oldu."}
${why}`;
}
