// Yerel hesap yönetimi için operatör komut satırı (sunucu başlatmadan çalışır).
//
// Neden var: kayıt varsayılan olarak "first" modunda (yalnızca ilk hesap). İlk hesap açıldıktan
// sonra yeni hesap açmak ya da parola sıfırlamak için hiçbir yol yoktu; kullanıcı "Kullanıcı adı
// veya parola yanlış" hatasında kilitli kalıyordu. Bu komutlar flyctl ssh üzerinden çalıştırılır:
//
//   node dist/index.js --local-user list
//   node dist/index.js --local-user invite --ttl 1440      # tek kullanımlık kayıt kodu üretir
//   node dist/index.js --local-user add <ad> --password-stdin
//   node dist/index.js --local-user passwd <ad> --password-stdin
//   node dist/index.js --local-user del <ad>
//
// Parola verilmezse güçlü bir parola üretilip bir kez yazdırılır (hiçbir yere kaydedilmez).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { LocalAccounts, passwordProblem } from "./localauth.js";

export const LOCAL_CLI_USAGE = `Kullanım:
  --local-user list
  --local-user invite [--ttl <dakika>]
  --local-user add <kullanıcı> [--password-stdin | --password <parola>]
  --local-user passwd <kullanıcı> [--password-stdin | --password <parola>]
  --local-user del <kullanıcı>`;

/** Rastgele, politika uyumlu parola (24 karakter, dört tür). */
export function randomPassword(len = 24): string {
  const abc = "abcdefghijkmnopqrstuvwxyz", ABC = "ABCDEFGHJKLMNPQRSTUVWXYZ", num = "23456789", sym = "!@#$%*-_=+";
  const all = abc + ABC + num + sym;
  const pick = (s: string) => s[crypto.randomInt(s.length)];
  const chars = [pick(abc), pick(ABC), pick(num), pick(sym)];
  while (chars.length < len) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join("");
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

export interface LocalCliOptions { stateDir?: string }

export async function localUserCli(argv: string[], opts: LocalCliOptions = {}): Promise<number> {
  const [sub, ...rest] = argv;
  const flag = (name: string): string | undefined => {
    const i = rest.indexOf(name);
    if (i === -1) return undefined;
    const v = rest[i + 1];
    return v && !v.startsWith("--") ? v : "";
  };
  const positional = rest.filter((v, i) => !v.startsWith("--") && !(i > 0 && rest[i - 1] === "--ttl" && false));
  const userArg = rest.find(v => !v.startsWith("--"));

  const store = opts.stateDir ? path.join(opts.stateDir, "local-accounts.json") : undefined;
  if (!store) {
    console.error("Durum dizini bulunamadı (HARDTOOLS_STATE_DIR ya da denetim dizini gerekli).");
    return 1;
  }
  const accounts = new LocalAccounts({ store, signup: process.env.HARDTOOLS_LOCAL_SIGNUP });

  const newPassword = async (user: string): Promise<{ pw: string; generated: boolean } | { error: string }> => {
    let pw = "";
    if (rest.includes("--password-stdin")) pw = (await readStdin()).split("\n")[0];
    else if (flag("--password")) pw = flag("--password")!;
    else if (process.env.HARDTOOLS_NEW_PASSWORD) pw = process.env.HARDTOOLS_NEW_PASSWORD;
    else return { pw: randomPassword(), generated: true };
    pw = pw.replace(/[\r\n]+$/, "");
    const problem = passwordProblem(user, pw);
    if (problem) return { error: problem };
    return { pw, generated: false };
  };

  switch (sub) {
    case "list": {
      const names = accounts.list();
      if (!names.length) console.log("Yerel hesap yok.");
      for (const n of names) {
        const a = accounts.get(n)!;
        const last = a.lastLogin ? new Date(a.lastLogin).toISOString() : "hiç";
        console.log(`${n}\tson giriş: ${last}\tkayıt: ${new Date(a.createdAt).toISOString()}`);
      }
      const invites = accounts.inviteCount();
      if (invites) console.log(`Bekleyen davet kodu: ${invites}`);
      return 0;
    }
    case "invite": {
      const ttlMin = Number(flag("--ttl") ?? "1440") || 1440;
      const code = accounts.createInvite(Math.min(Math.max(ttlMin, 5), 60 * 24 * 30) * 60_000);
      console.log(code);
      console.error(`Tek kullanımlık kayıt kodu (${ttlMin} dakika). Kullanıcı /local sayfasındaki "Hesap aç" bölümüne bu kodu yazsın.`);
      return 0;
    }
    case "add":
    case "passwd": {
      if (!userArg) { console.error(LOCAL_CLI_USAGE); return 2; }
      const user = userArg.trim().toLowerCase();
      const existing = accounts.has(user);
      if (sub === "add" && existing) { console.error(`"${user}" zaten var. Parola sıfırlamak için: --local-user passwd ${user}`); return 1; }
      if (sub === "passwd" && !existing) { console.error(`"${user}" yok. Hesap açmak için: --local-user add ${user}`); return 1; }
      const pwRes = await newPassword(user);
      if ("error" in pwRes) { console.error(`Parola politikası: ${pwRes.error}`); return 1; }
      if (sub === "add") {
        const r = accounts.create(user, pwRes.pw);
        if (!r.ok) { console.error(r.error); return 1; }
        console.log(`Hesap açıldı: ${r.account.user}`);
      } else {
        const r = accounts.adminSetPassword(user, pwRes.pw);
        if (!r.ok) { console.error(r.error ?? "Parola değiştirilemedi."); return 1; }
        console.log(`Parola güncellendi: ${user}`);
      }
      if (pwRes.generated) console.log(`Parola (bir kez gösterilir, kaydedilmez): ${pwRes.pw}`);
      if (pwRes.generated) console.error("Bu parolayı kullanıcıya ilet; panelden değiştirebilir.");
      return 0;
    }
    case "del": {
      if (!userArg) { console.error(LOCAL_CLI_USAGE); return 2; }
      const user = userArg.trim().toLowerCase();
      if (!accounts.remove(user)) { console.error(`"${user}" yok.`); return 1; }
      console.log(`Silindi: ${user}`);
      return 0;
    }
    default:
      console.error(LOCAL_CLI_USAGE);
      return 2;
  }
  void positional; void fs;
}
