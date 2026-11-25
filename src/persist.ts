// AI-generated (Claude, Anthropic), 2026-11-18. Requires human security review before production use.
/**
 * Kalıcı durum dosyaları: AES-256-GCM ile şifreli, atomik (temp+rename), 0600.
 *
 * Neden: süreç yeniden başlayınca oturum değişkenleri, paylaşım bağlantıları, zamanlanmış
 * çağrılar ve geri alma günlüğü sessizce kayboluyordu. Disk zaten kalıcı hacimde (/data);
 * eksik olan, bellekteki durumun oraya yazılmasıydı.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface Persist { read<T>(fallback: T): T; write(value: unknown): void }

export class StateFile implements Persist {
  constructor(private file?: string, private keyPath?: string) {}

  get path(): string | undefined { return this.file; }

  private key(): Buffer {
    const p = this.keyPath ?? `${this.file}.key`;
    try { const b = fs.readFileSync(p); if (b.length === 32) return b; } catch { /* anahtar üretilecek */ }
    const k = crypto.randomBytes(32);
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
    fs.writeFileSync(p, k, { mode: 0o600 });
    return k;
  }

  /** Bozuk/eski/eksik dosya: sessizce varsayılana döner (sunucu açılmaz diye durmaz). */
  read<T>(fallback: T): T {
    if (!this.file) return fallback;
    let raw: Buffer;
    try { raw = fs.readFileSync(this.file); } catch { return fallback; }
    try {
      if (raw.subarray(0, 4).toString() !== "HT1:") return fallback;
      const iv = raw.subarray(4, 16), tag = raw.subarray(16, 32), body = raw.subarray(32);
      const d = crypto.createDecipheriv("aes-256-gcm", this.key(), iv);
      d.setAuthTag(tag);
      return JSON.parse(Buffer.concat([d.update(body), d.final()]).toString("utf8")) as T;
    } catch { return fallback; }
  }

  write(value: unknown): void {
    if (!this.file) return;
    try {
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv("aes-256-gcm", this.key(), iv);
      const body = Buffer.concat([c.update(JSON.stringify(value), "utf8"), c.final()]);
      fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
      const tmp = `${this.file}.tmp-${process.pid}`;
      fs.writeFileSync(tmp, Buffer.concat([Buffer.from("HT1:"), iv, c.getAuthTag(), body]), { mode: 0o600 });
      fs.renameSync(tmp, this.file);
    } catch { /* kalıcılık hatası ana işlemi engellemez */ }
  }
}
