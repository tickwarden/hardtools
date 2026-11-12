// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { redact } from "./guard.js";

const ZERO = "0".repeat(64);

export interface VerifyResult { ok: boolean; entries: number; brokenAt?: number; reason?: string }

/** Append-only JSONL with a SHA-256 hash chain. Tamper-EVIDENT (not tamper-proof): detects edits/deletions in the middle, not truncation of the tail. One file per server process. */
export class Audit {
  readonly file: string;
  private prev = ZERO;
  private seq = 0;
  constructor(dir: string, private failClosed: boolean) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(dir, 0o700); } catch { /* best effort (Windows) */ }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    this.file = path.join(dir, `${stamp}-${process.pid}.jsonl`);
    fs.writeFileSync(this.file, "", { mode: 0o600, flag: "wx" });
  }
  write(entry: Record<string, unknown>): void {
    try {
      const rec = { ts: new Date().toISOString(), seq: this.seq++, ...entry, prev: this.prev };
      const body = JSON.stringify(rec);
      const hash = crypto.createHash("sha256").update(body).digest("hex");
      fs.appendFileSync(this.file, JSON.stringify({ ...rec, hash }) + "\n", { mode: 0o600 });
      this.prev = hash;
    } catch (e) {
      if (this.failClosed) throw new Error(`audit log write failed (fail-closed): ${(e as Error).message}`);
      console.error("[hardtools] audit write failed:", (e as Error).message);
    }
  }
  verify(): VerifyResult { return verifyAuditFile(this.file); }
}

export function verifyAuditFile(file: string): VerifyResult {
  const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  let prev = ZERO;
  for (let i = 0; i < lines.length; i++) {
    let obj: any;
    try { obj = JSON.parse(lines[i]); } catch { return { ok: false, entries: i, brokenAt: i, reason: "unparseable line" }; }
    const { hash, ...rest } = obj;
    if (rest.prev !== prev) return { ok: false, entries: i, brokenAt: i, reason: "prev-hash mismatch (entry removed or reordered)" };
    const calc = crypto.createHash("sha256").update(JSON.stringify(rest)).digest("hex");
    if (calc !== hash) return { ok: false, entries: i, brokenAt: i, reason: "entry content modified" };
    prev = hash;
  }
  return { ok: true, entries: lines.length };
}

export function summarize(v: unknown, max = 400): unknown {
  if (typeof v === "string") { const r = redact(v); return r.length > max ? r.slice(0, max) + `…(+${r.length - max})` : r; }
  if (Array.isArray(v)) return v.slice(0, 50).map(x => summarize(x, max));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, summarize(x, max)]));
  return v;
}
