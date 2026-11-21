// Append-only, hash-linked JSONL. Original implementation AI-assisted; see CREDITS.md.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PolicyError, redact } from "./guard.js";

const ZERO = "0".repeat(64), CHUNK = 128 * 1024;
const sha = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
export interface VerifyResult { ok: boolean; entries: number; brokenAt?: number; reason?: string }
interface Snapshot { id: string; size: number; head: string; entries: number; expires: number }

// Host events remain in the process log. HTTP exports use a second, real, grant-specific
// chain; filtering or redacting a process-wide hash chain after the fact would break it.
export class Audit {
  readonly file: string;
  private prev = ZERO;
  private seq = 0;
  private readonly identity: fs.Stats;
  private grants = new Map<string, { chain: Audit; lastUse: number }>();
  private snapshots = new Map<string, Snapshot>();
  constructor(private dir: string, private failClosed: boolean, private parent?: Audit) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(dir, 0o700); } catch { /* best effort (Windows) */ }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    this.file = path.join(dir, `${stamp}-${process.pid}-${crypto.randomUUID()}.jsonl`);
    const fd = fs.openSync(this.file, "wx", 0o600);
    try { this.identity = fs.fstatSync(fd); } finally { fs.closeSync(fd); }
  }
  private open(flags: number): number {
    const fd = fs.openSync(this.file, flags | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
    try {
      const st = fs.fstatSync(fd);
      if (!st.isFile() || st.nlink !== 1 || st.ino !== this.identity.ino || st.dev !== this.identity.dev)
        throw new PolicyError("audit_changed", "audit file identity changed");
      return fd;
    } catch (e) { fs.closeSync(fd); throw e; }
  }
  get scope() { return this.parent ? "authorization" : "process"; }
  forGrant(owner: string): Audit {
    const now = Date.now();
    // Same lifetime as other in-memory authorization state. Never evict another live
    // grant to service a new one, nor switch a full/failed grant to the host log.
    for (const [id, grant] of this.grants) if (now - grant.lastUse > 12 * 60 * 60_000) this.grants.delete(id);
    const hit = this.grants.get(owner);
    if (hit) { hit.lastUse = now; return hit.chain; }
    if (this.grants.size >= 256) throw new PolicyError("audit_capacity", "too many active audit scopes");
    const child = new Audit(this.dir, this.failClosed, this);
    child.write({ ev: "scope_start", scope: "authorization" });
    this.grants.set(owner, { chain: child, lastUse: now });
    return child;
  }
  write(entry: Record<string, unknown>): void {
    this.parent?.write({ ...entry, segment: path.basename(this.file) });
    try {
      const rec = { ts: new Date().toISOString(), seq: this.seq, ...entry, prev: this.prev };
      const hash = sha(JSON.stringify(rec));
      const fd = this.open(fs.constants.O_WRONLY | fs.constants.O_APPEND);
      try { fs.writeFileSync(fd, JSON.stringify({ ...rec, hash }) + "\n"); } finally { fs.closeSync(fd); }
      this.seq++; this.prev = hash;
    } catch (e) {
      if (this.failClosed) throw new Error(`audit log write failed (fail-closed): ${(e as Error).message}`);
      console.error("[hardtools] audit write failed:", (e as Error).message);
    }
  }
  verify(): VerifyResult {
    const fd = this.open(fs.constants.O_RDONLY);
    try { return verifyAuditText(fs.readFileSync(fd, "utf8"), this.prev); } finally { fs.closeSync(fd); }
  }
  /** Pin a prefix before the result event is logged. Further MCP calls append, but never move its end. */
  exportPage(id?: string, offset = 0) {
    const now = Date.now();
    for (const [k, v] of this.snapshots) if (v.expires <= now) this.snapshots.delete(k);
    const fd = this.open(fs.constants.O_RDONLY);
    try {
      const size = fs.fstatSync(fd).size;
      let s: Snapshot;
      if (id !== undefined) {
        const existing = this.snapshots.get(id);
        if (!existing) throw new PolicyError("audit_snapshot", "unknown or expired snapshot for this authorization");
        s = existing;
      } else {
        if (offset !== 0) throw new PolicyError("audit_offset", "begin an export at offset zero");
        s = { id: crypto.randomUUID(), size, head: this.prev, entries: this.seq, expires: now + 15 * 60_000 };
        if (this.snapshots.size >= 4) this.snapshots.delete(this.snapshots.keys().next().value!);
        this.snapshots.set(s.id, s);
      }
      if (!Number.isSafeInteger(offset) || offset < 0 || offset > s.size) throw new PolicyError("audit_offset", "invalid byte offset");
      if (size < s.size) throw new PolicyError("audit_changed", "audit prefix was truncated; discard this export");
      const buf = Buffer.alloc(Math.min(CHUNK, s.size - offset));
      for (let n = 0; n < buf.length;) {
        const got = fs.readSync(fd, buf, n, buf.length - n, offset + n);
        if (!got) throw new PolicyError("audit_changed", "unexpected end of audit file");
        n += got;
      }
      const next = offset + buf.length;
      const filename = s.size <= CHUNK ? "hardtools-audit.jsonl" : `hardtools-audit.part-${String(offset).padStart(12, "0")}`;
      return {
        info: { scope: this.scope, filename, snapshot: s.id, total_bytes: s.size, entries: s.entries,
          expected_head: s.head, offset, next_offset: next < s.size ? next : null, expires_at: new Date(s.expires).toISOString() },
        resource: { uri: `hardtools-audit://local/${s.id}/${filename}`, mimeType: s.size <= CHUNK ? "application/x-ndjson" : "application/octet-stream", blob: buf.toString("base64") },
      };
    } finally { fs.closeSync(fd); }
  }
}

export function verifyAuditText(text: string, expectedHead?: string): VerifyResult {
  const lines = text.split("\n"); if (lines.at(-1) === "") lines.pop();
  let prev = ZERO;
  for (let i = 0; i < lines.length; i++) {
    const bad = (reason: string) => ({ ok: false, entries: i, brokenAt: i, reason });
    let obj; try { obj = JSON.parse(lines[i]); } catch { return bad("unparseable line"); }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return bad("invalid record");
    const { hash, ...rest } = obj;
    if (rest.seq !== i || rest.prev !== prev) return bad("sequence or prev-hash mismatch");
    if (sha(JSON.stringify(rest)) !== hash) return bad("entry content modified");
    prev = hash;
  }
  if (expectedHead !== undefined && prev !== expectedHead) return { ok: false, entries: lines.length, reason: "expected head does not match (wrong snapshot or missing tail)" };
  return { ok: true, entries: lines.length };
}
export function verifyAuditFile(file: string, expectedHead?: string): VerifyResult {
  return verifyAuditText(fs.readFileSync(file, "utf8"), expectedHead);
}
export function summarize(v: unknown, max = 400): unknown {
  if (typeof v === "string") { const r = redact(v); return r.length > max ? r.slice(0, max) + `…(+${r.length - max})` : r; }
  if (Array.isArray(v)) return v.slice(0, 50).map(x => summarize(x, max));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, summarize(x, max)]));
  return v;
}
