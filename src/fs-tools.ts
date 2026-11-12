// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";
import { PolicyError, enforceSecrets, isDeniedRead, resolveSafe } from "./guard.js";

export const testHooks: { failAfterWrites: number | null; beforeCommit: (() => void) | null } = { failAfterWrites: null, beforeCommit: null };

const sha = (b: Buffer | string) => crypto.createHash("sha256").update(b).digest("hex");
const O_NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

function readBytesNoFollow(abs: string, max: number): Buffer {
  const fd = fs.openSync(abs, fs.constants.O_RDONLY | O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new PolicyError("not_a_file", "not a regular file");
    if (st.size > max) throw new PolicyError("too_large", `file is ${st.size} bytes; limit is ${max}. Use ht_search or read a smaller file.`);
    const buf = Buffer.alloc(st.size);
    let off = 0; while (off < st.size) { const n = fs.readSync(fd, buf, off, st.size - off, off); if (n <= 0) break; off += n; }
    return buf.subarray(0, off);
  } finally { fs.closeSync(fd); }
}
const looksBinary = (b: Buffer) => b.subarray(0, 8000).includes(0);
const detectEol = (s: string): "crlf" | "lf" | "mixed" | "none" => {
  const crlf = (s.match(/\r\n/g) ?? []).length; const lf = (s.match(/\n/g) ?? []).length - crlf;
  return crlf && lf ? "mixed" : crlf ? "crlf" : lf ? "lf" : "none";
};

/* ------------------------------- ht_read -------------------------------- */
export function htRead(policy: Policy, a: { path: string; start_line?: number; end_line?: number; numbered?: boolean }): string {
  const r = resolveSafe(policy, a.path, "read");
  const lst = fs.lstatSync(r.abs);
  if (lst.isDirectory()) {
    const names = fs.readdirSync(r.abs, { withFileTypes: true });
    let hidden = 0; const rows: string[] = [];
    for (const d of names.sort((x, y) => x.name.localeCompare(y.name))) {
      const child = path.join(r.abs, d.name);
      if (isDeniedRead(policy, child)) { hidden++; continue; }
      if (rows.length >= 300) { rows.push("… (truncated at 300 entries)"); break; }
      rows.push(d.isDirectory() ? `${d.name}/` : d.isSymbolicLink() ? `${d.name}@ (symlink)` : `${d.name}\t${fs.statSync(child).size} B`);
    }
    return `DIR ${path.relative(r.root, r.abs) || "."}\n${rows.join("\n")}${hidden ? `\n(${hidden} protected entries hidden)` : ""}`;
  }
  const buf = readBytesNoFollow(r.abs, policy.fs.maxReadBytes);
  if (looksBinary(buf)) throw new PolicyError("binary_file", `binary file (${buf.length} bytes); not returned`);
  let text = buf.toString("utf8"); const bom = text.charCodeAt(0) === 0xfeff; if (bom) text = text.slice(1);
  const lossy = text.includes("\ufffd");
  const lines = text.split(/\r?\n/); if (lines.at(-1) === "") lines.pop();
  const s = Math.max(1, a.start_line ?? 1); const e = Math.min(lines.length, a.end_line ?? Math.min(lines.length, s + 1999));
  if (s > lines.length && lines.length) throw new PolicyError("range", `start_line ${s} is beyond end of file (${lines.length} lines)`);
  const numbered = a.numbered ?? true;
  const body = lines.slice(s - 1, e).map((l, i) => (numbered ? `${s + i}\t${l}` : l)).join("\n");
  const head = `FILE ${path.relative(r.root, r.abs)} | lines ${lines.length ? s : 0}-${e} of ${lines.length} | eol=${detectEol(text)}${bom ? " | bom" : ""}${lossy ? " | NOT valid UTF-8 (lossy; ht_edit will refuse)" : ""} | sha256=${sha(buf)}`;
  return `${head}\n${body}${e < lines.length ? `\n… ${lines.length - e} more lines (use start_line/end_line)` : ""}`;
}

/* ----------------------------- atomic writing ---------------------------- */
function atomicWrite(abs: string, data: Buffer, mode: number, noClobber: boolean): void {
  const dir = path.dirname(abs);
  const tmp = path.join(dir, `.${path.basename(abs)}.ht-${crypto.randomBytes(6).toString("hex")}.tmp`);
  const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | O_NOFOLLOW, mode & 0o777);
  try { fs.writeSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  try {
    if (noClobber) fs.linkSync(tmp, abs); else fs.renameSync(tmp, abs); // link() fails with EEXIST: atomic "create only"
  } catch (e: any) {
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    if (e.code === "EEXIST") throw new PolicyError("exists", "file already exists (set overwrite=true and pass if_hash)");
    throw e;
  }
  if (noClobber) { try { fs.unlinkSync(tmp); } catch { /* ignore */ } }
}

/* ------------------------------- ht_write -------------------------------- */
export function htWrite(policy: Policy, a: { path: string; content: string; overwrite?: boolean; if_hash?: string; mkdirp?: boolean }): string {
  const r = resolveSafe(policy, a.path, "write");
  if (a.content.includes("\0")) throw new PolicyError("binary_content", "NUL bytes are not allowed (text files only)");
  const data = Buffer.from(a.content, "utf8");
  if (data.length > policy.fs.maxWriteBytes) throw new PolicyError("too_large", `content is ${data.length} bytes; limit is ${policy.fs.maxWriteBytes}`);
  const warnings = enforceSecrets(policy, a.content, "content");
  let mode = 0o644; let existed = false;
  if (r.exists) {
    const st = fs.lstatSync(r.abs);
    if (!st.isFile()) throw new PolicyError("not_a_file", "target exists and is not a regular file");
    existed = true; mode = st.mode;
    if (!a.overwrite) throw new PolicyError("exists", "file exists; set overwrite=true" + (policy.fs.requireHashForOverwrite ? " and pass if_hash from ht_read" : ""));
    if (policy.fs.requireHashForOverwrite && !a.if_hash) throw new PolicyError("hash_required", "overwriting requires if_hash (read the file first with ht_read)");
    if (a.if_hash) {
      const cur = sha(readBytesNoFollow(r.abs, Math.max(policy.fs.maxReadBytes, st.size)));
      if (cur !== a.if_hash) throw new PolicyError("hash_mismatch", "file changed since it was read (if_hash mismatch); re-read it");
    }
  } else {
    const dir = path.dirname(r.abs);
    if (!fs.existsSync(dir)) {
      if (!a.mkdirp) throw new PolicyError("no_parent", "parent directory does not exist (set mkdirp=true)");
      fs.mkdirSync(dir, { recursive: true });
    }
  }
  atomicWrite(r.abs, data, mode, !existed);
  return `${existed ? "OVERWROTE" : "CREATED"} ${path.relative(r.root, r.abs)} | ${data.length} bytes | sha256=${sha(data)}${warnings.length ? "\nWARNINGS:\n- " + warnings.join("\n- ") : ""}`;
}

/* ------------------------------- ht_edit --------------------------------- */
export interface EditItem { path: string; old_str: string; new_str: string; replace_all?: boolean; if_hash?: string }

function lineOf(text: string, idx: number): number { let n = 1; for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) n++; return n; }
function indicesOf(hay: string, needle: string): number[] { const out: number[] = []; let i = 0; while ((i = hay.indexOf(needle, i)) !== -1) { out.push(i); i += needle.length; } return out; }

function miniDiff(rel: string, a: string, b: string): string {
  const A = a.split("\n"), B = b.split("\n"); let p = 0;
  while (p < A.length && p < B.length && A[p] === B[p]) p++;
  let sa = A.length, sb = B.length;
  while (sa > p && sb > p && A[sa - 1] === B[sb - 1]) { sa--; sb--; }
  const ctx = 3, from = Math.max(0, p - ctx);
  const out = [`--- a/${rel}`, `+++ b/${rel}`, `@@ -${from + 1} +${from + 1} @@`];
  for (let i = from; i < p; i++) out.push(" " + A[i]);
  const rem = A.slice(p, sa), add = B.slice(p, sb); let shown = 0;
  for (const l of rem) { if (shown++ < 150) out.push("-" + l); }
  for (const l of add) { if (shown++ < 150) out.push("+" + l); }
  if (shown > 150) out.push(`… (${shown - 150} more changed lines not shown)`);
  for (let i = sa; i < Math.min(A.length, sa + ctx); i++) out.push(" " + A[i]);
  return out.join("\n");
}

interface Staged { rel: string; abs: string; orig: Buffer; origSha: string; next: Buffer; mode: number; diff: string }

export function htEdit(policy: Policy, a: { edits: EditItem[]; dry_run?: boolean }): string {
  if (!a.edits.length) throw new PolicyError("no_edits", "edits is empty");
  const groups = new Map<string, { r: ReturnType<typeof resolveSafe>; items: EditItem[] }>();
  for (const e of a.edits) {
    const r = resolveSafe(policy, e.path, "write");
    if (!r.exists) throw new PolicyError("not_found", `file does not exist: ${e.path} (use ht_write to create files)`);
    const g = groups.get(r.abs) ?? { r, items: [] }; g.items.push(e); groups.set(r.abs, g);
  }
  if (groups.size > policy.fs.maxEditFiles) throw new PolicyError("too_many_files", `edit touches ${groups.size} files; limit is ${policy.fs.maxEditFiles}`);

  // PHASE 1 — compute everything in memory. Any failure here leaves the disk untouched.
  const staged: Staged[] = []; const warnings: string[] = [];
  for (const { r, items } of groups.values()) {
    const st = fs.lstatSync(r.abs);
    if (!st.isFile()) throw new PolicyError("not_a_file", `not a regular file: ${path.relative(r.root, r.abs)}`);
    const orig = readBytesNoFollow(r.abs, policy.fs.maxWriteBytes);
    if (looksBinary(orig)) throw new PolicyError("binary_file", `refusing to edit binary file: ${path.relative(r.root, r.abs)}`);
    let text: string;
    try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(orig); } catch { throw new PolicyError("not_utf8", `file is not valid UTF-8; refusing to edit (would corrupt it): ${path.relative(r.root, r.abs)}`); }
    const bom = text.charCodeAt(0) === 0xfeff; if (bom) text = text.slice(1);
    const origSha = sha(orig); const eol = detectEol(text); const rel = path.relative(r.root, r.abs);
    for (const it of items) if (it.if_hash && it.if_hash !== origSha) throw new PolicyError("hash_mismatch", `${rel} changed since it was read (if_hash mismatch); re-read it`);
    const before = text;
    items.forEach((it, n) => {
      if (it.old_str === "") throw new PolicyError("empty_old_str", `${rel} edit #${n + 1}: old_str is empty`);
      let o = it.old_str, w = it.new_str;
      if (eol === "crlf" && !o.includes("\r")) { o = o.replace(/\n/g, "\r\n"); w = w.replace(/\r?\n/g, "\r\n"); }
      if (o === w) throw new PolicyError("noop_edit", `${rel} edit #${n + 1}: old_str equals new_str`);
      const idx = indicesOf(text, o);
      if (idx.length === 0) {
        const first = it.old_str.split(/\r?\n/).map(s => s.trim()).find(Boolean) ?? "";
        const hints = first ? text.split(/\r?\n/).flatMap((l, i) => (l.includes(first) ? [i + 1] : [])).slice(0, 5) : [];
        throw new PolicyError("no_match", `${rel} edit #${n + 1}: old_str not found (whitespace/indentation must match exactly).${hints.length ? ` First line of old_str appears at line(s): ${hints.join(", ")}.` : ""}`);
      }
      if (idx.length > 1 && !it.replace_all) throw new PolicyError("ambiguous", `${rel} edit #${n + 1}: old_str matches ${idx.length} times (lines ${idx.slice(0, 6).map(i => lineOf(text, i)).join(", ")}${idx.length > 6 ? ", …" : ""}). Add surrounding context or set replace_all=true.`);
      warnings.push(...enforceSecrets(policy, it.new_str, `${rel} edit #${n + 1} new_str`));
      text = it.replace_all ? text.split(o).join(w) : text.slice(0, idx[0]) + w + text.slice(idx[0] + o.length); // never String.replace: "$&" in new_str must stay literal
    });
    if (text === before) throw new PolicyError("noop_edit", `${rel}: edits produce no change`);
    const next = Buffer.from((bom ? "\ufeff" : "") + text, "utf8");
    if (next.length > policy.fs.maxWriteBytes) throw new PolicyError("too_large", `${rel}: result is ${next.length} bytes; limit is ${policy.fs.maxWriteBytes}`);
    staged.push({ rel, abs: r.abs, orig, origSha, next, mode: st.mode, diff: miniDiff(rel, before, text) });
  }

  const summary = staged.map(s => s.diff).join("\n\n");
  const wtxt = warnings.length ? `\nWARNINGS:\n- ${warnings.join("\n- ")}` : "";
  if (a.dry_run) return `DRY RUN — nothing written (${staged.length} file(s))\n\n${summary}${wtxt}`;

  // PHASE 2 — verify nothing changed on disk, then commit with rollback.
  testHooks.beforeCommit?.();
  for (const s of staged) {
    const now = readBytesNoFollow(s.abs, Math.max(policy.fs.maxWriteBytes, s.orig.length) + 1);
    if (sha(now) !== s.origSha) throw new PolicyError("changed_on_disk", `${s.rel} was modified by something else while the edit was being prepared; nothing was written`);
  }
  const done: Staged[] = [];
  try {
    staged.forEach((s, i) => {
      if (testHooks.failAfterWrites !== null && i === testHooks.failAfterWrites) throw new Error("injected failure");
      atomicWrite(s.abs, s.next, s.mode, false); done.push(s);
    });
  } catch (err) {
    const failedRollback: string[] = [];
    for (const s of done.reverse()) { try { atomicWrite(s.abs, s.orig, s.mode, false); } catch { failedRollback.push(s.rel); } }
    throw new Error(`edit failed (${(err as Error).message}); ${done.length ? (failedRollback.length ? `ROLLBACK INCOMPLETE for: ${failedRollback.join(", ")}` : "all earlier writes rolled back") : "nothing was written"}`);
  }
  return `APPLIED ${staged.length} file(s)\n${staged.map(s => `${s.rel} | sha256=${sha(s.next)}`).join("\n")}\n\n${summary}${wtxt}`;
}
