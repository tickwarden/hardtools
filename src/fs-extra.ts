// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
// Shell-free replacements for find / mkdir / mv / rm. Same confinement as fs-tools.ts (resolveSafe on every path).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";
import { PolicyError, globToRegExp, isDeniedRead, isDeniedWrite, isInside, resolveSafe, type Resolved } from "./guard.js";

export const TRASH_DIR = ".ht-trash";
const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", ".gradle", ".idea", ".mypy_cache", ".pytest_cache", TRASH_DIR]);
const MAX_VISITED = 200_000;
const MAX_COLLECT = 50_000;

const relParts = (r: Resolved) => path.relative(r.root, r.abs).split(path.sep).filter(Boolean);

/** Version-control metadata and the trash itself are never moved/trashed/created through these tools. */
function assertNotProtectedTree(policy: Policy, r: Resolved, what: string): void {
  if ([...policy.roots, ...policy.protectedDirs].some(d => isInside(r.abs, d))) throw new PolicyError("is_root", `cannot ${what} an allowed root or the parent of a protected directory`);
  const parts = relParts(r);
  if (parts.includes(".git")) throw new PolicyError("vcs_protected", `paths inside .git are protected (${what})`);
  if (parts[0] === TRASH_DIR && parts.length === 1) throw new PolicyError("trash_protected", `the trash directory itself cannot be modified (${what})`);
}

/** resolveSafe() realpaths the last component, so a symlink would silently be replaced by its target. Refuse instead. */
function refuseSymlinkSource(policy: Policy, input: string): void {
  let st: fs.Stats | null = null;
  try { st = fs.lstatSync(path.resolve(policy.roots[0], input)); } catch { /* resolveSafe reports not_found later */ }
  if (st?.isSymbolicLink()) throw new PolicyError("symlink_source", "source is a symlink; refusing (it would be resolved to its target). Operate on the real path.");
}

/* -------------------------------- ht_glob -------------------------------- */
export interface GlobArgs { pattern: string; path?: string; type?: "file" | "dir" | "any"; sort?: "name" | "mtime"; max_results?: number; include_hidden?: boolean }

export function htGlob(policy: Policy, a: GlobArgs): string {
  if (typeof a.pattern !== "string" || a.pattern.length < 1 || a.pattern.length > 500) throw new PolicyError("bad_pattern", "pattern must be 1–500 chars");
  if (a.pattern.startsWith("/") || a.pattern.split("/").includes("..") || a.pattern.includes("\0")) throw new PolicyError("bad_pattern", "pattern must be relative and must not contain '..'");
  const base = resolveSafe(policy, a.path ?? ".", "read");
  if (!fs.lstatSync(base.abs).isDirectory()) throw new PolicyError("not_a_dir", "path is not a directory");
  const pat = a.pattern.includes("/") ? a.pattern.replace(/^\.\//, "") : "**/" + a.pattern; // bare names match at any depth
  const rx = globToRegExp(pat);
  const want = a.type ?? "file";
  const limit = Math.min(a.max_results ?? 200, 2000);
  const deadline = Date.now() + policy.search.timeBudgetMs;

  type Hit = { rel: string; dir: boolean; size: number; mtime: number };
  const hits: Hit[] = []; let visited = 0, hidden = 0, symlinks = 0; let cut: string | null = null;
  const stack: string[] = [base.abs];
  while (stack.length && !cut) {
    const dir = stack.pop()!;
    if (Date.now() > deadline) { cut = `time budget (${policy.search.timeBudgetMs} ms)`; break; }
    let ents: fs.Dirent[];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const d of ents) {
      if (++visited > MAX_VISITED) { cut = `visit cap (${MAX_VISITED} entries)`; break; }
      if (d.isSymbolicLink()) { symlinks++; continue; } // never followed, never listed
      if (!a.include_hidden && d.name.startsWith(".")) continue;
      const abs = path.join(dir, d.name);
      if (isDeniedRead(policy, abs)) { hidden++; continue; }
      const rel = path.relative(base.abs, abs).split(path.sep).join("/");
      if (d.isDirectory()) {
        if (SKIP_DIRS.has(d.name)) continue;
        stack.push(abs);
        if ((want === "dir" || want === "any") && rx.test(rel)) { const s = fs.lstatSync(abs); hits.push({ rel: rel + "/", dir: true, size: 0, mtime: s.mtimeMs }); }
      } else if (d.isFile() && (want === "file" || want === "any") && rx.test(rel)) {
        const s = fs.lstatSync(abs); hits.push({ rel, dir: false, size: s.size, mtime: s.mtimeMs });
      }
      if (hits.length >= MAX_COLLECT) { cut = `match cap (${MAX_COLLECT})`; break; }
    }
  }
  hits.sort(a.sort === "mtime" ? (x, y) => y.mtime - x.mtime || x.rel.localeCompare(y.rel) : (x, y) => x.rel.localeCompare(y.rel));
  const shown = hits.slice(0, limit);
  const head = `GLOB ${JSON.stringify(a.pattern)} in ${path.relative(base.root, base.abs) || "."} | ${hits.length} match(es)${hits.length > shown.length ? ` (showing ${shown.length})` : ""} | visited=${visited}`
    + `${hidden ? ` | ${hidden} protected hidden` : ""}${symlinks ? ` | ${symlinks} symlinks skipped` : ""}${cut ? ` | PARTIAL: stopped at ${cut}` : ""}`;
  return `${head}\n${shown.map(h => h.dir ? h.rel : `${h.rel}\t${h.size} B\t${new Date(h.mtime).toISOString()}`).join("\n")}`;
}

/* -------------------------------- ht_mkdir ------------------------------- */
export function htMkdir(policy: Policy, a: { path: string }): string {
  const r = resolveSafe(policy, a.path, "write");
  assertNotProtectedTree(policy, r, "create a directory in");
  if (r.exists) {
    if (fs.lstatSync(r.abs).isDirectory()) return `OK ${path.relative(r.root, r.abs) || "."} already exists (directory)`;
    throw new PolicyError("exists", "a non-directory already exists at that path");
  }
  fs.mkdirSync(r.abs, { recursive: true, mode: 0o755 });
  return `CREATED ${path.relative(r.root, r.abs)}/`;
}

/* -------------------------------- ht_move -------------------------------- */
export function htMove(policy: Policy, a: { from: string; to: string; mkdirp?: boolean }): string {
  refuseSymlinkSource(policy, a.from);
  const src = resolveSafe(policy, a.from, "write");
  if (!src.exists) throw new PolicyError("not_found", `source does not exist: ${a.from}`);
  assertNotProtectedTree(policy, src, "move");
  const st = fs.lstatSync(src.abs);
  if (!st.isFile() && !st.isDirectory()) throw new PolicyError("unsupported_type", "only regular files and directories can be moved");
  const dst = resolveSafe(policy, a.to, "write");
  if (dst.exists) throw new PolicyError("exists", "destination already exists; moves never overwrite (give the full new path, not a target directory)");
  assertNotProtectedTree(policy, dst, "move into");
  if (st.isDirectory() && isInside(src.abs, dst.abs)) throw new PolicyError("into_self", "cannot move a directory into itself");
  const parent = path.dirname(dst.abs);
  if (!fs.existsSync(parent)) {
    if (!a.mkdirp) throw new PolicyError("no_parent", "destination directory does not exist (set mkdirp=true)");
    fs.mkdirSync(parent, { recursive: true });
  }
  try {
    if (st.isFile()) { fs.linkSync(src.abs, dst.abs); fs.unlinkSync(src.abs); } // link() fails with EEXIST: atomic no-clobber
    else { if (fs.existsSync(dst.abs)) throw new PolicyError("exists", "destination already exists"); fs.renameSync(src.abs, dst.abs); }
  } catch (e: any) {
    if (e instanceof PolicyError) throw e;
    if (e.code === "EEXIST") throw new PolicyError("exists", "destination already exists");
    if (e.code === "EXDEV") throw new PolicyError("cross_device", "source and destination are on different filesystems");
    throw e;
  }
  return `MOVED ${path.relative(src.root, src.abs)} -> ${path.relative(dst.root, dst.abs)} (${st.isDirectory() ? "directory" : `file, ${st.size} B`})`;
}

/* -------------------------------- ht_trash ------------------------------- */
/** Reversible "delete": moves the target into <root>/.ht-trash/ and logs the original path. Only ht_empty_trash can purge the trash. */
export function htTrash(policy: Policy, a: { path: string; recursive?: boolean }): string {
  refuseSymlinkSource(policy, a.path);
  const src = resolveSafe(policy, a.path, "write");
  if (!src.exists) throw new PolicyError("not_found", `does not exist: ${a.path}`);
  assertNotProtectedTree(policy, src, "trash");
  const parts = relParts(src);
  if (parts[0] === TRASH_DIR) throw new PolicyError("already_in_trash", "item is already in the trash; use ht_empty_trash to purge the trash");
  const st = fs.lstatSync(src.abs);
  if (!st.isFile() && !st.isDirectory()) throw new PolicyError("unsupported_type", "only regular files and directories can be trashed");
  if (st.isDirectory() && !a.recursive) throw new PolicyError("needs_recursive", "target is a directory; pass recursive=true to trash it with all its contents");

  const trashDir = path.join(src.root, TRASH_DIR);
  try { fs.mkdirSync(trashDir, { mode: 0o700 }); } catch (e: any) { if (e.code !== "EEXIST") throw e; }
  if (!fs.lstatSync(trashDir).isDirectory()) throw new PolicyError("trash_invalid", `${TRASH_DIR} exists but is not a real directory`);
  const safeName = path.basename(src.abs).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 100) || "item";
  const name = `${Date.now()}-${crypto.randomBytes(3).toString("hex")}-${safeName}`;
  const dst = resolveSafe(policy, path.join(trashDir, name), "write");
  const manifest = path.join(trashDir, "index.jsonl");
  if (resolveSafe(policy, manifest, "write").abs !== manifest) throw new PolicyError("trash_invalid", "invalid trash index");
  const fd = fs.openSync(manifest, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0), 0o600);
  const original = path.relative(src.root, src.abs);
  try {
    const index = fs.fstatSync(fd);
    if (!index.isFile() || index.nlink !== 1) throw new PolicyError("trash_invalid", "trash index must be a regular, single-link file");
    try { fs.renameSync(src.abs, dst.abs); }
    catch (e: any) { if (e.code === "EXDEV") throw new PolicyError("cross_device", "trash is on a different filesystem than the target"); throw e; }
    try { fs.writeFileSync(fd, JSON.stringify({ ts: new Date().toISOString(), name, original, kind: st.isDirectory() ? "dir" : "file" }) + "\n"); }
    catch (err) { fs.renameSync(dst.abs, src.abs); throw err; }
  } finally { fs.closeSync(fd); }
  return `TRASHED ${original} -> ${TRASH_DIR}/${name}\nRestore with ht_move from=${JSON.stringify(`${TRASH_DIR}/${name}`)} to=${JSON.stringify(original)}`;
}

/** The caller selects an actual configured root, never the directory to delete. Keep the trash directory. */
export function htEmptyTrash(policy: Policy, a: { root?: string; confirm?: boolean }): string {
  const root = resolveSafe(policy, a.root ?? ".", "write").abs;
  if (!policy.roots.includes(root)) throw new PolicyError("not_a_root", "select a configured root, not an arbitrary directory");
  const dir = path.join(root, TRASH_DIR);
  const checked = resolveSafe(policy, dir, "write");
  if (checked.abs !== dir || [...policy.roots, ...policy.protectedDirs].some(d => isInside(dir, d)))
    throw new PolicyError("trash_invalid", "trash is a link or overlaps a protected directory");
  if (!checked.exists) return "EMPTY: no trash directory; nothing deleted";
  if (!fs.lstatSync(dir).isDirectory()) throw new PolicyError("trash_invalid", "trash is not a real directory");
  const entries = fs.readdirSync(dir);
  const names = entries.filter(n => n !== "index.jsonl");
  if (a.confirm !== true) return `PREVIEW: ${names.length} item(s); nothing deleted. To permanently empty this trash and clear its index, set confirm=true.`;
  // Preflight the whole deletion before touching anything. Never follow links or cross
  // devices. Unlink/rmdir explicit entries rather than recursively deleting a supplied path.
  const device = fs.lstatSync(dir).dev;
  const pending = [...names, ...entries.filter(n => n === "index.jsonl")].map(n => path.join(dir, n)); // visit index first, delete it last
  const ordered: { abs: string; dir: boolean }[] = [];
  while (pending.length) {
    if (ordered.length + pending.length > 50_000) throw new PolicyError("trash_limit", "too many entries for one purge");
    const abs = pending.pop()!;
    if (isDeniedWrite(policy, abs) || fs.realpathSync.native(path.dirname(abs)) !== path.dirname(abs))
      throw new PolicyError("trash_protected", "trash contains a protected or changed path; nothing deleted");
    const st = fs.lstatSync(abs);
    if (st.dev !== device) throw new PolicyError("trash_mount", "refusing to cross a filesystem boundary");
    ordered.push({ abs, dir: st.isDirectory() });
    if (st.isDirectory()) for (const name of fs.readdirSync(abs)) pending.push(path.join(abs, name));
  }
  for (const item of ordered.reverse()) {
    if (fs.realpathSync.native(path.dirname(item.abs)) !== path.dirname(item.abs)) throw new PolicyError("trash_changed", "trash changed during purge");
    if (item.dir) fs.rmdirSync(item.abs); else fs.unlinkSync(item.abs);
  }
  return `EMPTIED: ${names.length} item(s); trash directory preserved`;
}
