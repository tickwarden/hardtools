import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";
import { PolicyError, resolveSafe } from "./guard.js";
import { readBytesNoFollow } from "./fs-tools.js";

export const TRASH_DIR = ".ht-trash", INDEX = "index.jsonl";
export interface TrashRow { name: string; original: string; ts: string; kind: "file" | "dir" }
const MAX_INDEX = 16 << 20;

/** Row paths are metadata, never filesystem instructions. Count real directory entries first. */
export function readTrashIndex(p: Policy, root: string, entries: string[]) {
  const manifest = path.join(root, TRASH_DIR, INDEX);
  const present = new Set(entries), active = new Map<string, TrashRow>();
  const idx = resolveSafe(p, manifest, "read");
  if (idx.abs !== manifest) throw new PolicyError("trash_invalid", "invalid trash index link");
  let total = 0;
  if (idx.exists) {
    const data = readBytesNoFollow(manifest, MAX_INDEX, true).toString("utf8");
    for (const line of data.split("\n")) {
      if (!line) continue;
      let row: TrashRow;
      try { row = JSON.parse(line); } catch { throw new PolicyError("trash_invalid", "invalid trash index JSONL"); }
      if (!row || typeof row.name !== "string" || typeof row.original !== "string" || !["file", "dir"].includes(row.kind))
        throw new PolicyError("trash_invalid", "invalid trash index record");
      total++;
      if (present.has(row.name)) active.set(row.name, row);
    }
  }
  return { manifest, active, stale: total - active.size, untracked: entries.length - active.size };
}

/** Serialize independent hardtools processes sharing this root. Preview never takes a lock. */
export function withTrashLock<T>(p: Policy, root: string, fn: () => T): T {
  const lockPath = path.join(root, ".ht-trash-index.lock");
  if (resolveSafe(p, lockPath, "write").abs !== lockPath) throw new PolicyError("trash_invalid", "invalid trash lock path");
  let lock: number;
  try { lock = fs.openSync(lockPath, "wx", 0o600); }
  catch (e: any) {
    if (e.code === "EEXIST") throw new PolicyError("trash_busy", "another operation holds the trash lock");
    throw e;
  }
  try { return fn(); }
  finally { fs.closeSync(lock); fs.unlinkSync(lockPath); }
}

/** Stage and fsync before moving anything; publish by rename. Roll back if publication fails. */
export function updateTrashIndex(p: Policy, root: string, edit: (rows: Map<string, TrashRow>) => void, move: () => void, undo: () => void) {
  withTrashLock(p, root, () => {
    const dir = path.join(root, TRASH_DIR);
    if (resolveSafe(p, dir, "write").abs !== dir || !fs.lstatSync(dir).isDirectory()) throw new PolicyError("trash_invalid", "invalid trash directory");
    const entries = fs.readdirSync(dir).filter(n => n !== INDEX);
    const { manifest, active } = readTrashIndex(p, root, entries);
    resolveSafe(p, manifest, "write");
    edit(active);
    const data = [...active.values()].map(r => JSON.stringify(r) + "\n").join("");
    if (Buffer.byteLength(data) > MAX_INDEX) throw new PolicyError("trash_limit", "trash index size limit reached");
    const tmp = path.join(root, `.ht-trash-index-${crypto.randomUUID()}.tmp`);
    const fd = fs.openSync(tmp, "wx", 0o600);
    try {
      try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      move();
      try { fs.renameSync(tmp, manifest); }
      catch (e) {
        try { undo(); } catch { throw new PolicyError("trash_recovery", "cannot publish index or undo move; inspect source, destination and index"); }
        throw e;
      }
    } finally { fs.rmSync(tmp, { force: true }); }
  });
}
