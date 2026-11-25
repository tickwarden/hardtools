// AI-generated (Claude, Anthropic), 2026-11-18. Requires human security review before production use.
/**
 * ht_undo — araç çağrılarının dosya etkilerini geri alır.
 *
 * Kabuktan yapılamaz: geri alma bilgisi (hangi araç hangi yolu değiştirdi, öncesinde ne vardı)
 * yalnızca sunucunun araç çağrısı kaydında bulunur. Kabuk, geçmiş bir araç çağrısının
 * değiştirdiği dosyaların önceki hâlini bilemez.
 */
import fs from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";
import { PolicyError, isInside, resolveSafe } from "./guard.js";
import type { Persist } from "./persist.js";

const MAX_OPS = 10;              // hesap başına saklanan işlem sayısı
const MAX_OP_BYTES = 4 << 20;    // tek işlem için en çok 4 MiB ön görüntü
const MAX_FILES = 400;           // tek işlemde en çok 400 dosya
const SKIP = new Set([".git", ".ht-trash", "node_modules"]);

export interface Snapshot { path: string; kind: "file" | "dir"; data?: Buffer; mode?: number }
export interface JournalEntry { tool: string; at: number; paths: string[]; snaps: Snapshot[]; complete: boolean; reason?: string }

/** Bir yolun (klasörse içeriğinin) ön görüntüsünü al. Sınır aşılırsa complete=false. */
function captureAbs(policy: Policy, abs: string, rel: string, out: Snapshot[], budget: { bytes: number; files: number }) {
  const st = fs.lstatSync(abs);
  if (st.isSymbolicLink()) { budget.files++; return; }          // symlink geri yüklenmez (güvenlik)
  if (st.isDirectory()) {
    out.push({ path: rel, kind: "dir", mode: st.mode & 0o777 });
    for (const name of fs.readdirSync(abs).sort()) {
      if (SKIP.has(name)) continue;
      captureAbs(policy, path.join(abs, name), path.join(rel, name), out, budget);
    }
    return;
  }
  if (!st.isFile()) { budget.files++; return; }
  budget.files++; budget.bytes += st.size;
  if (budget.files > MAX_FILES || budget.bytes > MAX_OP_BYTES) return;
  out.push({ path: rel, kind: "file", data: fs.readFileSync(abs), mode: st.mode & 0o777 });
}

/** Araç argümanlarından etkilenecek yolları çıkar (ht_undo'nun kaydı için). */
export function touchedPaths(tool: string, args: Record<string, unknown>): string[] {
  const out: string[] = [], push = (v: unknown) => { if (typeof v === "string" && v) out.push(v); };
  if (tool === "ht_write" || tool === "ht_mkdir" || tool === "ht_trash") push(args.path);
  if (tool === "ht_move") { push(args.from); push(args.to); }
  if (tool === "ht_edit" && Array.isArray(args.edits)) for (const e of args.edits as { path?: unknown }[]) push(e?.path);
  return out;
}

type StoredEntry = { tool: string; at: number; paths: string[]; complete: boolean; reason?: string;
  snaps: { path: string; kind: "file" | "dir"; b64?: string; mode?: number }[] };

export class UndoJournal {
  private byOwner = new Map<string, JournalEntry[]>();
  constructor(private persist?: Persist) {
    const saved = persist?.read<Record<string, StoredEntry[]>>({}) ?? {};
    for (const [owner, list] of Object.entries(saved)) {
      if (!Array.isArray(list)) continue;
      this.byOwner.set(owner, list.slice(-MAX_OPS).map(e => ({
        tool: e.tool, at: e.at, paths: e.paths ?? [], complete: Boolean(e.complete), reason: e.reason,
        snaps: (e.snaps ?? []).map(sn => ({ path: sn.path, kind: sn.kind, mode: sn.mode, ...(sn.b64 ? { data: Buffer.from(sn.b64, "base64") } : {}) })),
      })));
    }
  }
  private save() {
    if (!this.persist) return;
    const out: Record<string, StoredEntry[]> = {};
    for (const [owner, list] of this.byOwner)
      out[owner] = list.map(e => ({ tool: e.tool, at: e.at, paths: e.paths, complete: e.complete, reason: e.reason,
        snaps: e.snaps.map(sn => ({ path: sn.path, kind: sn.kind, mode: sn.mode, ...(sn.data ? { b64: sn.data.toString("base64") } : {}) })) }));
    this.persist.write(out);
  }

  /** Çağrı öncesi durumu kaydet. Hata yutulur: geri alma asla ana işlemi engellemez. */
  record(policy: Policy, owner: string, tool: string, args: Record<string, unknown>): void {
    const raw = touchedPaths(tool, args);
    if (!raw.length) return;
    const snaps: Snapshot[] = [];
    const budget = { bytes: 0, files: 0 };
    const seen = new Set<string>();
    let complete = true;
    for (const input of raw) {
      let r;
      try { r = resolveSafe(policy, input, "write"); } catch { complete = false; continue; }
      if (seen.has(r.abs)) continue;
      seen.add(r.abs);
      if (r.exists) {
        try { captureAbs(policy, r.abs, r.abs, snaps, budget); } catch { complete = false; }
      } else snaps.push({ path: r.abs, kind: "file" });          // sonradan oluşacak: geri almada silinir
    }
    if (budget.bytes > MAX_OP_BYTES || budget.files > MAX_FILES) complete = false;
    const stack = this.byOwner.get(owner) ?? [];
    stack.push({ tool, at: Date.now(), paths: raw, snaps: complete ? snaps : [], complete, reason: complete ? undefined : "snapshot_limit" });
    while (stack.length > MAX_OPS) stack.shift();
    this.byOwner.set(owner, stack);
    this.save();
  }

  list(owner: string): JournalEntry[] { return this.byOwner.get(owner) ?? []; }
  last(owner: string): JournalEntry | undefined { return this.list(owner).at(-1); }
  pop(owner: string): JournalEntry | undefined { const s = this.byOwner.get(owner) ?? []; const e = s.pop(); this.byOwner.set(owner, s); this.save(); return e; }
  /** Çağrı reddedildi/başarısız olduysa son kaydı at (geri alınacak bir etki yok). */
  dropLast(owner: string): void { const s2 = this.byOwner.get(owner); if (s2?.length) { s2.pop(); this.byOwner.set(owner, s2); this.save(); } }
  clear(owner: string): number { const n = this.list(owner).length; this.byOwner.set(owner, []); this.save(); return n; }
}

const rel = (policy: Policy, abs: string) => policy.roots.map(r => isInside(r, abs) ? path.relative(r, abs) || "." : null).find(Boolean) ?? abs;
const human = (e: JournalEntry) => `${new Date(e.at).toISOString().replace("T", " ").slice(0, 19)} · ${e.tool} · ${e.paths.length} path(s)${e.complete ? "" : ` · NOT UNDOABLE (${e.reason})`}`;

export interface UndoArgs { action?: "undo" | "list" | "clear" }

export function htUndo(policy: Policy, journal: UndoJournal, owner: string, a: UndoArgs): string {
  const action = a.action ?? "list";
  if (action === "list") {
    const items = journal.list(owner);
    if (!items.length) return "UNDO: kayıt yok (bu oturumda dosya değiştiren araç çağrısı görülmedi).";
    return `UNDO: ${items.length} işlem (en yenisi sonda)\n${items.map((e, i) => `${i + 1}. ${human(e)}`).join("\n")}`;
  }
  if (action === "clear") return `UNDO: ${journal.clear(owner)} kayıt temizlendi.`;
  if (action !== "undo") throw new PolicyError("bad_input", "action: undo|list|clear");
  if (!policy.fs.writeEnabled) throw new PolicyError("write_disabled", "geri alma yazma izni ister (politika kapalı)");
  const entry = journal.pop(owner);
  if (!entry) return "UNDO: geri alınacak işlem yok.";
  if (!entry.complete) return `UNDO: son işlem geri alınamaz (${entry.reason}): ${entry.paths.join(", ")}`;
  const done: string[] = [], failed: string[] = [];
  for (const s of [...entry.snaps].reverse()) {
    let target;
    try { target = resolveSafe(policy, s.path, "write"); } catch (e) { failed.push(`${rel(policy, s.path)} (${(e as PolicyError).code ?? "error"})`); continue; }
    try {
      if (s.kind === "dir") { fs.mkdirSync(target.abs, { recursive: true, mode: s.mode ?? 0o755 }); continue; }
      if (!s.data) {                                            // işlemden önce yoktu → oluşturulanı sil
        if (fs.existsSync(target.abs)) {
          const st = fs.lstatSync(target.abs);
          if (st.isDirectory()) fs.rmdirSync(target.abs);
          else fs.unlinkSync(target.abs);
          done.push(`- ${rel(policy, target.abs)}`);
        }
        continue;
      }
      fs.mkdirSync(path.dirname(target.abs), { recursive: true });
      const tmp = `${target.abs}.undo-${process.pid}`;
      fs.writeFileSync(tmp, s.data, { mode: s.mode ?? 0o644 });
      fs.renameSync(tmp, target.abs);
      done.push(`~ ${rel(policy, target.abs)}`);
    } catch (e) { failed.push(`${rel(policy, s.path)} (${(e as Error).message.slice(0, 60)})`); }
  }
  return `UNDO ${entry.tool}: ${done.length} yol geri alındı${failed.length ? `, ${failed.length} başarısız: ${failed.join(", ")}` : ""}\n${done.join("\n")}`;
}
