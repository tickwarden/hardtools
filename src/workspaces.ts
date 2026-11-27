// AI-generated (Claude, Anthropic), 2026-11-18. Requires human security review before production use.
/**
 * ht_workspace — hangi hesabın hangi çalışma alanında olduğunu gösterir ve eski bir sohbetin
 * kökündeki dosyaları mevcut köke devralmayı sağlar.
 *
 * Neden gerekli: kök kimliği taşıma oturumuna bağlıyken her yeniden bağlanma yeni boş bir dizin
 * açıyor, eski iş diskte kalıp görünmez oluyordu ("her şey sıfırlandı"). Bu araç, sahip olunan
 * tüm kökleri dosya sayısı/boyut/son kullanım ile listeler ve seçilenini mevcut köke taşır.
 */
import fs from "node:fs";
import path from "node:path";
import { PolicyError, isInside } from "./guard.js";

export interface WsEntry {
  rel: string; dir: string; kind: "account" | "session";
  owner?: string; user?: string;
  files: number; bytes: number; lastUsed: number; current: boolean;
}

const MAX_DIRS = 200, MAX_COUNT_FILES = 50_000;
// Kabuk iskeleti (.hardtools) kullanıcı verisi değildir; ölçüme ve listeye girmez.
const SCRATCH = new Set([".hardtools", ".ht-trash", "node_modules", ".recycle"]);
/** Devralmada asla taşınmayan öğeler: kabuk iskeleti (.hardtools), geri dönüşüm kutusu, atık indeksi.
 *  Bunlar kullanıcı verisi değil; taşınırsa kaynak kökün bwrap bağları kırılır
 *  ("bwrap: Can't find source path …/.hardtools/tmp"). */
const NEVER_MOVE = new Set([".hardtools", ".ht-trash", ".recycle", ".ht-owner", ".ht-adopted"]);

/** Bir dizinin (sınırlı) dosya sayısı ve bayt toplamı. Symlink izlenmez. */
export function measure(dir: string): { files: number; bytes: number } {
  let files = 0, bytes = 0;
  const walk = (d: string, depth: number) => {
    if (files >= MAX_COUNT_FILES || depth > 8) return;
    let names: string[]; try { names = fs.readdirSync(d); } catch { return; }
    for (const name of names) {
      if (files >= MAX_COUNT_FILES) return;
      if (SCRATCH.has(name)) continue;
      const abs = path.join(d, name);
      let st; try { st = fs.lstatSync(abs); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(abs, depth + 1);
      else { files++; bytes += st.size; }
    }
  };
  walk(dir, 0);
  return { files, bytes };
}

function readMarker(dir: string): { owner?: string; user?: string } {
  try { return JSON.parse(fs.readFileSync(path.join(dir, ".ht-owner"), "utf8")); } catch { return {}; }
}

export function writeMarker(dir: string, owner: string, user: string): void {
  try { fs.writeFileSync(path.join(dir, ".ht-owner"), JSON.stringify({ owner, user, at: Date.now() }), { mode: 0o600 }); } catch { /* işaret zorunlu değil */ }
}

/** Kök altındaki hesap (a-) ve oturum (u-) dizinlerini listele; eski kayıtlar için sahip `ownerFor` ile çözülür. */
export function scanWorkspaces(base: string, current: string, ownerFor?: (dir: string) => string | undefined): WsEntry[] {
  let names: string[] = [];
  try { names = fs.readdirSync(base); } catch { return []; }
  const out: WsEntry[] = [];
  for (const name of names.slice(0, MAX_DIRS)) {
    if (!/^(a|u)-[0-9a-f]{16}$/.test(name)) continue;
    const dir = path.join(base, name);
    let st; try { st = fs.lstatSync(dir); } catch { continue; }
    if (!st.isDirectory()) continue;
    const m = readMarker(dir), owner = m.owner ?? ownerFor?.(dir);
    const { files, bytes } = measure(dir);
    out.push({ rel: name, dir, kind: name.startsWith("a-") ? "account" : "session", owner, user: m.user, files, bytes, lastUsed: st.mtimeMs, current: path.resolve(dir) === path.resolve(current) });
  }
  return out.sort((a, b) => (b.current ? 1 : 0) - (a.current ? 1 : 0) || b.lastUsed - a.lastUsed);
}

const kb = (n: number) => n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : n < 1 << 30 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
const when = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 16);

/** Eski bir kökün içeriğini hedefe taşı (üzerine yazmadan). Kısmi taşımada kaynak korunur. */
export function adoptInto(from: string, to: string): { moved: number; skipped: number } {
  if (path.resolve(from) === path.resolve(to)) throw new PolicyError("bad_input", "kaynak ve hedef aynı dizin");
  if (!fs.existsSync(from)) throw new PolicyError("not_found", `dizin yok: ${from}`);
  let moved = 0, skipped = 0;
  for (const name of fs.readdirSync(from)) {
    if (NEVER_MOVE.has(name)) continue;
    const src = path.join(from, name), dst = path.join(to, name);
    if (fs.existsSync(dst)) { skipped++; continue; }                       // var olanın üzerine yazma
    try { fs.renameSync(src, dst); moved++; }
    catch {
      try { fs.cpSync(src, dst, { recursive: true, errorOnExist: false, force: false }); fs.rmSync(src, { recursive: true, force: true }); moved++; }
      catch { skipped++; }
    }
  }
  return { moved, skipped };
}

export interface WsArgs { action?: "list" | "adopt"; dir?: string }
export interface WsContext {
  base: string; current: string; user: string;
  entries?: () => WsEntry[];
}

export function htWorkspace(ctx: WsContext, a: WsArgs): string {
  const entries = ctx.entries?.() ?? scanWorkspaces(ctx.base, ctx.current);
  // Kendi dizinleri + (operatör için) sahibi bilinmeyen eski dizinler: "sahip: ?" ile gösterilir,
  // böylece kaybolmuş gibi görünen iş kaybolmaz; başka hesabın dizinleri asla listelenmez.
  const mine = entries.filter(e => e.current || e.user === ctx.user || (ctx.user === "operator" && e.user === undefined));
  if ((a.action ?? "list") === "list") {
    if (!mine.length) return `WORKSPACE: kök ${path.relative(ctx.base, ctx.current) || "."} (boş liste).`;
    const shown = [...mine].sort((x, y) => (y.current ? 1 : 0) - (x.current ? 1 : 0) || y.bytes - x.bytes || y.lastUsed - x.lastUsed);
    const LIMIT = 25, hidden = Math.max(0, shown.length - LIMIT);
    const lines = shown.slice(0, LIMIT).map(e => `${e.current ? "*" : " "} ${e.rel}  ${e.kind === "account" ? "hesap" : "sohbet"}  ${String(e.files).padStart(6)} dosya  ${kb(e.bytes).padStart(9)}  son: ${when(e.lastUsed)}${e.user ? `  hesap: ${e.user}` : ""}`);
    return `WORKSPACE: mevcut kök ${path.relative(ctx.base, ctx.current) || "."} · ${mine.length} dizin ( * = bu sohbetin kökü )\n${lines.join("\n")}${hidden ? `\n… +${hidden} dizin daha (en büyük/en yeni ${LIMIT} tanesi gösterildi; tamamı /workspaces sayfasında)` : ""}\nDevam etmek için: ht_workspace {action:"adopt", dir:"<rel>"} — dosyalar mevcut köke kopyalanır, var olanın üzerine yazılmaz.`;
  }
  if (a.action === "adopt") {
    if (!a.dir || !/^(a|u)-[0-9a-f]{16}$/.test(a.dir)) throw new PolicyError("bad_input", "dir: a-… ya da u-… biçiminde olmalı (listeden seç)");
    const src = path.join(ctx.base, a.dir);
    if (!isInside(ctx.base, src)) throw new PolicyError("bad_input", "dizin taban kökün dışında");
    const entry = entries.find(e => e.rel === a.dir);
    if (!entry) throw new PolicyError("not_found", `dizin listede yok: ${a.dir}`);
    // Sahibi bilinmeyen eski (işaretsiz) dizinler ilk devralan hesaba kilitlenir: devraldıktan
    // sonra sahiplik işareti yazılır, böylece bir daha başka hesaba görünmez.
    const unknown = entry.user === undefined;
    if (!(entry.user === ctx.user || unknown)) throw new PolicyError("denied_path", `bu dizin başka bir hesaba ait (${entry.user}); devralınamaz`);
    const r = adoptInto(src, ctx.current);
    if (unknown) writeMarker(src, "adopted-by:" + ctx.user, ctx.user);
    return `WORKSPACE adopt ${a.dir}: ${r.moved} öğe taşındı, ${r.skipped} atlandı (var olan korunur) → ${path.relative(ctx.base, ctx.current) || "."}`;
  }
  throw new PolicyError("bad_input", "action: list|adopt");
}
