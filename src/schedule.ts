// AI-generated (Claude, Anthropic), 2026-11-18. Requires human security review before production use.
/**
 * ht_schedule — sunucu tarafında gecikmeli araç çağrısı.
 *
 * Kabuktan yapılamaz: kabuk MCP araçlarını çağıramaz. Bu araç, aynı oturumun politika ve
 * denetim yolundan geçen bir çağrıyı ileri bir ana planlar; sonucu oturum belleğinde tutar.
 */
import { PolicyError } from "./guard.js";
import type { Persist } from "./persist.js";

const MAX_ITEMS = 20;
const MAX_DELAY_S = 3600;
const MAX_RESULT = 8 << 10;
const FORBIDDEN = new Set(["ht_schedule", "ht_user_input", "ht_ask", "ht_stop_new"]);

export interface SchedResult { isError?: boolean; content?: { type: string; text?: string }[] }
export interface SchedItem {
  id: string; tool: string; args: Record<string, unknown>; created: number; run_at: number;
  status: "pending" | "running" | "done" | "error" | "cancelled"; result?: string; error?: string; ms?: number;
}

const textOf = (r: SchedResult | string): string => {
  if (typeof r === "string") return r;
  const t = (r.content ?? []).map(c => c.text ?? "").join("\n");
  return t.length > MAX_RESULT ? t.slice(0, MAX_RESULT) + `\n… (${t.length - MAX_RESULT} bytes truncated)` : t;
};

const GRACE_S = 120; // yeniden başlatmadan sonra bu kadar gecikmiş iş hemen çalıştırılır

export class Scheduler {
  private items: SchedItem[] = [];
  private seq = 0;
  constructor(private run: (tool: string, args: Record<string, unknown>) => Promise<SchedResult | string>, private persist?: Persist) {
    const saved = persist?.read<SchedItem[]>([]) ?? [];
    const now = Date.now();
    for (const it of saved.slice(-MAX_ITEMS)) {
      if (!it || typeof it.tool !== "string" || it.status !== "pending") { this.items.push(it); continue; }
      this.seq = Math.max(this.seq, Number(String(it.id).replace(/^s/, "")) || 0);
      const late = (now - it.run_at) / 1000;
      if (late > GRACE_S) { this.items.push({ ...it, status: "error", error: `missed: sunucu yeniden başladı (${Math.round(late)}s gecikme)` }); continue; }
      this.items.push(it);
      const timer = setTimeout(() => { void this.fire(it); }, Math.max(0, it.run_at - now));
      (timer as unknown as { unref?: () => void }).unref?.();
    }
    this.save();
  }
  private save() { this.persist?.write(this.items.slice(-MAX_ITEMS)); }

  add(available: Set<string>, tool: string, args: Record<string, unknown>, afterS: number, maxDelayS = MAX_DELAY_S): SchedItem {
    if (!available.has(tool)) throw new PolicyError("bad_input", `bilinmeyen ya da kapalı araç: ${tool}`);
    if (FORBIDDEN.has(tool)) throw new PolicyError("bad_input", `${tool} zamanlanamaz`);
    if (!Number.isFinite(afterS) || afterS < 0) throw new PolicyError("bad_input", "after_s 0 ile " + maxDelayS + " arasında olmalı");
    const delay = Math.min(Math.round(afterS), Math.min(maxDelayS, MAX_DELAY_S));
    const live = this.items.filter(i => i.status === "pending" || i.status === "running");
    if (live.length >= MAX_ITEMS) throw new PolicyError("busy", `bekleyen iş sınırı (${MAX_ITEMS})`);
    const item: SchedItem = { id: `s${++this.seq}`, tool, args, created: Date.now(), run_at: Date.now() + delay * 1000, status: "pending" };
    this.items.push(item);
    const timer = setTimeout(() => { void this.fire(item); }, delay * 1000);
    (timer as unknown as { unref?: () => void }).unref?.();
    this.save();
    return item;
  }

  private async fire(item: SchedItem) {
    if (item.status !== "pending") return;
    item.status = "running";
    const t0 = Date.now();
    try { item.result = textOf(await this.run(item.tool, item.args)); item.status = "done"; }
    catch (e) { item.error = (e as Error).message.slice(0, 400); item.status = "error"; }
    item.ms = Date.now() - t0;
    this.save();
  }

  list(): SchedItem[] { return this.items.slice(-MAX_ITEMS); }
  collect(ids?: string[]): SchedItem[] {
    const done = this.items.filter(i => i.status === "done" || i.status === "error");
    const picked = ids?.length ? done.filter(i => ids.includes(i.id)) : done;
    this.items = this.items.filter(i => !picked.includes(i));
    this.save();
    return picked;
  }
  cancel(id: string): boolean {
    const it = this.items.find(i => i.id === id);
    if (!it || it.status !== "pending") return false;
    it.status = "cancelled"; this.save(); return true;
  }
  get pending(): number { return this.items.filter(i => i.status === "pending" || i.status === "running").length; }
}

export interface ScheduleArgs {
  action?: "add" | "list" | "collect" | "cancel";
  tool?: string; arguments?: Record<string, unknown>; after_s?: number; id?: string; ids?: string[];
}

export function htSchedule(s: Scheduler, available: Set<string>, a: ScheduleArgs, maxDelayS?: number): string {
  const action = a.action ?? "list";
  if (action === "add") {
    if (typeof a.tool !== "string" || !a.tool) throw new PolicyError("bad_input", "tool gerekli");
    const it = s.add(available, a.tool, a.arguments ?? {}, a.after_s ?? 0, maxDelayS);
    return `SCHEDULED ${it.id}: ${it.tool} @ ${new Date(it.run_at).toISOString().slice(11, 19)}Z (${Math.round((it.run_at - Date.now()) / 1000)}s)`;
  }
  if (action === "cancel") {
    if (!a.id) throw new PolicyError("bad_input", "id gerekli");
    return s.cancel(a.id) ? `CANCELLED ${a.id}` : `NOT CANCELLED ${a.id} (yok ya da çalışmaya başladı)`;
  }
  if (action === "collect") {
    const got = s.collect(a.ids);
    if (!got.length) return "COLLECT: tamamlanmış iş yok.";
    return got.map(i => `${i.id} ${i.tool} · ${i.status}${i.ms != null ? ` · ${i.ms}ms` : ""}${i.error ? ` · ${i.error}` : ""}\n${i.result ?? ""}`).join("\n---\n");
  }
  const items = s.list();
  if (!items.length) return "SCHEDULE: iş yok.";
  return `SCHEDULE: ${s.pending} bekleyen\n${items.map(i => `${i.id} ${i.status.padEnd(9)} ${i.tool} @ ${new Date(i.run_at).toISOString().slice(11, 19)}Z${i.ms != null ? ` (${i.ms}ms)` : ""}`).join("\n")}`;
}
