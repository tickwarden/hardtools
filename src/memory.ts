// AI-generated (Claude, Anthropic), 2026-11-18. Requires human security review before production use.
/**
 * ht_memory — hesap kapsamlı, oturum köklerinin DIŞINDA duran not defteri.
 *
 * Kabuktan yapılamaz: her sohbet kendi kökünde çalışır ve bu dosya köklerin dışındadır;
 * kabuk ne yazabilir ne okuyabilir. Yeni bir sohbet, önceki sohbetin bıraktığı notları görür.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PolicyError } from "./guard.js";

const MAX_ENTRIES = 200;
const MAX_VALUE = 8 * 1024;
const MAX_TOTAL = 256 * 1024;

interface Store { entries: { key: string; value: string; updated: number }[] }

export class AccountMemory {
  private dir: string;
  constructor(dir?: string) { this.dir = dir ?? ""; }

  private file(owner: string): string | null {
    if (!this.dir) return null;
    const tag = crypto.createHash("sha256").update(owner.toLowerCase()).digest("hex").slice(0, 16);
    return path.join(this.dir, `${tag}.json`);
  }

  private read(owner: string): Store {
    const f = this.file(owner);
    if (!f) return { entries: [] };
    try { const d = JSON.parse(fs.readFileSync(f, "utf8")); return { entries: Array.isArray(d?.entries) ? d.entries : [] }; }
    catch { return { entries: [] }; }
  }

  private write(owner: string, s: Store) {
    const f = this.file(owner);
    if (!f) throw new PolicyError("memory_unavailable", "not defteri yolu yapılandırılmadı");
    fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 });
    const tmp = `${f}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(s), { mode: 0o600 });
    fs.renameSync(tmp, f);
  }

  set(owner: string, key: string, value: string): number {
    if (!/^[\w.:/-]{1,120}$/.test(key)) throw new PolicyError("bad_input", "key: 1-120 karakter (harf, rakam, _ . : / -)");
    if (Buffer.byteLength(value) > MAX_VALUE) throw new PolicyError("too_large", `değer ${MAX_VALUE} bayt sınırını aşıyor`);
    const s = this.read(owner);
    const now = Date.now();
    const i = s.entries.findIndex(e => e.key === key);
    if (i >= 0) s.entries[i] = { key, value, updated: now };
    else {
      if (s.entries.length >= MAX_ENTRIES) throw new PolicyError("too_many", `en çok ${MAX_ENTRIES} kayıt`);
      s.entries.push({ key, value, updated: now });
    }
    const total = s.entries.reduce((n, e) => n + Buffer.byteLength(e.value), 0);
    if (total > MAX_TOTAL) throw new PolicyError("too_large", `toplam ${MAX_TOTAL} bayt sınırını aşıyor`);
    this.write(owner, s);
    return s.entries.length;
  }

  get(owner: string, key: string): { value: string; updated: number } | undefined {
    return this.read(owner).entries.find(e => e.key === key);
  }

  list(owner: string): { key: string; bytes: number; updated: number }[] {
    return this.read(owner).entries.map(e => ({ key: e.key, bytes: Buffer.byteLength(e.value), updated: e.updated }));
  }

  del(owner: string, key: string): boolean {
    const s = this.read(owner), before = s.entries.length;
    s.entries = s.entries.filter(e => e.key !== key);
    this.write(owner, s);
    return s.entries.length < before;
  }

  clear(owner: string): number {
    const n = this.read(owner).entries.length;
    this.write(owner, { entries: [] });
    return n;
  }
}

export interface MemoryArgs { action?: "set" | "get" | "list" | "delete" | "clear"; key?: string; value?: string }

export function htMemory(store: AccountMemory, owner: string, a: MemoryArgs): string {
  const action = a.action ?? "list";
  if (action === "set") {
    if (!a.key || typeof a.value !== "string") throw new PolicyError("bad_input", "set için key ve value gerekli");
    const n = store.set(owner, a.key, a.value);
    return `MEMORY set ${a.key} (${Buffer.byteLength(a.value)} bytes) · ${n} kayıt`;
  }
  if (action === "get") {
    if (!a.key) throw new PolicyError("bad_input", "get için key gerekli");
    const e = store.get(owner, a.key);
    return e ? `MEMORY ${a.key} (${new Date(e.updated).toISOString().slice(0, 19)}Z)\n${e.value}` : `MEMORY: ${a.key} yok`;
  }
  if (action === "delete") {
    if (!a.key) throw new PolicyError("bad_input", "delete için key gerekli");
    return store.del(owner, a.key) ? `MEMORY deleted ${a.key}` : `MEMORY: ${a.key} yok`;
  }
  if (action === "clear") return `MEMORY: ${store.clear(owner)} kayıt silindi.`;
  const items = store.list(owner);
  if (!items.length) return "MEMORY: kayıt yok.";
  return `MEMORY: ${items.length} kayıt\n${items.map(i => `${i.key} · ${i.bytes} bayt · ${new Date(i.updated).toISOString().slice(0, 16).replace("T", " ")}`).join("\n")}`;
}
