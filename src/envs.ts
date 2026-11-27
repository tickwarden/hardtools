// Fresh shell environments: rotate the workspace root so a broken tree can be abandoned
// without losing the previous one (it is moved to a bounded recycle bin, never deleted
// outright). The shared policy object carries the active root, so every tool follows.
import fs from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";
import { isInside, PolicyError } from "./guard.js";

const ENV_PREFIX = "env-";
/** Kök değişirken taşınmaması gereken yerel iskelet/atık dizinleri. */
const SCRATCH_ENTRY = new Set([".hardtools", ".ht-trash", ".recycle"]);
const KEEP_RECYCLED = 3;
const LABEL = /^[a-z0-9][a-z0-9-]{0,23}$/;

export interface EnvInfo { name: string; root: string; createdAt: number; recycled?: string; carriedFiles: number }

export function envBase(policy: Policy): string {
  const fromEnv = (process.env.HARDTOOLS_ENVS_DIR ?? "").trim();
  const root = policy.roots[0];
  if (fromEnv) {
    const base = path.resolve(fromEnv);
    // Taban çalışma kökünün içindeyse rotasyon kökü kökün içine gömer (…/work/envs/env-…):
    // o zaman kökün kardeşi (…/envs) kullanılır, iç içe geçme olmaz.
    if (isInside(root, base)) return path.join(path.dirname(root), "envs");
    return base;
  }
  const parent = path.dirname(root);
  // Kök zaten bir ortam diziniyse (…/envs/env-…) taban onun ebeveynidir; aksi hâlde
  // her rotasyonda …/envs/envs gibi iç içe bir taban oluşurdu.
  if (path.basename(parent) === "envs") return parent;
  return path.join(parent, "envs");
}

export function currentEnvName(policy: Policy): string | null {
  const root = policy.roots[0];
  return isInside(envBase(policy), root) ? path.basename(root) : null;
}

function stamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-").replace("T", "-").replace("Z", "");
}

function realOrSelf(p: string): string {
  try { return fs.realpathSync(p); } catch { return p; }
}

/** Move every entry of the current root into <base>/.recycle/<root>-<ts>, keeping the newest few. */
function recycleRoot(policy: Policy, base: string): { recycled?: string; files: number } {
  const root = policy.roots[0];
  let entries: string[];
  try { entries = fs.readdirSync(root); } catch { return { files: 0 }; }
  if (!entries.length) return { files: 0 };
  const bin = path.join(base, ".recycle");
  fs.mkdirSync(bin, { recursive: true, mode: 0o700 });
  const dest = path.join(bin, `${path.basename(root)}-${stamp()}`);
  fs.mkdirSync(dest, { recursive: true, mode: 0o700 });
  let moved = 0;
  for (const entry of entries) {
    if (SCRATCH_ENTRY.has(entry)) continue;                    // kabuk iskeleti geri dönüşüme gitmez
    try { fs.renameSync(path.join(root, entry), path.join(dest, entry)); moved++; }
    catch { /* a busy entry stays in place rather than being lost */ }
  }
  const kept = fs.readdirSync(bin).sort();
  for (const old of kept.slice(0, Math.max(0, kept.length - KEEP_RECYCLED))) {
    try { fs.rmSync(path.join(bin, old), { recursive: true, force: true }); } catch { /* keep what we cannot remove */ }
  }
  return { recycled: dest, files: moved };
}

/**
 * Create a new environment root and make it the active one. rotation=true keeps the tree
 * clean by moving the previous contents to the recycle bin first.
 */
export function createEnv(policy: Policy, o: { label?: string; rotate?: boolean } = {}): EnvInfo {
  if (policy.roots.length !== 1) throw new PolicyError("bad_env", "environment rotation needs exactly one project root");
  if (!policy.fs.writeEnabled) throw new PolicyError("read_only", "environment rotation needs write access");
  const base = envBase(policy);
  const current = policy.roots[0];
  if (base === current || isInside(current, base)) throw new PolicyError("bad_env_dir", "the environment directory must be outside the current workspace");
  if (policy.protectedDirs.some(d => isInside(d, base) || isInside(base, d))) throw new PolicyError("bad_env_dir", "the environment directory overlaps an audit or configuration directory");
  if (o.label !== undefined && !LABEL.test(o.label)) throw new PolicyError("bad_input", "label must be 1–24 chars of a-z, 0-9 and '-'");

  fs.mkdirSync(base, { recursive: true, mode: 0o700 });
  const name = `${ENV_PREFIX}${stamp()}${o.label ? `-${o.label}` : ""}`;
  const root = path.join(base, name);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });

  let recycled: string | undefined; let carriedFiles = 0;
  if (o.rotate) ({ recycled, files: carriedFiles } = recycleRoot(policy, base));
  else {
    // Tasima: eski agac yeni koke gecer (geri donusum kutusuna gitmez).
    for (const entry of (() => { try { return fs.readdirSync(current); } catch { return [] as string[]; } })()) {
      if (SCRATCH_ENTRY.has(entry)) continue;                  // taşınan ağaç kabuk iskeletini kopyalamaz
      try { fs.renameSync(path.join(current, entry), path.join(root, entry)); carriedFiles++; } catch { /* kalan kalir */ }
    }
  }

  policy.roots = [realOrSelf(root)];
  return { name, root: policy.roots[0], createdAt: Date.now(), ...(recycled ? { recycled } : {}), carriedFiles };
}
