// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import fs from "node:fs";
import path from "node:path";
import { Worker } from "node:worker_threads";
import type { Policy } from "./config.js";
import { PolicyError, resolveSafe } from "./guard.js";

export interface SearchArgs {
  pattern: string; path?: string; fixed?: boolean; case_sensitive?: boolean; context?: number;
  include?: string[]; exclude?: string[]; max_results?: number; max_per_file?: number; respect_gitignore?: boolean;
}

export async function htSearch(policy: Policy, a: SearchArgs): Promise<string> {
  if (!a.pattern || a.pattern.length > 2000) throw new PolicyError("bad_pattern", "pattern must be 1–2000 chars");
  const r = resolveSafe(policy, a.path ?? ".", "read");
  const maxResults = Math.min(a.max_results ?? 100, policy.search.maxResults);
  const q = {
    pattern: a.pattern, fixed: a.fixed ?? false, caseSensitive: a.case_sensitive ?? false,
    context: Math.min(Math.max(a.context ?? 0, 0), 5), include: a.include ?? [], exclude: a.exclude ?? [],
    maxResults, maxPerFile: Math.min(a.max_per_file ?? 20, 200), respectGitignore: a.respect_gitignore ?? true,
    searchRoot: r.abs, maxFileBytes: policy.search.maxFileBytes,
  };
  const matches: any[] = []; let meta = { scanned: 0, skipped: 0, truncated: false }; let timedOut = false; let error: string | undefined;
  await new Promise<void>((resolve) => {
    const w = new Worker(new URL("./search-worker.js", import.meta.url), { workerData: { policy, q }, resourceLimits: { maxOldGenerationSizeMb: 256 } });
    const timer = setTimeout(() => { timedOut = true; void w.terminate(); }, policy.search.timeBudgetMs);
    w.on("message", (m: any) => {
      if (m.type === "matches") matches.push(...m.matches);
      else if (m.type === "done") meta = { scanned: m.scanned, skipped: m.skipped, truncated: m.truncated };
      else if (m.type === "error") error = m.message;
    });
    w.on("error", (e) => { error = e.message; });
    w.on("exit", () => { clearTimeout(timer); resolve(); });
  });
  if (error) throw new PolicyError("search_error", error);
  const lines: string[] = [];
  for (const m of matches) {
    for (let i = 0; i < m.before.length; i++) lines.push(`${m.file}-${m.line - m.before.length + i}-${m.before[i]}`);
    lines.push(`${m.file}:${m.line}:${m.text}`);
    for (let i = 0; i < m.after.length; i++) lines.push(`${m.file}-${m.line + 1 + i}-${m.after[i]}`);
    if (q.context) lines.push("--");
  }
  const rel = path.relative(r.root, r.abs) || ".";
  return `SEARCH ${JSON.stringify(a.pattern)} in ${rel} | ${matches.length} match(es) | files scanned=${meta.scanned} skipped=${meta.skipped}${meta.truncated ? " | RESULT LIMIT REACHED" : ""}${timedOut ? ` | TIME BUDGET (${policy.search.timeBudgetMs} ms) EXCEEDED — results are partial (pattern may be too expensive)` : ""}\n${lines.join("\n")}`;
}
void fs;
