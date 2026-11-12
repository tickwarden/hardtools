// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
// Runs inside a worker thread so a catastrophic regex can be terminated by the parent (ReDoS containment).
import fs from "node:fs";
import path from "node:path";
import { parentPort, workerData } from "node:worker_threads";
import { isDeniedRead, matchesAny, globToRegExp } from "./guard.js";

const { policy, q } = workerData as { policy: any; q: any };
const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", ".gradle", ".idea", ".mypy_cache", ".pytest_cache"]);

let flags = q.caseSensitive ? "" : "i";
let rx: RegExp;
try { rx = new RegExp(q.fixed ? q.pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : q.pattern, flags); }
catch (e) { parentPort!.postMessage({ type: "error", message: `invalid regex: ${(e as Error).message}` }); process.exit(0); }

// Minimal .gitignore support (dir names, simple globs, trailing-slash dirs; negations ignored).
const ignoreRx: { rx: RegExp; dirOnly: boolean }[] = [];
if (q.respectGitignore) {
  try {
    for (const raw of fs.readFileSync(path.join(q.searchRoot, ".gitignore"), "utf8").split(/\r?\n/)) {
      const l = raw.trim(); if (!l || l.startsWith("#") || l.startsWith("!")) continue;
      const dirOnly = l.endsWith("/"); const body = l.replace(/\/$/, "").replace(/^\//, "");
      ignoreRx.push({ rx: globToRegExp(body.includes("/") ? body : `**/${body}`), dirOnly });
    }
  } catch { /* no .gitignore */ }
}
const ignored = (rel: string, isDir: boolean) => ignoreRx.some(g => (!g.dirOnly || isDir) && g.rx.test(rel));

let scanned = 0, skipped = 0, found = 0, truncated = false;
let batch: any[] = [];
const flush = () => { if (batch.length) { parentPort!.postMessage({ type: "matches", matches: batch }); batch = []; } };

function scanFile(abs: string, rel: string) {
  let st: fs.Stats; try { st = fs.statSync(abs); } catch { skipped++; return; }
  if (st.size > q.maxFileBytes) { skipped++; return; }
  let buf: Buffer; try { buf = fs.readFileSync(abs); } catch { skipped++; return; }
  if (buf.subarray(0, 8000).includes(0)) { skipped++; return; }
  scanned++;
  const lines = buf.toString("utf8").split(/\r?\n/); let perFile = 0;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].length > 4000 ? lines[i].slice(0, 4000) : lines[i];
    if (!rx.test(l)) continue;
    const c = q.context as number;
    batch.push({ file: rel, line: i + 1, text: l.slice(0, 400),
      before: c ? lines.slice(Math.max(0, i - c), i).map((x: string) => x.slice(0, 400)) : [], after: c ? lines.slice(i + 1, i + 1 + c).map((x: string) => x.slice(0, 400)) : [] });
    found++; perFile++;
    if (batch.length >= 25) flush();
    if (found >= q.maxResults) { truncated = true; return; }
    if (perFile >= q.maxPerFile) return;
  }
}

function walk(dir: string) {
  let entries: fs.Dirent[]; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { skipped++; return; }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const d of entries) {
    if (truncated) return;
    const abs = path.join(dir, d.name); const rel = path.relative(q.searchRoot, abs).split(path.sep).join("/");
    if (d.isSymbolicLink()) { skipped++; continue; } // never follow symlinks
    if (d.isDirectory()) { if (SKIP_DIRS.has(d.name) || ignored(rel, true) || isDeniedRead(policy, abs)) continue; walk(abs); continue; }
    if (!d.isFile()) continue;
    if (isDeniedRead(policy, abs) || ignored(rel, false)) { skipped++; continue; }
    if (q.include.length && !matchesAny(abs, q.include)) continue;
    if (q.exclude.length && matchesAny(abs, q.exclude)) continue;
    scanFile(abs, rel);
  }
}

const st = fs.statSync(q.searchRoot);
if (st.isDirectory()) walk(q.searchRoot); else scanFile(q.searchRoot, path.basename(q.searchRoot));
flush();
parentPort!.postMessage({ type: "done", scanned, skipped, truncated });
