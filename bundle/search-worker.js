import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);

// src/search-worker.ts
import fs from "node:fs";
import path2 from "node:path";
import { parentPort, workerData } from "node:worker_threads";

// src/guard.ts
import path from "node:path";
var rxCache = /* @__PURE__ */ new Map();
function globToRegExp(glob) {
  const hit = rxCache.get(glob);
  if (hit) return hit;
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  const r = new RegExp("^" + re + "$", "i");
  rxCache.set(glob, r);
  return r;
}
function matchesAny(absPath, patterns) {
  const posix = absPath.split(path.sep).join("/");
  const base = path.posix.basename(posix);
  for (const p of patterns) {
    if (!p.includes("/")) {
      if (globToRegExp(p).test(base)) return true;
    } else {
      const pat = p.startsWith("/") || p.startsWith("**") ? p : "**/" + p;
      if (globToRegExp(pat).test(posix)) return true;
    }
  }
  return false;
}
function isInside(root, p) {
  const rel = path.relative(root, p);
  return rel === "" || rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel);
}
function isDeniedRead(p, abs) {
  if (p.protectedDirs.some((d) => isInside(d, abs))) return true;
  return matchesAny(abs, p.fs.denyRead) && !matchesAny(abs, p.fs.allowRead);
}

// src/search-worker.ts
var { policy, q } = workerData;
var SKIP_DIRS = /* @__PURE__ */ new Set([".git", "node_modules", ".venv", "venv", "__pycache__", ".gradle", ".idea", ".mypy_cache", ".pytest_cache"]);
var flags = q.caseSensitive ? "" : "i";
var rx;
try {
  rx = new RegExp(q.fixed ? q.pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : q.pattern, flags);
} catch (e) {
  parentPort.postMessage({ type: "error", message: `invalid regex: ${e.message}` });
  process.exit(0);
}
var ignoreRx = [];
if (q.respectGitignore) {
  try {
    for (const raw of fs.readFileSync(path2.join(q.searchRoot, ".gitignore"), "utf8").split(/\r?\n/)) {
      const l = raw.trim();
      if (!l || l.startsWith("#") || l.startsWith("!")) continue;
      const dirOnly = l.endsWith("/");
      const body = l.replace(/\/$/, "").replace(/^\//, "");
      ignoreRx.push({ rx: globToRegExp(body.includes("/") ? body : `**/${body}`), dirOnly });
    }
  } catch {
  }
}
var ignored = (rel, isDir) => ignoreRx.some((g) => (!g.dirOnly || isDir) && g.rx.test(rel));
var scanned = 0;
var skipped = 0;
var found = 0;
var truncated = false;
var batch = [];
var flush = () => {
  if (batch.length) {
    parentPort.postMessage({ type: "matches", matches: batch });
    batch = [];
  }
};
function scanFile(abs, rel) {
  let st2;
  try {
    st2 = fs.statSync(abs);
  } catch {
    skipped++;
    return;
  }
  if (st2.size > q.maxFileBytes) {
    skipped++;
    return;
  }
  let buf;
  try {
    buf = fs.readFileSync(abs);
  } catch {
    skipped++;
    return;
  }
  if (buf.subarray(0, 8e3).includes(0)) {
    skipped++;
    return;
  }
  scanned++;
  const lines = buf.toString("utf8").split(/\r?\n/);
  let perFile = 0;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].length > 4e3 ? lines[i].slice(0, 4e3) : lines[i];
    if (!rx.test(l)) continue;
    const c = q.context;
    batch.push({
      file: rel,
      line: i + 1,
      text: l.slice(0, 400),
      before: c ? lines.slice(Math.max(0, i - c), i).map((x) => x.slice(0, 400)) : [],
      after: c ? lines.slice(i + 1, i + 1 + c).map((x) => x.slice(0, 400)) : []
    });
    found++;
    perFile++;
    if (batch.length >= 25) flush();
    if (found >= q.maxResults) {
      truncated = true;
      return;
    }
    if (perFile >= q.maxPerFile) return;
  }
}
function walk(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    skipped++;
    return;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const d of entries) {
    if (truncated) return;
    const abs = path2.join(dir, d.name);
    const rel = path2.relative(q.searchRoot, abs).split(path2.sep).join("/");
    if (d.isSymbolicLink()) {
      skipped++;
      continue;
    }
    if (d.isDirectory()) {
      if (SKIP_DIRS.has(d.name) || ignored(rel, true) || isDeniedRead(policy, abs)) continue;
      walk(abs);
      continue;
    }
    if (!d.isFile()) continue;
    if (isDeniedRead(policy, abs) || ignored(rel, false)) {
      skipped++;
      continue;
    }
    if (q.include.length && !matchesAny(abs, q.include)) continue;
    if (q.exclude.length && matchesAny(abs, q.exclude)) continue;
    scanFile(abs, rel);
  }
}
var st = fs.statSync(q.searchRoot);
if (st.isDirectory()) walk(q.searchRoot);
else scanFile(q.searchRoot, path2.basename(q.searchRoot));
flush();
parentPort.postMessage({ type: "done", scanned, skipped, truncated });
