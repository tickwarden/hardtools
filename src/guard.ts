// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import fs from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";

export class PolicyError extends Error {
  constructor(public code: string, message: string) { super(message); this.name = "PolicyError"; }
}

const rxCache = new Map<string, RegExp>();
export function globToRegExp(glob: string): RegExp {
  const hit = rxCache.get(glob); if (hit) return hit;
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") { re += "(?:.*/)?"; i += 2; } else { re += ".*"; i += 1; }
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  const r = new RegExp("^" + re + "$", "i"); // case-insensitive on purpose: over-deny rather than under-deny
  rxCache.set(glob, r); return r;
}

export function matchesAny(absPath: string, patterns: string[]): boolean {
  const posix = absPath.split(path.sep).join("/");
  const base = path.posix.basename(posix);
  for (const p of patterns) {
    if (!p.includes("/")) { if (globToRegExp(p).test(base)) return true; }
    else {
      const pat = p.startsWith("/") || p.startsWith("**") ? p : "**/" + p;
      if (globToRegExp(pat).test(posix)) return true;
    }
  }
  return false;
}

export function isInside(root: string, p: string): boolean {
  const rel = path.relative(root, p);
  return rel === "" || (rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel));
}

type GuardPolicy = Pick<Policy, "roots" | "protectedDirs" | "fs">;

export function isDeniedRead(p: GuardPolicy, abs: string): boolean {
  if (p.protectedDirs.some(d => isInside(d, abs))) return true;
  return matchesAny(abs, p.fs.denyRead) && !matchesAny(abs, p.fs.allowRead);
}
export function isDeniedWrite(p: GuardPolicy, abs: string): boolean {
  return isDeniedRead(p, abs) || matchesAny(abs, p.fs.denyWrite);
}

export interface Resolved { abs: string; root: string; exists: boolean }

/**
 * Resolve `input` against `baseDir` (default: first root), follow symlinks on the deepest existing
 * ancestor, and require the *real* location to live inside an allowed root.
 * Residual risk: TOCTOU between check and use (documented in SECURITY.md); mitigated with O_NOFOLLOW + temp/rename writes.
 */
export function resolveSafe(policy: GuardPolicy, input: string, mode: "read" | "write", baseDir?: string): Resolved {
  if (typeof input !== "string" || input.length === 0 || input.includes("\0")) throw new PolicyError("bad_path", "invalid path");
  if (mode === "write" && !policy.fs.writeEnabled) throw new PolicyError("write_disabled", "writes are disabled by policy");
  const abs = path.resolve(baseDir ?? policy.roots[0], input);
  let probe = abs; const rest: string[] = []; let real: string;
  for (;;) {
    try { real = fs.realpathSync.native(probe); break; }
    catch (e: any) {
      if (e.code !== "ENOENT" && e.code !== "ENOTDIR") throw new PolicyError("fs_error", `cannot resolve path (${e.code})`);
      const parent = path.dirname(probe);
      if (parent === probe) throw new PolicyError("bad_path", "cannot resolve path");
      rest.unshift(path.basename(probe)); probe = parent;
    }
  }
  if (rest.length) {
    // A dangling symlink looks like "ENOENT" but writing through it would escape. Refuse.
    try { fs.lstatSync(path.join(real, rest[0])); throw new PolicyError("dangling_symlink", "path is a dangling symlink"); }
    catch (e) { if (e instanceof PolicyError) throw e; }
  }
  const full = path.join(real, ...rest);
  const root = policy.roots.find(r => isInside(r, full));
  if (!root) throw new PolicyError("outside_roots", `path is outside the allowed roots: ${input}`);
  if (mode === "read" ? isDeniedRead(policy, full) : isDeniedWrite(policy, full))
    throw new PolicyError("denied_path", `path is protected by policy (${mode}): ${path.relative(root, full) || "."}`);
  return { abs: full, root, exists: rest.length === 0 };
}

const SECRET_PATTERNS: [string, RegExp][] = [
  ["private key block", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/],
  ["AWS access key id", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/],
  ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ["Anthropic API key", /\bsk-ant-[A-Za-z0-9_-]{20,}\b/],
  ["OpenAI-style API key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["Stripe live key", /\b[sr]k_live_[0-9A-Za-z]{20,}\b/],
  ["JWT", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
];

export function scanSecrets(text: string): string[] {
  const found: string[] = [];
  for (const [name, rx] of SECRET_PATTERNS) if (rx.test(text)) found.push(name);
  return found;
}
export function redact(text: string): string {
  let out = text;
  for (const [, rx] of SECRET_PATTERNS) out = out.replace(new RegExp(rx.source, "g"), "[REDACTED]");
  return out;
}
/** Returns warnings (mode=warn) or throws (mode=block). */
export function enforceSecrets(policy: Pick<Policy, "fs">, text: string, what: string): string[] {
  if (policy.fs.secretScan === "off") return [];
  const hits = scanSecrets(text);
  if (!hits.length) return [];
  if (policy.fs.secretScan === "block")
    throw new PolicyError("secret_detected", `${what} appears to contain a secret (${hits.join(", ")}). Refusing to write it. Use an env var / secret manager instead.`);
  return hits.map(h => `${what} looks like it contains: ${h}`);
}
