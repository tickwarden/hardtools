// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";
import { PolicyError, isInside, resolveSafe } from "./guard.js";

const active = new Set<ChildProcess>();
process.on("exit", () => { for (const c of active) killTree(c, "SIGKILL"); });

function killTree(c: ChildProcess, sig: NodeJS.Signals): void {
  if (!c.pid) return;
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(c.pid), "/t", "/f"], { windowsHide: true });
    else process.kill(-c.pid, sig); // whole process group
  } catch { try { c.kill(sig); } catch { /* already gone */ } }
}

class Capture {
  private head: Buffer[] = []; private headLen = 0; private tail = Buffer.alloc(0); dropped = 0;
  constructor(private max: number) {}
  push(b: Buffer) {
    const headMax = Math.floor(this.max * 0.6), tailMax = this.max - headMax;
    if (this.headLen < headMax) {
      const take = Math.min(headMax - this.headLen, b.length); this.head.push(b.subarray(0, take)); this.headLen += take; b = b.subarray(take);
    }
    if (b.length) {
      const joined = Buffer.concat([this.tail, b]);
      if (joined.length > tailMax) { this.dropped += joined.length - tailMax; this.tail = joined.subarray(joined.length - tailMax); } else this.tail = joined;
    }
  }
  text(): string {
    const h = Buffer.concat(this.head).toString("utf8");
    return this.dropped ? `${h}\n…[${this.dropped} bytes omitted]…\n${this.tail.toString("utf8")}` : h + this.tail.toString("utf8");
  }
}

function matchAllow(argv: string[], allow: string[]): boolean {
  return allow.some(entry => {
    if (entry === "*") return true;
    const t = entry.trim().split(/\s+/);
    return argv.length >= t.length && t.every((x, i) => argv[i] === x);
  });
}

function buildEnv(policy: Policy, rootsReal: string[]): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const secretish = /(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|AUTH|COOKIE|SESSION)/i;
  const wildcard = policy.shell.envAllow.includes("*");
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    if (k.startsWith("HARDTOOLS_")) continue;
    const exact = policy.shell.envAllow.includes(k);
    if (exact || (wildcard && !secretish.test(k))) env[k] = v;
  }
  if (policy.shell.sanitizePath && env.PATH) {
    env.PATH = env.PATH.split(path.delimiter).filter(p => path.isAbsolute(p) && !rootsReal.some(r => isInside(r, p))).join(path.delimiter);
  }
  Object.assign(env, { GIT_TERMINAL_PROMPT: "0", GIT_PAGER: "cat", PAGER: "cat", GIT_CONFIG_NOSYSTEM: "1", GIT_OPTIONAL_LOCKS: "0" });
  if (policy.profile !== "open") env.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  delete env.GIT_EXTERNAL_DIFF; delete env.GIT_SSH_COMMAND; delete env.LD_PRELOAD; delete env.LD_LIBRARY_PATH; delete env.NODE_OPTIONS; delete env.BASH_ENV; delete env.ENV;
  return env;
}

export interface ShellArgs { argv?: string[]; command?: string; cwd?: string; timeout_ms?: number; stdin?: string }

export async function htShell(policy: Policy, a: ShellArgs): Promise<string> {
  const sh = policy.shell;
  if (!sh.enabled) throw new PolicyError("shell_disabled", "shell execution is disabled by policy");
  if ((a.argv === undefined) === (a.command === undefined)) throw new PolicyError("bad_input", "provide exactly one of argv or command");
  if (active.size >= sh.maxConcurrent) throw new PolicyError("busy", `too many concurrent commands (limit ${sh.maxConcurrent})`);

  const cwdR = resolveSafe(policy, a.cwd ?? ".", "read");
  if (!fs.statSync(cwdR.abs).isDirectory()) throw new PolicyError("bad_cwd", "cwd is not a directory");
  const timeout = Math.min(a.timeout_ms ?? sh.timeoutMs, sh.maxTimeoutMs);
  if (a.stdin !== undefined && Buffer.byteLength(a.stdin) > 64 * 1024) throw new PolicyError("stdin_too_large", "stdin limited to 64 KiB");

  let file: string; let args: string[]; let shown: string;
  if (a.argv) {
    const argv = a.argv;
    if (!argv.length || argv.length > 64 || argv.some(x => typeof x !== "string" || x.includes("\0") || x.length > 4096)) throw new PolicyError("bad_argv", "argv must be 1–64 strings (≤4096 chars, no NUL)");
    if (!matchAllow(argv, sh.allow)) throw new PolicyError("not_allowed", `command is not in shell.allow: ${argv.slice(0, 3).join(" ")}`);
    for (const rx of sh.denyArgs.map(s => new RegExp(s))) {
      const bad = argv.slice(1).find(x => rx.test(x)); if (bad !== undefined) throw new PolicyError("arg_denied", `argument is denied by policy: ${bad}`);
    }
    if (/[\\/]/.test(argv[0])) {
      if (!sh.allowRelativeExecutables) throw new PolicyError("path_executable", "executables must be plain command names (no path separators)");
      resolveSafe(policy, argv[0], "read", cwdR.abs);
    }
    if (sh.confineArgPaths) {
      for (const x of argv.slice(1)) {
        const v = x.startsWith("-") ? (x.includes("=") ? x.slice(x.indexOf("=") + 1) : "") : x;
        if (!v) continue;
        if (v.startsWith("~")) throw new PolicyError("arg_path_outside_roots", `argument looks like a home-relative path: ${x}`);
        if (/[\\/]/.test(v) || v === ".." || v.startsWith(".")) {
          try { resolveSafe(policy, v, "read", cwdR.abs); }
          catch (e) { if (e instanceof PolicyError && e.code !== "bad_path") throw new PolicyError("arg_path_outside_roots", `path argument rejected (${e.code}): ${x}`); }
        }
      }
    }
    [file, ...args] = argv; shown = argv.join(" ");
  } else {
    const cmd = a.command as string;
    if (!sh.allowShellSyntax || !sh.allow.includes("*")) throw new PolicyError("shell_syntax_disabled", "shell syntax (command=) is only available in profiles that allow it; use argv instead");
    if (!cmd.trim() || cmd.includes("\0") || cmd.length > 16384) throw new PolicyError("bad_command", "invalid command");
    for (const s of sh.shellDenyPatterns) if (new RegExp(s).test(cmd)) throw new PolicyError("pattern_denied", "command matches a deny pattern");
    [file, args] = process.platform === "win32" ? ["cmd.exe", ["/d", "/s", "/c", cmd]] : ["/bin/sh", ["-c", cmd]]; shown = cmd;
  }

  const env = buildEnv(policy, policy.roots);
  const started = Date.now();
  return await new Promise<string>((resolve, reject) => {
    let child: ChildProcess;
    try {
      child = spawn(file, args, { cwd: cwdR.abs, env, shell: false, detached: process.platform !== "win32", stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    } catch (e) { return reject(new Error(`spawn failed: ${(e as Error).message}`)); }
    active.add(child);
    const out = new Capture(Math.floor(sh.maxOutputBytes * 0.7)), err = new Capture(Math.floor(sh.maxOutputBytes * 0.3));
    child.stdout!.on("data", (b: Buffer) => out.push(b)); child.stderr!.on("data", (b: Buffer) => err.push(b));
    child.stdin!.on("error", () => { /* child may exit before reading stdin */ });
    child.stdin!.end(a.stdin ?? "");
    let timedOut = false;
    const t = setTimeout(() => { timedOut = true; killTree(child, "SIGTERM"); setTimeout(() => killTree(child, "SIGKILL"), 2000).unref(); }, timeout);
    child.on("error", (e: NodeJS.ErrnoException) => { clearTimeout(t); active.delete(child); reject(e.code === "ENOENT" ? new Error(`command not found: ${file}`) : e); });
    child.on("close", (code, signal) => {
      clearTimeout(t); active.delete(child);
      killTree(child, "SIGKILL"); // reap stragglers in the process group
      resolve([`exit_code=${code ?? "null"}${signal ? ` signal=${signal}` : ""}${timedOut ? " TIMED_OUT" : ""} duration_ms=${Date.now() - started} cwd=${path.relative(cwdR.root, cwdR.abs) || "."}`,
        `$ ${shown}`, out.text() ? `--- stdout ---\n${out.text()}` : "--- stdout (empty) ---", err.text() ? `--- stderr ---\n${err.text()}` : ""].filter(Boolean).join("\n"));
    });
  });
}
