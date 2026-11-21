import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import type { Policy } from "./config.js";
import { isInside, PolicyError } from "./guard.js";

// The launcher is chosen by the operator's OS, never by an MCP argument or a workspace PATH.
const launcher = "/usr/bin/bwrap";
export function workerEnv(selected: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { PATH: "/runtime:/usr/bin:/bin", HOME: "/tmp", TMPDIR: "/tmp", LANG: "C.UTF-8", GIT_TERMINAL_PROMPT: "0", ...selected };
}
export function workspaceLaunch(p: Policy, cwd: string, program: string, args: string[]) {
  if (process.platform !== "linux" || p.roots.length !== 1) throw new PolicyError("worker_unavailable", "workspace shell requires Linux and one dedicated project root");
  const root = p.roots[0];
  if (root === path.parse(root).root || root === os.homedir() || !isInside(root, cwd) || p.protectedDirs.some(d => isInside(root, d) || isInside(d, root)))
    throw new PolicyError("worker_root", "choose a dedicated workspace separate from audit, home and configuration");
  try { fs.accessSync(launcher, fs.constants.X_OK); } catch { throw new PolicyError("worker_unavailable", "bubblewrap is not installed at /usr/bin/bwrap; no host-shell fallback"); }
  const childCwd = path.posix.join("/work", path.relative(root, cwd));
  return { file: launcher, args: [
    "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
    "--dir", "/usr", "--ro-bind", "/usr/bin", "/usr/bin", "--ro-bind", "/usr/lib", "/usr/lib",
    "--ro-bind-try", "/usr/lib64", "/usr/lib64", "--ro-bind", "/usr/share", "/usr/share",
    "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
    "--dir", "/runtime", "--ro-bind", fs.realpathSync(process.execPath), "/runtime/node",
    "--size", "67108864", "--tmpfs", "/tmp", "--dev", "/dev", "--proc", "/proc", "--remount-ro", "/proc",
    p.fs.writeEnabled ? "--bind" : "--ro-bind", root, "/work", "--remount-ro", "/", "--chdir", childCwd,
    "--", program, ...args,
  ] };
}

/** Fail before the HTTP endpoint starts if the kernel or the launcher cannot enforce the boundary. */
export function probeWorkspaceShell(p: Policy): void {
  const spec = workspaceLaunch(p, p.roots[0], "/usr/bin/true", []);
  const child = spawnSync(spec.file, spec.args, { cwd: "/", env: workerEnv(), encoding: "utf8", timeout: 5000 });
  if (child.status !== 0) throw new PolicyError("worker_unavailable", `isolated workspace probe failed; no fallback: ${child.error?.message ?? child.stderr?.trim() ?? "launch failed"}`);
}
