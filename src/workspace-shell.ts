import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import type { Policy } from "./config.js";
import { isInside, PolicyError } from "./guard.js";

// The launcher is chosen by the operator's OS, never by an MCP argument or a workspace PATH.
const launcher = "/usr/bin/bwrap";
function workerEnv(selected: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { PATH: "/runtime:/usr/bin:/bin", HOME: "/tmp", TMPDIR: "/tmp", LANG: "C.UTF-8", GIT_TERMINAL_PROMPT: "0", ...selected };
}
function workspaceArgs(p: Policy, cwd: string, program: string, args: string[]): string[] {
  if (process.platform !== "linux" || p.roots.length !== 1) throw new PolicyError("worker_unavailable", "workspace shell requires Linux and one dedicated project root");
  const root = p.roots[0];
  if (root === path.parse(root).root || root === os.homedir() || !isInside(root, cwd) || p.protectedDirs.some(d => isInside(root, d) || isInside(d, root)))
    throw new PolicyError("worker_root", "choose a dedicated workspace separate from audit, home and configuration");
  try { fs.accessSync(launcher, fs.constants.X_OK); } catch { throw new PolicyError("worker_unavailable", "bubblewrap is not installed at /usr/bin/bwrap; no host-shell fallback"); }

  const childCwd = path.posix.join("/work", path.relative(root, cwd));
  return [
    "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
    "--dir", "/usr", "--ro-bind", "/usr/bin", "/usr/bin", "--ro-bind", "/usr/lib", "/usr/lib",
    "--ro-bind-try", "/usr/lib64", "/usr/lib64", "--ro-bind", "/usr/share", "/usr/share",
    "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
    "--dir", "/runtime", "--ro-bind-fd", "3", "/runtime/node",
    "--size", "67108864", "--tmpfs", "/tmp", "--dev", "/dev", "--proc", "/proc", "--remount-ro", "/proc",
    p.fs.writeEnabled ? "--bind" : "--ro-bind", root, "/work", "--remount-ro", "/", "--chdir", childCwd,
    "--", program, ...args,
  ];
}

/** Pin this process's executable via procfs, not a name from process.execPath or PATH.
 * spawn duplicates this descriptor into child stdio slot 3 before returning. Bubblewrap
 * consumes that fd for the read-only mount; no descriptor is handed to the guest program. */
function withRuntimeFd<T>(launch: (fd: number) => T): T {
  let fd: number;
  try { fd = fs.openSync("/proc/self/exe", fs.constants.O_RDONLY); }
  catch { throw new PolicyError("worker_unavailable", "cannot open the running Node executable through procfs"); }
  try {
    if (!fs.fstatSync(fd).isFile()) throw new PolicyError("worker_unavailable", "the running Node executable is not a regular file");
    return launch(fd);
  } finally { fs.closeSync(fd); }
}

export function spawnWorkspaceShell(p: Policy, cwd: string, program: string, args: string[], selected: NodeJS.ProcessEnv): ChildProcess {
  const argv = workspaceArgs(p, cwd, program, args);
  return withRuntimeFd(fd => spawn(launcher, argv, {
    cwd: "/", env: workerEnv(selected), shell: false, detached: true, stdio: ["pipe", "pipe", "pipe", fd],
  }));
}

/** Exercise the same fd mount before opening the HTTP endpoint. Never fall back to the host. */
export function probeWorkspaceShell(p: Policy): void {
  const argv = workspaceArgs(p, p.roots[0], "/runtime/node", ["--version"]);
  const child = withRuntimeFd(fd => spawnSync(launcher, argv, {
    cwd: "/", env: workerEnv(), shell: false, stdio: ["ignore", "pipe", "pipe", fd], encoding: "utf8", timeout: 5000,
  }));
  if (child.status !== 0) throw new PolicyError("worker_unavailable", `isolated workspace probe failed; no fallback: ${child.error?.message ?? child.stderr?.trim() ?? "launch failed"}`);
}
