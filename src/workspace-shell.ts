import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import type { Policy } from "./config.js";
import { isInside, PolicyError } from "./guard.js";
import { openWorkspaceEgress, type EgressLease } from "./workspace-egress.js";

// The launcher is chosen by the operator's OS, never by an MCP argument or a workspace PATH.
const launcher = "/usr/bin/bwrap";
// Runs INSIDE the namespace. The FIFO is in a fresh guest tmpfs and carries only
// the relay's readiness/port. The requested argv follows the fixed script; it
// is never inserted into it. exec preserves normal command exit/signal semantics.
const guestStart = `set -eu
r=$(mktemp -d /tmp/ht-ready.XXXXXXXX)
mkfifo "$r/port"
/runtime/node /runtime/https-bridge.mjs </dev/null >"$r/port" &
IFS= read -r port <"$r/port" || exit 125
rm -- "$r/port"; rmdir -- "$r"
case "$port" in ''|*[!0-9]*) exit 125;; esac
p="http://127.0.0.1:$port"
export HTTPS_PROXY="$p" https_proxy="$p" HTTP_PROXY="$p" http_proxy="$p" NO_PROXY='' no_proxy=''
exec "$@"`;

function workerEnv(selected: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { PATH: "/runtime:/usr/bin:/bin", HOME: "/tmp", TMPDIR: "/tmp", LANG: "C.UTF-8", GIT_TERMINAL_PROMPT: "0", ...selected };
}
function workspaceArgs(p: Policy, cwd: string, program: string, args: string[], lease?: EgressLease): string[] {
  if (process.platform !== "linux" || p.roots.length !== 1) throw new PolicyError("worker_unavailable", "workspace shell requires Linux and one dedicated project root");
  const root = p.roots[0];
  if (root === path.parse(root).root || root === os.homedir() || !isInside(root, cwd) || p.protectedDirs.some(d => isInside(root, d) || isInside(d, root)))
    throw new PolicyError("worker_root", "choose a dedicated workspace separate from audit, home and configuration");
  try { fs.accessSync(launcher, fs.constants.X_OK); } catch { throw new PolicyError("worker_unavailable", "bubblewrap is not installed at /usr/bin/bwrap; no host-shell fallback"); }

  const childCwd = path.posix.join("/work", path.relative(root, cwd));
  return [
    "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
    "--dir", "/usr", "--ro-bind", "/usr/bin", "/usr/bin", "--ro-bind", "/usr/lib", "/usr/lib",
    // pip/pipx ve benzeri /usr/local kurulumları da görünür olsun (salt okunur).
    "--ro-bind-try", "/usr/local/bin", "/usr/local/bin", "--ro-bind-try", "/usr/local/lib", "/usr/local/lib",
    "--ro-bind-try", "/usr/lib64", "/usr/lib64", "--ro-bind", "/usr/share", "/usr/share",
    // Dağıtım kimliği: komutlar (ve kullanıcı) kabuğun Ubuntu/Debian tabanını görebilsin.
    "--ro-bind-try", "/etc/os-release", "/etc/os-release",
    "--ro-bind-try", "/etc/lsb-release", "/etc/lsb-release",
    "--ro-bind-try", "/etc/debian_version", "/etc/debian_version",
    // Debian/Ubuntu'da pek çok araç (/usr/bin/which, awk, pager...) /etc/alternatives
    // üzerinden symlink; bağlanmazsa "not found" görünür.
    "--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
    "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
    "--dir", "/runtime", "--ro-bind-fd", "3", "/runtime/node",
    ...(lease ? ["--ro-bind-fd", "4", "/runtime/https-bridge.mjs", "--ro-bind", lease.socketPath, "/runtime/https.sock",
      "--ro-bind", "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/ca-certificates.crt"] : []),
    "--size", "67108864", "--tmpfs", "/tmp", "--dev", "/dev", "--proc", "/proc", "--remount-ro", "/proc",
    p.fs.writeEnabled ? "--bind" : "--ro-bind", root, "/work", "--remount-ro", "/", "--chdir", childCwd,
    "--", ...(lease ? ["/bin/sh", "-c", guestStart, "ht-workspace"] : []), program, ...args,
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

export function spawnWorkspaceShell(p: Policy, cwd: string, program: string, args: string[], selected: NodeJS.ProcessEnv, lease?: EgressLease): ChildProcess {
  if (Boolean(p.workspaceHttps) !== Boolean(lease)) throw new PolicyError("worker_unavailable", "workspace egress lease mismatch");
  const argv = workspaceArgs(p, cwd, program, args, lease);
  return withRuntimeFd(fd => {
    let bridge: number | undefined;
    try {
      if (lease) {
        bridge = fs.openSync(new URL("./workspace-bridge.js", import.meta.url), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
        if (!fs.fstatSync(bridge).isFile()) throw new PolicyError("worker_unavailable", "invalid guest bridge");
      }
      return spawn(launcher, argv, { cwd: "/", env: workerEnv(selected), shell: false, detached: true,
        stdio: ["pipe", "pipe", "pipe", fd, ...(bridge === undefined ? [] : [bridge])] });
    } finally { if (bridge !== undefined) fs.closeSync(bridge); }
  });
}

/** Exercise the same fd mount before opening the HTTP endpoint. Never fall back to the host. */
export function probeWorkspaceShell(p: Policy): void {
  const argv = workspaceArgs(p, p.roots[0], "/runtime/node", ["--version"]);
  const child = withRuntimeFd(fd => spawnSync(launcher, argv, {
    cwd: "/", env: workerEnv(), shell: false, stdio: ["ignore", "pipe", "pipe", fd], encoding: "utf8", timeout: 5000,
  }));
  if (child.status !== 0) throw new PolicyError("worker_unavailable", `isolated workspace probe failed; no fallback: ${child.error?.message ?? child.stderr?.trim() ?? "launch failed"}`);
}

/** Test the whole relay inside a guest, without contacting a destination or probing the live MCP. */
export async function probeWorkspaceHttps(p: Policy): Promise<void> {
  const lease = await openWorkspaceEgress(p);
  try {
    const check = `const http=require('node:http'),u=new URL(process.env.HTTPS_PROXY);
      const r=http.request({host:u.hostname,port:u.port,method:'CONNECT',path:'127.0.0.1:443'});
      r.on('connect',(res,s)=>{s.destroy();process.exit(res.statusCode===403?0:1)});
      r.on('error',()=>process.exit(1));r.end();`;
    const c = spawnWorkspaceShell(p, p.roots[0], "/runtime/node", ["-e", check], {}, lease);
    await new Promise<void>((ok, fail) => {
      const timer = setTimeout(() => { try { if (c.pid) process.kill(-c.pid, "SIGKILL"); } catch { /* already exited */ } }, 5000);
      c.stdout!.resume(); c.stderr!.resume(); c.stdin!.end();
      c.once("error", e => { clearTimeout(timer); fail(e); });
      c.once("close", code => { clearTimeout(timer); if (code === 0) ok(); else fail(new PolicyError("worker_unavailable", "isolated HTTPS proxy probe failed; no fallback")); });
    });
  } finally { lease.close(); }
}
