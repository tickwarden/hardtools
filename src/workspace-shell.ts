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

// 0.5.3: /tmp artık çağrı başına tmpfs değil, proje hacminde kalıcı bir kazı alanı:
// aynı oturumdaki ht_shell çağrıları arasında indirilen dosyalar ve pip --user
// kurulumları kaybolmaz. HARDTOOLS_SESSION_TMP=0 eski (uçucu tmpfs) davranışa döner.
export interface Scratch { tmp: string; home: string; bin: string; root: string; aptLists: string; aptCache: string; aptConf: string | null }
const scratchCache = new Map<string, Scratch | null>();
function prepareScratch(p: Policy): Scratch | null {
  if ((process.env.HARDTOOLS_SESSION_TMP ?? "1").trim() === "0") return null;
  const base = path.join(p.roots[0], ".hardtools");
  const cached = scratchCache.get(base);
  if (cached !== undefined) return cached;
  const s: Scratch = {
    tmp: path.join(base, "tmp"), home: path.join(base, "home"),
    bin: path.join(base, "bin"), root: path.join(base, "root"),
    aptLists: path.join(base, "apt", "lists"), aptCache: path.join(base, "apt", "archives"),
    aptConf: path.join(base, "apt", "etc"),
  };
  try {
    for (const d of [s.tmp, s.home, s.bin, s.root, s.aptLists, s.aptCache, s.aptConf!,
                     path.join(s.aptLists, "partial"), path.join(s.aptCache, "partial")]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    s.aptConf = seedAptConf(s.aptConf!);
    scratchCache.set(base, s);
    return s;
  } catch { scratchCache.set(base, null); return null; } // açılamazsa uçucu tmpfs'e düş
}

function workerEnv(home: string, selected: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    // Kullanıcı kurulumları önce görünsün: dpkg -x ile /work/.hardtools/root içine açılan araçlar.
    PATH: `/work/.hardtools/bin:/work/.hardtools/root/usr/bin:/runtime:/usr/bin:/bin`,
    HOME: home, TMPDIR: "/tmp", LANG: "C.UTF-8", GIT_TERMINAL_PROMPT: "0", ...selected,
  };
}
/** /etc/apt'ı kazı alanına kopyalar ve kaynakları https'e çevirir: izole kabuğun çıkışı
 * yalnızca HTTPS:443 CONNECT ile olur, http://archive.ubuntu.com bu yüzden çalışmaz. */
function seedAptConf(dst: string): string | null {
  try {
    if (!fs.statSync("/etc/apt").isDirectory()) return null;
    const write = (from: string, to: string) => {
      if (!fs.existsSync(from)) return;
      let text = fs.readFileSync(from, "utf8");
      text = text.replace(/http:\/\//g, "https://");
      fs.writeFileSync(to, text, { mode: 0o644 });
    };
    write("/etc/apt/sources.list", path.join(dst, "sources.list"));
    const d = "/etc/apt/sources.list.d";
    if (fs.existsSync(d)) {
      const out = path.join(dst, "sources.list.d");
      fs.mkdirSync(out, { recursive: true, mode: 0o755 });
      for (const f of fs.readdirSync(d)) if (f.endsWith(".sources") || f.endsWith(".list")) write(path.join(d, f), path.join(out, f));
    }
    fs.mkdirSync(path.join(dst, "preferences.d"), { recursive: true, mode: 0o755 });
    const c = "/etc/apt/apt.conf.d";
    if (fs.existsSync(c)) {
      const out = path.join(dst, "apt.conf.d");
      fs.mkdirSync(out, { recursive: true, mode: 0o755 });
      fs.mkdirSync(path.join(out, "preferences.d"), { recursive: true, mode: 0o755 });
      for (const f of fs.readdirSync(c)) {
        try { fs.copyFileSync(path.join(c, f), path.join(out, f)); } catch { /* okunamayan parça atlanır */ }
      }
    }
    // bwrap --cap-drop ALL altında apt "_apt" kullanıcısına geçemiyor (setgroups EPERM);
    // sandbox kullanıcısını root yap ve yavaş aynalar için zaman aşımlarını uzat.
    fs.writeFileSync(path.join(dst, "apt.conf.d", "99hardtools"), [
      'APT::Sandbox::User "root";',
      'Acquire::https::Timeout "120";',
      'Acquire::http::Timeout "120";',
      'Acquire::Retries "3";',
      "",
    ].join("\n"), { mode: 0o644 });
    return dst;
  } catch { return null; }
}

/** /tmp + apt durumu. Kalıcı kazı alanı varsa proje hacmine bağlanır; yoksa eski uçucu tmpfs. */
function scratchBinds(p: Policy): string[] {
  const s = prepareScratch(p);
  if (!s) return ["--size", "67108864", "--tmpfs", "/tmp"];
  return [
    "--bind", s.tmp, "/tmp",
    // apt kaynakları görünür olsun (/etc/apt imajda var, sandbox'a bağlanmıyordu).
    // Kopya https'e çevrildi ve yazılabilir: apt-get update / apt-get download çalışır.
    ...(s.aptConf ? ["--bind", s.aptConf, "/etc/apt"] : ["--ro-bind-try", "/etc/apt", "/etc/apt"]),
    "--ro-bind-try", "/etc/passwd", "/etc/passwd", "--ro-bind-try", "/etc/group", "/etc/group",
    // Liste/önbellek yazılabilir: `apt-get update` ve `apt-get download` çalışır.
    "--dir", "/var", "--dir", "/var/lib", "--dir", "/var/lib/apt", "--dir", "/var/cache", "--dir", "/var/cache/apt",
    "--bind", s.aptLists, "/var/lib/apt/lists", "--bind", s.aptCache, "/var/cache/apt/archives",
    // dpkg veritabanı salt okunur: sistem geneline kurulum yapılamaz (kök salt okunur).
    "--ro-bind-try", "/var/lib/dpkg", "/var/lib/dpkg",
  ];
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
    ...scratchBinds(p),
    "--dev", "/dev", "--proc", "/proc", "--remount-ro", "/proc",
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
      const scratch = prepareScratch(p);
      return spawn(launcher, argv, { cwd: "/", env: workerEnv(scratch ? `/work/.hardtools/home` : "/tmp", selected), shell: false, detached: true,
        stdio: ["pipe", "pipe", "pipe", fd, ...(bridge === undefined ? [] : [bridge])] });
    } finally { if (bridge !== undefined) fs.closeSync(bridge); }
  });
}

/** Exercise the same fd mount before opening the HTTP endpoint. Never fall back to the host. */
export function probeWorkspaceShell(p: Policy): void {
  const argv = workspaceArgs(p, p.roots[0], "/runtime/node", ["--version"]);
  const scratch = prepareScratch(p);
  const child = withRuntimeFd(fd => spawnSync(launcher, argv, {
    cwd: "/", env: workerEnv(scratch ? "/work/.hardtools/home" : "/tmp"), shell: false, stdio: ["ignore", "pipe", "pipe", fd], encoding: "utf8", timeout: 5000,
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
