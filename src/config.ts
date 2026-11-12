// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";

export type ProfileName = "strict" | "balanced" | "open";

const FsSchema = z.object({
  writeEnabled: z.boolean(),
  maxReadBytes: z.number().int().positive(),
  maxWriteBytes: z.number().int().positive(),
  maxEditFiles: z.number().int().positive(),
  denyRead: z.array(z.string()),
  allowRead: z.array(z.string()),
  denyWrite: z.array(z.string()),
  secretScan: z.enum(["block", "warn", "off"]),
  requireHashForOverwrite: z.boolean(),
}).strict();

const ShellSchema = z.object({
  enabled: z.boolean(),
  allow: z.array(z.string()),
  denyArgs: z.array(z.string()),
  allowShellSyntax: z.boolean(),
  shellDenyPatterns: z.array(z.string()),
  allowRelativeExecutables: z.boolean(),
  confineArgPaths: z.boolean(),
  sanitizePath: z.boolean(),
  timeoutMs: z.number().int().positive(),
  maxTimeoutMs: z.number().int().positive(),
  maxOutputBytes: z.number().int().positive(),
  maxConcurrent: z.number().int().positive(),
  envAllow: z.array(z.string()),
}).strict();

const NetSchema = z.object({
  enabled: z.boolean(),
  schemes: z.array(z.enum(["http", "https"])),
  ports: z.array(z.number().int()),          // empty = any port
  allowDomains: z.array(z.string()),         // suffix match; empty = any public host (strict requires non-empty)
  denyDomains: z.array(z.string()),
  loopbackPorts: z.array(z.number().int()),  // explicit localhost exceptions
  requireAllowDomains: z.boolean(),
  maxBytes: z.number().int().positive(),
  timeoutMs: z.number().int().positive(),
  maxRedirects: z.number().int().nonnegative(),
  cacheTtlSec: z.number().int().nonnegative(),
}).strict();

const SearchSchema = z.object({
  maxFileBytes: z.number().int().positive(),
  maxResults: z.number().int().positive(),
  timeBudgetMs: z.number().int().positive(),
}).strict();

const AuditSchema = z.object({
  dir: z.string().nullable(),
  failClosed: z.boolean(),
}).strict();

const OverrideSchema = z.object({
  profile: z.enum(["strict", "balanced", "open"]),
  roots: z.array(z.string()),
  fs: FsSchema.partial(),
  shell: ShellSchema.partial(),
  net: NetSchema.partial(),
  search: SearchSchema.partial(),
  audit: AuditSchema.partial(),
}).strict().partial();

export interface Policy {
  profile: ProfileName;
  roots: string[];
  protectedDirs: string[];
  fs: z.infer<typeof FsSchema>;
  shell: z.infer<typeof ShellSchema>;
  net: z.infer<typeof NetSchema>;
  search: z.infer<typeof SearchSchema>;
  audit: z.infer<typeof AuditSchema>;
}

const SENSITIVE = [
  ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.kdbx",
  "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
  ".npmrc", ".netrc", ".pypirc", ".git-credentials",
  "**/.ssh/**", "**/.aws/**", "**/.gnupg/**", "**/.kube/config", "**/.docker/config.json",
];
const ENV_EXAMPLES = [".env.example", ".env.sample", ".env.template", ".env.dist"];

const DENY_ARGS = [
  "^--output(=|$)", "^--exec(=|$)", "^--exec-path", "^--upload-pack", "^--receive-pack",
  "^--ext-diff$", "^--textconv$", "^--open-files-in-pager", "^-c$", "^--config", "^--git-dir",
  "^--work-tree", "^--no-index$", "^--paginate$",
];

const READ_ONLY_CMDS = [
  "git status", "git diff", "git log", "git show", "git branch", "git rev-parse",
  "git ls-files", "git blame", "ls", "pwd", "wc", "head", "tail",
  "node --version", "npm --version", "python3 --version",
];

const BASE = {
  search: { maxFileBytes: 2 * 1024 * 1024, maxResults: 200, timeBudgetMs: 10_000 },
  audit: { dir: null as string | null, failClosed: false },
};

const PROFILES: Record<ProfileName, Omit<Policy, "profile" | "roots" | "protectedDirs">> = {
  strict: {
    fs: {
      writeEnabled: true, maxReadBytes: 1 << 20, maxWriteBytes: 512 << 10, maxEditFiles: 10,
      denyRead: SENSITIVE, allowRead: ENV_EXAMPLES,
      denyWrite: [".git", ".git/**", ".claude/**", ".mcp.json", ".github/workflows/**", ".husky/**",
        "**/.vscode/tasks.json", "**/.vscode/settings.json", "**/.devcontainer/**", ".gitmodules"],
      secretScan: "block", requireHashForOverwrite: true,
    },
    shell: {
      enabled: true, allow: READ_ONLY_CMDS, denyArgs: DENY_ARGS, allowShellSyntax: false,
      shellDenyPatterns: [], allowRelativeExecutables: false, confineArgPaths: true, sanitizePath: true,
      timeoutMs: 20_000, maxTimeoutMs: 60_000, maxOutputBytes: 64 << 10, maxConcurrent: 2,
      envAllow: ["PATH", "LANG", "LC_ALL", "TERM"],
    },
    net: {
      enabled: true, schemes: ["https"], ports: [443], allowDomains: [], denyDomains: ["metadata.google.internal"],
      loopbackPorts: [], requireAllowDomains: true, maxBytes: 1 << 20, timeoutMs: 15_000, maxRedirects: 3, cacheTtlSec: 300,
    },
    search: { ...BASE.search, maxFileBytes: 1 << 20, timeBudgetMs: 8_000 },
    audit: { ...BASE.audit, failClosed: true },
  },
  balanced: {
    fs: {
      writeEnabled: true, maxReadBytes: 2 << 20, maxWriteBytes: 1 << 20, maxEditFiles: 25,
      denyRead: SENSITIVE, allowRead: ENV_EXAMPLES,
      denyWrite: [".git", ".git/**", ".claude/**", ".mcp.json", ".husky/**", ".gitmodules"],
      secretScan: "block", requireHashForOverwrite: true,
    },
    shell: {
      enabled: true,
      allow: [...READ_ONLY_CMDS, "git add", "git commit", "git checkout", "git switch", "git stash", "git restore",
        "npm test", "npm run test", "npm run build", "npm run lint", "npx tsc", "tsc", "node --test",
        "pytest", "python3 -m pytest", "cargo build", "cargo test", "cargo check", "go build", "go test", "go vet"],
      denyArgs: DENY_ARGS, allowShellSyntax: false, shellDenyPatterns: [], allowRelativeExecutables: false,
      confineArgPaths: true, sanitizePath: true,
      timeoutMs: 60_000, maxTimeoutMs: 300_000, maxOutputBytes: 128 << 10, maxConcurrent: 3,
      envAllow: ["PATH", "LANG", "LC_ALL", "TERM", "HOME", "USER", "TMPDIR", "CI", "NODE_ENV"],
    },
    net: {
      enabled: true, schemes: ["https", "http"], ports: [80, 443, 8080, 8443], allowDomains: [],
      denyDomains: ["metadata.google.internal"], loopbackPorts: [], requireAllowDomains: false,
      maxBytes: 2 << 20, timeoutMs: 20_000, maxRedirects: 5, cacheTtlSec: 300,
    },
    search: { ...BASE.search },
    audit: { ...BASE.audit },
  },
  open: {
    fs: {
      writeEnabled: true, maxReadBytes: 8 << 20, maxWriteBytes: 4 << 20, maxEditFiles: 100,
      denyRead: ["**/.ssh/**", "**/.aws/**", "**/.gnupg/**", "id_rsa*", "id_ed25519*", "id_ecdsa*"],
      allowRead: [], denyWrite: [".git", ".git/**"], secretScan: "warn", requireHashForOverwrite: false,
    },
    shell: {
      enabled: true, allow: ["*"], denyArgs: [], allowShellSyntax: true,
      // Best-effort tripwires, NOT a sandbox. A determined caller can bypass regexes.
      shellDenyPatterns: [
        "\\brm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\\s+(/|~|\\$HOME)", "\\bmkfs\\b", "\\bdd\\b[^|;&]*\\bof=/dev/",
        ":\\(\\)\\s*\\{.*\\};\\s*:", "\\b(curl|wget)\\b[^|;&]*\\|\\s*(sudo\\s+)?(ba|z)?sh\\b", ">\\s*/dev/sd[a-z]",
      ],
      allowRelativeExecutables: true, confineArgPaths: false, sanitizePath: false,
      timeoutMs: 120_000, maxTimeoutMs: 900_000, maxOutputBytes: 256 << 10, maxConcurrent: 4,
      envAllow: ["*"],
    },
    net: {
      enabled: true, schemes: ["https", "http"], ports: [], allowDomains: [], denyDomains: ["metadata.google.internal"],
      loopbackPorts: [], requireAllowDomains: false, maxBytes: 5 << 20, timeoutMs: 30_000, maxRedirects: 8, cacheTtlSec: 300,
    },
    search: { ...BASE.search, maxFileBytes: 4 << 20, timeBudgetMs: 20_000 },
    audit: { ...BASE.audit },
  },
};

export function defaultConfigPath(): string {
  return process.env.HARDTOOLS_CONFIG ?? path.join(os.homedir(), ".hardtools", "config.json");
}

export interface LoadOptions {
  profile?: ProfileName;
  roots?: string[];
  configPath?: string | null;
  override?: unknown;
  cwd?: string;
}

/**
 * Policy is loaded ONLY from an explicit env var / the user's home dir — never from the workspace,
 * otherwise a malicious repository could ship its own permissive policy.
 */
export function loadPolicy(opts: LoadOptions = {}): Policy {
  let file: unknown = {};
  const cfgPath = opts.configPath === undefined ? defaultConfigPath() : opts.configPath;
  let usedConfig: string | null = null;
  if (opts.override !== undefined) {
    file = opts.override;
  } else if (cfgPath && fs.existsSync(cfgPath)) {
    try { file = JSON.parse(fs.readFileSync(cfgPath, "utf8")); usedConfig = fs.realpathSync(cfgPath); }
    catch (e) { throw new Error(`hardtools: cannot parse config ${cfgPath}: ${(e as Error).message}`); }
  }
  const parsed = OverrideSchema.safeParse(file);
  if (!parsed.success) {
    throw new Error(`hardtools: invalid config (unknown/typo'd keys are rejected on purpose): ${parsed.error.issues.map(i => i.path.join(".") + ": " + i.message).join("; ")}`);
  }
  const o = parsed.data;
  const profile: ProfileName = opts.profile ?? (process.env.HARDTOOLS_PROFILE as ProfileName | undefined) ?? o.profile ?? "balanced";
  if (!(profile in PROFILES)) throw new Error(`hardtools: unknown profile "${profile}"`);
  const base = PROFILES[profile];

  const rootsIn = opts.roots ?? o.roots ?? (process.env.HARDTOOLS_ROOTS ? process.env.HARDTOOLS_ROOTS.split(path.delimiter).filter(Boolean) : [opts.cwd ?? process.cwd()]);
  const roots = validateRoots(rootsIn, profile);

  const auditDir = path.resolve(o.audit?.dir ?? base.audit.dir ?? path.join(os.homedir(), ".hardtools", "audit"));
  const protectedDirs = [auditDir, path.join(os.homedir(), ".hardtools")];
  if (usedConfig) protectedDirs.push(path.dirname(usedConfig));

  return {
    profile, roots,
    protectedDirs: [...new Set(protectedDirs.map(d => safeReal(d)))],
    fs: { ...base.fs, ...(o.fs ?? {}) },
    shell: { ...base.shell, ...(o.shell ?? {}) },
    net: { ...base.net, ...(o.net ?? {}) },
    search: { ...base.search, ...(o.search ?? {}) },
    audit: { ...base.audit, ...(o.audit ?? {}), dir: auditDir },
  };
}

function safeReal(p: string): string {
  let probe = path.resolve(p); const rest: string[] = [];
  for (;;) {
    try { return path.join(fs.realpathSync.native(probe), ...rest); }
    catch { const parent = path.dirname(probe); if (parent === probe) return path.resolve(p); rest.unshift(path.basename(probe)); probe = parent; }
  }
}

export function validateRoots(input: string[], profile: ProfileName): string[] {
  if (!input.length) throw new Error("hardtools: at least one root is required");
  const out: string[] = [];
  for (const r of input) {
    let real: string;
    try { real = fs.realpathSync.native(path.resolve(r)); }
    catch { throw new Error(`hardtools: root does not exist: ${r}`); }
    if (!fs.statSync(real).isDirectory()) throw new Error(`hardtools: root is not a directory: ${r}`);
    if (profile !== "open") {
      if (path.parse(real).root === real) throw new Error(`hardtools: refusing filesystem root as a root (${real}). Set HARDTOOLS_ROOTS to your project directory.`);
      if (real === safeReal(os.homedir())) throw new Error(`hardtools: refusing the home directory itself as a root (${real}). Use a project directory.`);
    }
    out.push(real);
  }
  return [...new Set(out)];
}
