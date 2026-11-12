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
  ports: z.array(z.number().int()),
  allowDomains: z.array(z.string()),
  denyDomains: z.array(z.string()),
  loopbackPorts: z.array(z.number().int()),
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
  "**/.ssh/**", "**/.aws/**", "**/.gnupg/**",
  "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
];
const ENV_EXAMPLES = [".env.example", ".env.sample", ".env.template", ".env.dist"];

const DENY_ARGS = [
  // Sadece gerçekten tehlikeli olanlar bırakıldı
  "^--upload-pack", "^--receive-pack",
];

const READ_ONLY_CMDS = [
  "git status", "git diff", "git log", "git show", "git branch", "git rev-parse",
  "git ls-files", "git blame", "git remote", "git config --get", "git describe",
  "ls", "pwd", "wc", "head", "tail", "cat", "less", "more",
  "grep", "rg", "ag", "find", "fd", "which", "whereis", "type",
  "node --version", "npm --version", "npx --version", "yarn --version", "pnpm --version",
  "python3 --version", "python --version", "pip --version", "pip3 --version",
  "cargo --version", "go version", "rustc --version",
  "docker --version", "kubectl version", "make --version",
];

const COMMON_CMDS = [
  ...READ_ONLY_CMDS,
  // git
  "git add", "git commit", "git checkout", "git switch", "git stash", "git restore",
  "git pull", "git fetch", "git push", "git merge", "git rebase", "git cherry-pick",
  "git reset", "git clean", "git tag", "git remote add", "git remote set-url",
  // node / js
  "npm", "npm install", "npm ci", "npm run", "npm test", "npm run test", "npm run build",
  "npm run lint", "npm run start", "npm run dev", "npx", "npx tsc", "tsc",
  "yarn", "yarn install", "yarn add", "yarn run", "yarn test", "yarn build",
  "pnpm", "pnpm install", "pnpm add", "pnpm run", "pnpm test", "pnpm build",
  "node", "node --test",
  // python
  "python", "python3", "pip", "pip3", "pip install", "pip3 install",
  "pytest", "python3 -m pytest", "python -m pytest",
  // rust / go
  "cargo", "cargo build", "cargo test", "cargo check", "cargo run", "cargo clippy",
  "go", "go build", "go test", "go run", "go vet", "go mod",
  // containers / k8s
  "docker", "docker build", "docker run", "docker ps", "docker images", "docker compose",
  "kubectl", "kubectl get", "kubectl apply", "kubectl describe", "kubectl logs",
  // genel
  "make", "make build", "make test", "make clean",
  "curl", "wget", "http", "https",
  "sed", "awk", "cut", "sort", "uniq", "tr", "xargs",
  "tar", "zip", "unzip", "gzip", "gunzip",
  "echo", "printf", "true", "false", "test", "[",
  "mkdir", "cp", "mv", "rm", "touch", "chmod", "chown",
  "env", "export", "unset", "printenv",
];

const BASE = {
  search: { maxFileBytes: 8 * 1024 * 1024, maxResults: 500, timeBudgetMs: 30_000 },
  audit: { dir: null as string | null, failClosed: false },
};

const COMMON_DOMAINS = [
  // paket kayıtları
  "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
  "crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org",
  // git / github
  "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
  "gitlab.com", "bitbucket.org", "git.sr.ht",
  // docker
  "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
  "ghcr.io", "quay.io",
  // cdn / genel
  "cdn.jsdelivr.net", "unpkg.com", "esm.sh", "deno.land",
  "nodejs.org", "npmmirror.com",
  // google / cloud metadata hariç yaygın
  "googleapis.com", "gstatic.com", "cloudflare.com", "cloudflarestorage.com",
];

const PROFILES: Record<ProfileName, Omit<Policy, "profile" | "roots" | "protectedDirs">> = {
  strict: {
    fs: {
      writeEnabled: true,
      maxReadBytes: 8 << 20,
      maxWriteBytes: 4 << 20,
      maxEditFiles: 50,
      denyRead: SENSITIVE,
      allowRead: ENV_EXAMPLES,
      denyWrite: [".git/hooks/**"], // sadece hook'lar
      secretScan: "warn",
      requireHashForOverwrite: false,
    },
    shell: {
      enabled: true,
      allow: COMMON_CMDS,
      denyArgs: DENY_ARGS,
      allowShellSyntax: true,
      shellDenyPatterns: [
        // sadece en bariz tehlikeli kalıplar
        "\\brm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\\s+(/|~)",
        "\\bmkfs\\b",
        ":\\(\\)\\s*\\{.*\\};\\s*:",
      ],
      allowRelativeExecutables: true,
      confineArgPaths: false,
      sanitizePath: false,
      timeoutMs: 120_000,
      maxTimeoutMs: 600_000,
      maxOutputBytes: 512 << 10,
      maxConcurrent: 6,
      envAllow: ["*"],
    },
    net: {
      enabled: true,
      schemes: ["https", "http"],
      ports: [80, 443, 8080, 8443, 3000, 5000, 5173, 8000, 8081],
      allowDomains: COMMON_DOMAINS,
      denyDomains: ["metadata.google.internal", "169.254.169.254"],
      loopbackPorts: [3000, 5000, 5173, 8000, 8080, 8081],
      requireAllowDomains: false,
      maxBytes: 10 << 20,
      timeoutMs: 60_000,
      maxRedirects: 10,
      cacheTtlSec: 300,
    },
    search: { ...BASE.search },
    audit: { ...BASE.audit },
  },
  balanced: {
    fs: {
      writeEnabled: true,
      maxReadBytes: 16 << 20,
      maxWriteBytes: 8 << 20,
      maxEditFiles: 100,
      denyRead: SENSITIVE,
      allowRead: ENV_EXAMPLES,
      denyWrite: [],
      secretScan: "warn",
      requireHashForOverwrite: false,
    },
    shell: {
      enabled: true,
      allow: ["*"], // neredeyse her şey
      denyArgs: DENY_ARGS,
      allowShellSyntax: true,
      shellDenyPatterns: [
        "\\brm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\\s+(/|~)",
        "\\bmkfs\\b",
      ],
      allowRelativeExecutables: true,
      confineArgPaths: false,
      sanitizePath: false,
      timeoutMs: 180_000,
      maxTimeoutMs: 900_000,
      maxOutputBytes: 1 << 20,
      maxConcurrent: 8,
      envAllow: ["*"],
    },
    net: {
      enabled: true,
      schemes: ["https", "http"],
      ports: [],
      allowDomains: COMMON_DOMAINS,
      denyDomains: ["metadata.google.internal", "169.254.169.254"],
      loopbackPorts: [3000, 5000, 5173, 8000, 8080, 8081, 9229],
      requireAllowDomains: false,
      maxBytes: 20 << 20,
      timeoutMs: 90_000,
      maxRedirects: 15,
      cacheTtlSec: 300,
    },
    search: { ...BASE.search, maxFileBytes: 16 << 20, timeBudgetMs: 45_000 },
    audit: { ...BASE.audit },
  },
  open: {
    fs: {
      writeEnabled: true,
      maxReadBytes: 64 << 20,
      maxWriteBytes: 32 << 20,
      maxEditFiles: 500,
      denyRead: [],
      allowRead: [],
      denyWrite: [],
      secretScan: "off",
      requireHashForOverwrite: false,
    },
    shell: {
      enabled: true,
      allow: ["*"],
      denyArgs: [],
      allowShellSyntax: true,
      shellDenyPatterns: [],
      allowRelativeExecutables: true,
      confineArgPaths: false,
      sanitizePath: false,
      timeoutMs: 300_000,
      maxTimeoutMs: 1_800_000,
      maxOutputBytes: 4 << 20,
      maxConcurrent: 12,
      envAllow: ["*"],
    },
    net: {
      enabled: true,
      schemes: ["https", "http"],
      ports: [],
      allowDomains: [],
      denyDomains: ["metadata.google.internal"],
      loopbackPorts: [],
      requireAllowDomains: false,
      maxBytes: 50 << 20,
      timeoutMs: 120_000,
      maxRedirects: 20,
      cacheTtlSec: 60,
    },
    search: { ...BASE.search, maxFileBytes: 32 << 20, timeBudgetMs: 60_000 },
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
    try {
      file = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
      usedConfig = fs.realpathSync(cfgPath);
    } catch (e) {
      throw new Error(`hardtools: cannot parse config ${cfgPath}: ${(e as Error).message}`);
    }
  }
  const parsed = OverrideSchema.safeParse(file);
  if (!parsed.success) {
    throw new Error(
      `hardtools: invalid config (unknown/typo'd keys are rejected on purpose): ${parsed.error.issues
        .map((i) => i.path.join(".") + ": " + i.message)
        .join("; ")}`,
    );
  }
  const o = parsed.data;
  const profile: ProfileName =
    opts.profile ?? (process.env.HARDTOOLS_PROFILE as ProfileName | undefined) ?? o.profile ?? "balanced";
  if (!(profile in PROFILES)) throw new Error(`hardtools: unknown profile "${profile}"`);
  const base = PROFILES[profile];

  const rootsIn =
    opts.roots ??
    o.roots ??
    (process.env.HARDTOOLS_ROOTS
      ? process.env.HARDTOOLS_ROOTS.split(path.delimiter).filter(Boolean)
      : [opts.cwd ?? process.cwd()]);
  const roots = validateRoots(rootsIn, profile);

  const auditDir = path.resolve(
    o.audit?.dir ?? base.audit.dir ?? path.join(os.homedir(), ".hardtools", "audit"),
  );
  const protectedDirs = [auditDir, path.join(os.homedir(), ".hardtools")];
  if (usedConfig) protectedDirs.push(path.dirname(usedConfig));

  return {
    profile,
    roots,
    protectedDirs: [...new Set(protectedDirs.map((d) => safeReal(d)))],
    fs: { ...base.fs, ...(o.fs ?? {}) },
    shell: { ...base.shell, ...(o.shell ?? {}) },
    net: { ...base.net, ...(o.net ?? {}) },
    search: { ...base.search, ...(o.search ?? {}) },
    audit: { ...base.audit, ...(o.audit ?? {}), dir: auditDir },
  };
}

function safeReal(p: string): string {
  let probe = path.resolve(p);
  const rest: string[] = [];
  for (;;) {
    try {
      return path.join(fs.realpathSync.native(probe), ...rest);
    } catch {
      const parent = path.dirname(probe);
      if (parent === probe) return path.resolve(p);
      rest.unshift(path.basename(probe));
      probe = parent;
    }
  }
}

export function validateRoots(input: string[], profile: ProfileName): string[] {
  if (!input.length) throw new Error("hardtools: at least one root is required");
  const out: string[] = [];
  for (const r of input) {
    let real: string;
    try {
      real = fs.realpathSync.native(path.resolve(r));
    } catch {
      throw new Error(`hardtools: root does not exist: ${r}`);
    }
    if (!fs.statSync(real).isDirectory()) throw new Error(`hardtools: root is not a directory: ${r}`);
    if (profile !== "open") {
      if (path.parse(real).root === real)
        throw new Error(
          `hardtools: refusing filesystem root as a root (${real}). Set HARDTOOLS_ROOTS to your project directory.`,
        );
      if (real === safeReal(os.homedir()))
        throw new Error(
          `hardtools: refusing the home directory itself as a root (${real}). Use a project directory.`,
        );
    }
    out.push(real);
  }
  return [...new Set(out)];
}
