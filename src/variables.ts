import type { Policy } from "./config.js";
import { PolicyError } from "./guard.js";
import type { Persist } from "./persist.js";

// Never set a loader, interpreter, credential helper, or host process variable. A short
// user name becomes HT_VAR_<name>; application-owned names can be used verbatim.
export function varName(input: string): string {
  if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(input)) throw new PolicyError("bad_var", "invalid variable name (ASCII letters, digits and underscores only)");
  const name = input.toUpperCase();
  const key = /^(?:HT_VAR_|APP_|MY_|PROJECT_).+/.test(name) ? name : `HT_VAR_${name}`;
  if (key.length > 64) throw new PolicyError("bad_var", "effective name exceeds 64 characters");
  return key;
}

const MAX_VARS = 32, MAX_SCOPES = 128, IDLE_MS = 12 * 3_600_000;
export class Variables {
  private scopes = new Map<string, { at: number; vars: Map<string, string> }>();
  constructor(private persist?: Persist) {
    const saved = persist?.read<Record<string, { at: number; vars: [string, string][] }>>({}) ?? {};
    const now = Date.now();
    for (const [owner, v] of Object.entries(saved))
      if (v && now - v.at < IDLE_MS && Array.isArray(v.vars)) this.scopes.set(owner, { at: v.at, vars: new Map(v.vars) });
  }
  private save() {
    if (!this.persist) return;
    const out: Record<string, { at: number; vars: [string, string][] }> = {};
    for (const [owner, v] of this.scopes) out[owner] = { at: v.at, vars: [...v.vars] };
    this.persist.write(out);
  }
  private scope(p: Policy, owner: string, create = false) {
    if (!p.shell.enabled) throw new PolicyError("shell_disabled", "shell variables require an enabled shell");
    const now = Date.now();
    for (const [k, v] of this.scopes) if (now - v.at >= IDLE_MS) this.scopes.delete(k);
    let s = this.scopes.get(owner);
    if (create && !s) {
      if (this.scopes.size >= MAX_SCOPES) throw new PolicyError("var_limit", "active variable scope limit reached");
      this.scopes.set(owner, s = { at: now, vars: new Map() });
    }
    if (s) s.at = now;
    return s?.vars;
  }
  add(p: Policy, owner: string, a: { name: string; value: string; overwrite?: boolean }) {
    const key = varName(a.name);
    if (a.value.includes("\0") || Buffer.byteLength(a.value) > 4096) throw new PolicyError("bad_value", "value must have no NUL and fit in 4096 bytes");
    if (Object.keys(process.env).some(k => k.toUpperCase() === key)) throw new PolicyError("reserved_var", "cannot shadow an existing host variable");
    const vars = this.scope(p, owner, true)!;
    if (vars.has(key) && !a.overwrite) throw new PolicyError("var_exists", "already set; use overwrite=true to replace");
    if (!vars.has(key) && vars.size >= MAX_VARS) throw new PolicyError("var_limit", `maximum ${MAX_VARS} variables`);
    vars.set(key, a.value);
    this.save();
    return `SET ${key}; pass its name in ht_shell.inherit_vars to use it`;
  }
  /** Drop every variable of this scope (used when the environment is reset). */
  clear(owner: string): number {
    const s = this.scopes.get(owner);
    this.scopes.delete(owner);
    this.save();
    return s ? s.vars.size : 0;
  }
  list(p: Policy, owner: string): string {
    return JSON.stringify({ names: [...(this.scope(p, owner)?.keys() ?? [])].sort() });
  }
  remove(p: Policy, owner: string, name: string): string {
    const key = varName(name), vars = this.scope(p, owner);
    if (!vars?.delete(key)) return `NOT SET ${key}`;
    if (!vars.size) this.scopes.delete(owner);
    this.save();
    return `DELETED ${key}`;
  }
  select(p: Policy, owner: string, names: string[] = []): NodeJS.ProcessEnv {
    const out: NodeJS.ProcessEnv = Object.create(null);
    if (!names.length) return out;
    if (names.length > MAX_VARS) throw new PolicyError("var_limit", `select at most ${MAX_VARS} variables`);
    const vars = this.scope(p, owner);
    for (const name of names) {
      const key = varName(name), v = vars?.get(key);
      if (v === undefined) throw new PolicyError("var_missing", `no such session variable: ${key}`);
      out[key] = v;
    }
    return out;
  }
}
