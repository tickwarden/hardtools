// Capability-URL user input: the model asks a question, the user answers it in a browser
// form, and the answer appears to shell commands as $HT_USER_INPUT. Secret answers are
// never echoed back to the model or written to the audit log, and are masked in shell
// output.
//
// 0.5.1 — v2:
//   * multi-field forms (`fields`) answered once, exposed as $HT_USER_INPUT (JSON) plus
//     $HT_USER_INPUT_<NAME> per field,
//   * choices / default / placeholder / help for every field,
//   * long-poll (`wait`) so the model does not have to ask the user to "call get again",
//   * dedupe keys, listing, cancelling, and a browser "Vazgeç" button,
//   * per-request status transitions (pending → ready/cancelled/expired).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";
import { PolicyError } from "./guard.js";

export type InputKind = "string" | "boolean" | "number" | "array" | "null";

export interface InputField {
  /** Suffix for $HT_USER_INPUT_<NAME>; must match /^[A-Za-z][A-Za-z0-9_]{0,31}$/. */
  name: string;
  title: string;
  kind: InputKind;
  secret: boolean;
  required: boolean;
  choices?: string[];
  multiple?: boolean; // choices ile birlikte: onay kutuları (çoklu seçim)
  default?: string;
  placeholder?: string;
  help?: string;
}

export interface InputRequest {
  id: string;
  title: string;
  kind: InputKind;
  secret: boolean;
  fields?: InputField[];
  createdAt: number;
  expiresAt: number;
  submittedAt?: number;
  cancelledAt?: number;
  dedupeKey?: string;
  choices?: string[];
  default?: string;
  placeholder?: string;
  help?: string;
  value?: unknown;
  values?: Record<string, unknown>;
}

export interface CreateOptions {
  title: string;
  kind: InputKind;
  secret: boolean;
  ttlMs: number;
  fields?: InputField[];
  choices?: string[];
  default?: string;
  placeholder?: string;
  help?: string;
  dedupeKey?: string;
}

const MAX_TEXT = 8192;
const MAX_ARRAY_ITEMS = 100;
const MAX_ARRAY_BYTES = 32768;
const MAX_REQUESTS = 32;
const MAX_SECRETS = 16;
const MAX_FIELDS = 8;
const MAX_CHOICES = 50;
const NAME_RE = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
const KINDS: InputKind[] = ["string", "boolean", "number", "array", "null"];

const esc = (v: string) => v.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

/** Parse the browser payload for the requested type; every failure is a 400, never a guess. */
export function parseValue(kind: InputKind, raw: string): unknown {
  if (typeof raw !== "string") throw new PolicyError("bad_input", "value must be a string");
  if (raw.length > MAX_TEXT) throw new PolicyError("bad_input", `value is longer than ${MAX_TEXT} characters`);
  switch (kind) {
    case "string": return raw;
    case "boolean":
      if (raw === "true") return true;
      if (raw === "false") return false;
      throw new PolicyError("bad_input", "expected true or false");
    case "number": {
      if (!raw.trim() || !/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(raw.trim())) throw new PolicyError("bad_input", "expected a number");
      const n = Number(raw);
      if (!Number.isFinite(n)) throw new PolicyError("bad_input", "expected a finite number");
      return n;
    }
    case "array": {
      if (raw.length > MAX_ARRAY_BYTES) throw new PolicyError("bad_input", "array payload is too large");
      let parsed: unknown;
      try { parsed = JSON.parse(raw); } catch { throw new PolicyError("bad_input", "expected a JSON array, e.g. [\"a\",\"b\"]"); }
      if (!Array.isArray(parsed)) throw new PolicyError("bad_input", "expected a JSON array");
      if (parsed.length > MAX_ARRAY_ITEMS) throw new PolicyError("bad_input", `at most ${MAX_ARRAY_ITEMS} items`);
      for (const item of parsed) if (item !== null && !["string", "number", "boolean"].includes(typeof item)) throw new PolicyError("bad_input", "array items must be strings, numbers, booleans or null");
      return parsed;
    }
    case "null":
      if (raw.trim() !== "" && raw.trim().toLowerCase() !== "null") throw new PolicyError("bad_input", "expected an empty answer");
      return null;
  }
}

/** Render the browser answer as $HT_USER_INPUT: strings verbatim, everything else as JSON. */
export function renderEnv(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** Env var name for one field of a multi-field form. */
export function fieldEnvName(name: string): string {
  return `HT_USER_INPUT_${name.toUpperCase()}`;
}

function normalizeChoices(choices: unknown): string[] | undefined {
  if (choices === undefined) return undefined;
  if (!Array.isArray(choices) || !choices.length) throw new PolicyError("bad_input", "choices must be a non-empty array of strings");
  if (choices.length > MAX_CHOICES) throw new PolicyError("bad_input", `at most ${MAX_CHOICES} choices`);
  const out: string[] = [];
  for (const c of choices) {
    if (typeof c !== "string" || !c.trim()) throw new PolicyError("bad_input", "choices must be non-empty strings");
    if (c.length > 200) throw new PolicyError("bad_input", "a choice is longer than 200 characters");
    if (!out.includes(c)) out.push(c);
  }
  return out;
}

function normalizeField(raw: unknown, index: number): InputField {
  if (!raw || typeof raw !== "object") throw new PolicyError("bad_input", `fields[${index}] must be an object`);
  const f = raw as Record<string, unknown>;
  const name = String(f.name ?? "").trim();
  if (!NAME_RE.test(name)) throw new PolicyError("bad_input", `fields[${index}].name must match ${NAME_RE} (it becomes $${fieldEnvName(name || "NAME")})`);
  const title = String(f.title ?? "").trim();
  if (!title || title.length > 200) throw new PolicyError("bad_input", `fields[${index}].title must be 1–200 characters`);
  const multiple = Boolean(f.multiple);
  const kind = (multiple ? "array" : (f.kind ?? "string")) as InputKind;
  if (!KINDS.includes(kind)) throw new PolicyError("bad_input", `fields[${index}].kind must be one of ${KINDS.join(", ")}`);
  const choices = normalizeChoices(f.choices);
  if (multiple && !choices) throw new PolicyError("bad_input", `fields[${index}].multiple needs choices`);
  const def = f.default === undefined || f.default === null ? undefined : String(f.default);
  if (def !== undefined && def.length > MAX_TEXT) throw new PolicyError("bad_input", `fields[${index}].default is too long`);
  if (choices && def !== undefined && !choices.includes(def)) throw new PolicyError("bad_input", `fields[${index}].default must be one of the choices`);
  const placeholder = f.placeholder === undefined ? undefined : String(f.placeholder).slice(0, 200);
  const help = f.help === undefined ? undefined : String(f.help).slice(0, 400);
  return { name, title, kind, secret: Boolean(f.secret), required: f.required === undefined ? true : Boolean(f.required), ...(choices ? { choices } : {}), ...(multiple ? { multiple: true } : {}), ...(def !== undefined ? { default: def } : {}), ...(placeholder ? { placeholder } : {}), ...(help ? { help } : {}) };
}

export class UserInputs {
  private byId = new Map<string, InputRequest>();
  private active = new Map<string, string>(); // owner -> request id
  private owners = new Map<string, string>(); // request id -> owner
  private secrets: string[] = [];
  private waiters = new Map<string, Set<() => void>>(); // request id -> resolvers
  private store?: string;

  /** store verilirse açık/yanıtlanmış formlar diske yazılır: sunucu yeniden başlasa da cevap kaybolmaz.
   * Sır içeren formlar bilerek diske yazılmaz. */
  constructor(opts: { store?: string } = {}) {
    this.store = opts.store;
    this.restore();
  }

  private save(): void {
    if (!this.store) return;
    try {
      const now = Date.now();
      const items: unknown[] = [];
      for (const r of this.byId.values()) {
        if (r.expiresAt < now && r.submittedAt === undefined) continue;      // süresi geçmiş
        if (r.secret || r.fields?.some(f => f.secret)) continue;             // sır diske yazılmaz
        items.push({ ...r, owner: this.owners.get(r.id) ?? "" });
      }
      fs.mkdirSync(path.dirname(this.store), { recursive: true, mode: 0o700 });
      const tmp = this.store + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify({ v: 1, items }), { mode: 0o600 });
      fs.renameSync(tmp, this.store);
    } catch { /* disk hatası aracı düşürmesin */ }
  }

  private restore(): void {
    if (!this.store) return;
    try {
      if (!fs.existsSync(this.store)) return;
      const data = JSON.parse(fs.readFileSync(this.store, "utf8")) as { v?: number; items?: unknown[] };
      const now = Date.now();
      for (const raw of data.items ?? []) {
        const r = raw as InputRequest & { owner?: string };
        if (!r?.id || typeof r.expiresAt !== "number") continue;
        if (r.expiresAt < now && r.submittedAt === undefined) continue;
        this.byId.set(r.id, r);
        const owner = r.owner ?? "";
        if (owner) {
          this.owners.set(r.id, owner);
          if (r.submittedAt === undefined && r.cancelledAt === undefined) this.active.set(owner, r.id);
        }
      }
    } catch { /* bozuk dosya: boş başla */ }
  }

  create(owner: string, o: CreateOptions): InputRequest {
    if (!KINDS.includes(o.kind)) throw new PolicyError("bad_input", `kind must be one of ${KINDS.join(", ")}`);
    const title = (o.title ?? "").trim();
    if (!title || title.length > 200) throw new PolicyError("bad_input", "title must be 1–200 characters");
    this.prune();

    let fields: InputField[] | undefined;
    if (o.fields && o.fields.length) {
      if (o.fields.length > MAX_FIELDS) throw new PolicyError("bad_input", `at most ${MAX_FIELDS} fields`);
      fields = o.fields.map(normalizeField);
      const seen = new Set<string>();
      for (const f of fields) {
        const key = f.name.toLowerCase();
        if (seen.has(key)) throw new PolicyError("bad_input", `duplicate field name: ${f.name}`);
        seen.add(key);
      }
      if (!fields.some(f => f.required)) fields[0].required = true;
    }

    const dedupeKey = o.dedupeKey ? String(o.dedupeKey).slice(0, 200) : undefined;
    if (dedupeKey) {
      for (const r of this.byId.values()) {
        if (r.dedupeKey === dedupeKey && this.active.get(owner) === r.id && r.expiresAt > Date.now() && r.submittedAt === undefined && r.cancelledAt === undefined) return r;
      }
    }

    if (this.byId.size >= MAX_REQUESTS) throw new PolicyError("too_many_requests", "too many open input requests; clear one first");
    const id = crypto.randomBytes(24).toString("base64url");
    const now = Date.now();
    const choices = normalizeChoices(o.choices);
    const def = o.default === undefined ? undefined : String(o.default).slice(0, MAX_TEXT);
    if (choices && def !== undefined && !choices.includes(def)) throw new PolicyError("bad_input", "default must be one of the choices");
    const req: InputRequest = {
      id, title, kind: o.kind, secret: o.secret,
      ...(fields ? { fields } : {}),
      ...(choices ? { choices } : {}),
      ...(def !== undefined ? { default: def } : {}),
      ...(o.placeholder ? { placeholder: String(o.placeholder).slice(0, 200) } : {}),
      ...(o.help ? { help: String(o.help).slice(0, 400) } : {}),
      ...(dedupeKey ? { dedupeKey } : {}),
      createdAt: now,
      expiresAt: now + Math.max(60_000, Math.min(3_600_000, o.ttlMs)),
    } as InputRequest;
    this.byId.set(id, req);
    this.owners.set(id, owner);
    this.active.set(owner, id);
    this.save();
    return req;
  }

  get(owner: string, id?: string): InputRequest {
    const key = id ?? this.active.get(owner);
    const req = key ? this.byId.get(key) : undefined;
    if (!req) throw new PolicyError("not_found", "no open input request (expired or already answered and cleared)");
    if (req.expiresAt < Date.now()) throw new PolicyError("not_found", "no open input request (expired or already answered and cleared)");
    return req;
  }

  status(req: InputRequest): "pending" | "ready" | "cancelled" | "expired" {
    if (req.submittedAt !== undefined) return "ready";
    if (req.cancelledAt !== undefined) return "cancelled";
    if (req.expiresAt < Date.now()) return "expired";
    return "pending";
  }

  /** Submit a browser answer. The request id is the capability; a second answer is refused. */
  submit(id: string, raw: string | Record<string, string>): InputRequest {
    const req = this.byId.get(id);
    if (!req) throw new PolicyError("not_found", "this input request does not exist or was already cleared");
    if (req.expiresAt < Date.now()) { this.byId.delete(id); throw new PolicyError("expired", "this input request expired; ask again from the chat"); }
    if (req.submittedAt !== undefined) throw new PolicyError("already_answered", "this input was already submitted once");
    if (req.cancelledAt !== undefined) throw new PolicyError("cancelled", "this input request was cancelled");

    if (req.fields) {
      const payload = typeof raw === "string" ? { [req.fields[0].name]: raw } : raw;
      const values: Record<string, unknown> = {};
      for (const f of req.fields) {
        const text = payload[f.name] ?? "";
        if (text === "" && f.default !== undefined) { values[f.name] = this.coerce(f, f.default); continue; }
        if (text === "" && f.kind === "null") { values[f.name] = null; continue; }
        if (text === "" && !f.required) { values[f.name] = null; continue; }
        if (text === "" && f.required) throw new PolicyError("bad_input", `${f.title} is required`);
        values[f.name] = this.coerce(f, text);
      }
      req.values = values;
      for (const f of req.fields) if (f.secret && values[f.name] !== null && values[f.name] !== undefined) this.rememberSecret(renderEnv(values[f.name]));
      if (req.fields.some(f => f.secret)) this.rememberSecret(JSON.stringify(values));
    } else {
      const text = typeof raw === "string" ? raw : (raw.value ?? "");
      const value = parseValue(req.kind, text);
      const choices = (req as InputRequest & { choices?: string[] }).choices;
      if (choices) {
        if (value === null || !choices.includes(String(value))) throw new PolicyError("bad_input", "answer must be one of the offered choices");
      }
      req.value = value;
      if (req.secret) this.rememberSecret(renderEnv(value));
    }
    req.submittedAt = Date.now();
    this.save();
    this.notify(id);
    return req;
  }

  private coerce(f: InputField, text: string): unknown {
    const value = parseValue(f.kind, text);
    if (f.multiple && f.choices) {
      if (!Array.isArray(value)) throw new PolicyError("bad_input", `${f.title} beklenen biçimde değil`);
      for (const v of value) if (!f.choices.includes(String(v))) throw new PolicyError("bad_input", `${f.title}: seçeneklerden biri değil`);
      return value;
    }
    if (f.choices) {
      if (value === null || !f.choices.includes(String(value))) throw new PolicyError("bad_input", `${f.title} must be one of the offered choices`);
    }
    return value;
  }

  /** Cancel an open request from the browser; the model sees status=cancelled. */
  cancel(id: string): boolean {
    const req = this.byId.get(id);
    if (!req || req.submittedAt !== undefined || req.cancelledAt !== undefined) return false;
    req.cancelledAt = Date.now();
    this.save();
    this.notify(id);
    return true;
  }

  /** Wait until the user answers (or the timeout elapses); resolves with the request. */
  async wait(owner: string, id: string | undefined, ms: number, signal?: AbortSignal): Promise<InputRequest | undefined> {
    const deadline = Date.now() + Math.max(0, Math.min(120_000, ms));
    const check = (): InputRequest | undefined => {
      const k = id ?? this.active.get(owner);
      return k ? this.byId.get(k) : undefined;
    };
    const settled = (r?: InputRequest) => !!r && (r.submittedAt !== undefined || r.cancelledAt !== undefined);
    if (settled(check())) return check();
    while (Date.now() < deadline && !signal?.aborted) {
      await new Promise<void>(resolve => {
        const k = id ?? this.active.get(owner) ?? "";
        const set = this.waiters.get(k) ?? new Set<() => void>();
        const fire = () => { clearTimeout(timer); set.delete(fire); resolve(); };
        const timer = setTimeout(fire, Math.min(200, Math.max(1, deadline - Date.now())));
        set.add(fire);
        this.waiters.set(k, set);
      });
      const r = check();
      if (settled(r)) return r;
      if (r && r.expiresAt < Date.now()) return r;
    }
    return check();
  }

  private notify(id: string) {
    const set = this.waiters.get(id);
    if (!set) return;
    this.waiters.delete(id);
    for (const fn of set) fn();
  }

  /** Current unexpired, un-cancelled answer of this owner, if any. */
  value(owner: string): { request: InputRequest; env: string } | undefined {
    const key = this.active.get(owner);
    const req = key ? this.byId.get(key) : undefined;
    if (!req || req.submittedAt === undefined || req.cancelledAt !== undefined || req.expiresAt < Date.now()) return undefined;
    return { request: req, env: req.fields ? JSON.stringify(req.values ?? {}) : renderEnv(req.value) };
  }

  /** Environment for shell children; absent until the user answers. */
  envFor(owner: string): Record<string, string> {
    const v = this.value(owner);
    if (!v) return {};
    const out: Record<string, string> = { HT_USER_INPUT: v.env };
    if (v.request.fields) {
      for (const f of v.request.fields) {
        const raw = (v.request.values ?? {})[f.name];
        if (raw !== null && raw !== undefined) out[fieldEnvName(f.name)] = renderEnv(raw);
      }
    }
    return out;
  }

  /** Model-facing shape of an answered request (secrets replaced with null). */
  view(req: InputRequest): Record<string, unknown> {
    const base = {
      request_id: req.id,
      status: this.status(req),
      expires_in_s: Math.max(0, Math.round((req.expiresAt - Date.now()) / 1000)),
      title: req.title,
      env: "HT_USER_INPUT",
    };
    if (req.fields) {
      const values: Record<string, unknown> = {};
      const filled: Record<string, boolean> = {};
      for (const f of req.fields) {
        const raw = (req.values ?? {})[f.name];
        // Sır asla modele dönmez: değer yerine null, doluluk ayrı bayrakta.
        values[f.name] = f.secret ? null : raw ?? null;
        filled[f.name] = raw !== null && raw !== undefined;
      }
      return {
        ...base,
        kind: "form",
        fields: req.fields.map(f => ({ name: f.name, title: f.title, kind: f.kind, secret: f.secret, required: f.required, env: fieldEnvName(f.name) })),
        secret: req.fields.some(f => f.secret),
        values,
        filled,
      };
    }
    return {
      ...base,
      kind: req.kind,
      secret: req.secret,
      value: req.secret ? null : req.value ?? null,
      ...(req.secret ? { filled: req.submittedAt !== undefined } : {}),
    };
  }

  clear(owner: string, id?: string): boolean {
    const key = id ?? this.active.get(owner);
    if (!key) return false;
    const req = this.byId.get(key);
    if (req?.secret && req.value !== undefined) this.forgetSecret(renderEnv(req.value));
    if (req?.fields?.some(f => f.secret)) this.forgetSecret(JSON.stringify(req.values ?? {}));
    if (req) {
      for (const f of req.fields ?? []) {
        const raw = (req.values ?? {})[f.name];
        if (f.secret && raw !== null && raw !== undefined) this.forgetSecret(renderEnv(raw));
      }
    }
    this.byId.delete(key);
    if (this.active.get(owner) === key) this.active.delete(owner);
    return true;
  }

  /** Open requests of this owner (never includes values). */
  list(owner: string): Record<string, unknown>[] {
    const out: Record<string, unknown>[] = [];
    for (const [id, r] of this.byId) {
      if (this.active.get(owner) !== id) continue;
      out.push({ request_id: id, title: r.title, status: this.status(r), kind: r.fields ? "form" : r.kind, secret: r.fields ? r.fields.some(f => f.secret) : r.secret, expires_in_s: Math.max(0, Math.round((r.expiresAt - Date.now()) / 1000)) });
    }
    return out;
  }

  /** Never let a secret come back to the model through command output. */
  mask(text: string): string {
    if (!text || !this.secrets.length) return text;
    let out = text;
    for (const s of this.secrets) if (s.length >= 4 && out.includes(s)) out = out.split(s).join("[redacted:HT_USER_INPUT]");
    return out;
  }

  private rememberSecret(env: string) {
    if (env.length < 4) return; // too short to redact meaningfully without mangling output
    this.secrets = [env, ...this.secrets.filter(s => s !== env)].slice(0, MAX_SECRETS);
  }
  private forgetSecret(env: string) { this.secrets = this.secrets.filter(s => s !== env); }

  private prune() {
    const now = Date.now();
    for (const [id, r] of this.byId) if (r.expiresAt < now) { if (r.secret && r.value !== undefined) this.forgetSecret(renderEnv(r.value)); this.byId.delete(id); }
  }

  // ---- browser UI -------------------------------------------------------------------
  /** Serve /ui/input/<id>. Returns false when the path is not ours. */
  handle(req: IncomingMessage, res: ServerResponse, path: string, origin: string): boolean {
    const m = /^\/ui\/input\/([A-Za-z0-9_-]{20,64})$/.exec(path);
    if (!m) return false;
    const id = m[1];
    const req_ = this.byId.get(id);
    const headers = {
      "cache-control": "no-store", "referrer-policy": "no-referrer", "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    };
    const page = (code: number, body: string) => { res.writeHead(code, { "content-type": "text/html; charset=utf-8", ...headers }); res.end(body); };
    const shell = (body: string) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>hardtools</title>
<style>body{font:16px system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5}input[type=text],input[type=password],input[type=number],select,textarea{width:100%;padding:.6rem;box-sizing:border-box;font:14px ui-monospace,monospace;margin-top:.25rem}button{padding:.6rem 1.2rem;margin:.8rem .4rem 0 0;cursor:pointer}.m{color:#555;font-size:14px}.e{color:#b00020}label{display:block;margin:1rem 0 .3rem;font-weight:600}.h{color:#555;font-size:13px;font-weight:400;margin-top:.2rem}fieldset{border:0;padding:0;margin:0}.q{font-size:18px}.sec{background:#fff6f6;border:1px solid #f0c0c0;border-radius:6px;padding:.6rem;margin-top:1rem}</style>
<h1>hardtools</h1>${body}`;

    if (!req_) return page(410, shell(`<p class="e">Bu istek bulunamadı ya da süresi doldu. Sohbetten yeniden iste.</p>`)), true;
    if (this.status(req_) === "cancelled") return page(410, shell(`<p class="e">Bu istek iptal edildi.</p>`)), true;
    if (req_.expiresAt < Date.now()) return page(410, shell(`<p class="e">Bu istek bulunamadı ya da süresi doldu. Sohbetten yeniden iste.</p>`)), true;
    if (req_.submittedAt !== undefined) return page(409, shell(`<p class="e">Bu istek zaten yanıtlandı. Yeni bir istek için sohbetten tekrar iste.</p>`)), true;

    if (req.method === "POST") {
      let size = 0; const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => { size += c.length; if (size <= 65536) chunks.push(c); });
      req.on("end", () => {
        if (size > 65536) return page(413, shell(`<p class="e">Yanıt çok büyük.</p>`));
        const params = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        if (params.get("action") === "cancel") {
          this.cancel(id);
          return page(200, shell(`<p>Vazgeçildi. Sohbete dönüp modeli bilgilendir.</p>`));
        }
        try {
          const value = req_.fields
            ? this.submit(id, Object.fromEntries(req_.fields.map(f => [f.name,
                // çoklu seçim: aynı adla gelen tüm onay kutuları JSON dizi olarak geçer
                f.multiple ? JSON.stringify(params.getAll(f.name)) : params.get(f.name) ?? ""])))
            : this.submit(id, params.get("value") ?? params.get("secret") ?? "");
          const secrets = req_.fields ? req_.fields.some(f => f.secret) : value.secret;
          const summary = req_.fields
            ? Object.entries(value.values ?? {}).map(([k, v]) => {
              const f = req_.fields!.find(x => x.name === k)!;
              return `<li>${esc(f.title)}: ${f.secret ? "<em>(gizli)</em>" : `<code>${esc(renderEnv(v).slice(0, 200))}</code>`}</li>`;
            }).join("")
            : "";
          page(200, shell(`<p>Kaydedildi. Sohbete dön${secrets ? "" : `; değer <code>$HT_USER_INPUT</code> olarak kullanılabilir`}.</p>${summary ? `<ul class="m">${summary}</ul>` : ""}${secrets ? `<p class="m">Gizli değerler bu sayfada tekrar gösterilmez; modelin göreceği çıktıda maskelenir.</p>` : ""}`));
        } catch (e) {
          return page(400, shell(`<p class="e">${esc((e as Error).message)}</p><p class="m"><a href="${esc(path)}">Geri dön</a></p>`));
        }
      });
      req.on("error", () => { if (!res.headersSent) page(400, shell(`<p class="e">Okunamadı.</p>`)); });
      return true;
    }
    if (req.method !== "GET") return page(405, shell(`<p class="e">Yalnız GET/POST.</p>`)), true;

    const field = (f: InputField): string => {
      const label = `<label for="f_${esc(f.name)}">${esc(f.title)}${f.required ? "" : ' <span class="m">(isteğe bağlı)</span>'}</label>`;
      const help = f.help ? `<div class="h">${esc(f.help)}</div>` : "";
      const common = `id="f_${esc(f.name)}" name="${esc(f.name)}" autocomplete="off" ${f.required ? "required" : ""}`;
      let control: string;
      if (f.secret) control = `<input type="password" ${common} ${f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ""}>`;
      else if (f.choices && f.multiple) control = `<div class="cb">${f.choices.map(c => `<label><input type="checkbox" name="${esc(f.name)}" value="${esc(c)}"${c === f.default ? " checked" : ""}> ${esc(c)}</label>`).join("")}</div>`;
      else if (f.choices) control = `<select ${common}>${f.choices.map(c => `<option${c === f.default ? " selected" : ""}>${esc(c)}</option>`).join("")}</select>`;
      else if (f.kind === "boolean") control = `<select ${common}><option value="true"${f.default === "true" ? " selected" : ""}>true</option><option value="false"${f.default === "false" || f.default === undefined ? " selected" : ""}>false</option></select>`;
      else if (f.kind === "array") control = `<textarea ${common} rows="4" placeholder='["a","b"]'>${esc(f.default ?? "")}</textarea>`;
      else if (f.kind === "number") control = `<input type="number" step="any" ${common} value="${esc(f.default ?? "")}" ${f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ""}>`;
      else control = `<input type="text" ${common} value="${esc(f.default ?? "")}" ${f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ""}>`;
      return `<div${f.secret ? ' class="sec"' : ""}>${label}${control}${help}${f.secret ? '<div class="h">Gizli: sohbete geri dönmez, denetim kaydına yazılmaz, komut çıktısında maskelenir.</div>' : ""}</div>`;
    };

    const mins = Math.max(1, Math.round((req_.expiresAt - Date.now()) / 60000));
    const body = req_.fields
      ? `<p class="q">${esc(req_.title)}</p>${req_.help ? `<p class="m">${esc(req_.help)}</p>` : ""}
<form method="post" action="${esc(path)}" autocomplete="off"><fieldset>${req_.fields.map(field).join("")}</fieldset>
<button type="submit">Gönder</button><button type="submit" name="action" value="cancel" formnovalidate>Vazgeç</button></form>
<p class="m">Yanıtlar <code>$HT_USER_INPUT</code> (JSON) ve her alan için <code>$HT_USER_INPUT_ADI</code> olarak komutlara geçer. Bu bağlantı tek kullanımlıktır, ~${mins} dk geçerlidir.</p>`
      : `<p class="q">${esc(req_.title)}</p>
<form method="post" action="${esc(path)}" autocomplete="off">${field({ name: req_.secret ? "secret" : "value", title: "Yanıt", kind: req_.kind, secret: req_.secret, required: true, ...((req_ as any).choices ? { choices: (req_ as any).choices } : {}), ...((req_ as any).default !== undefined ? { default: (req_ as any).default } : {}), ...((req_ as any).placeholder ? { placeholder: (req_ as any).placeholder } : {}) } as InputField)}
<button type="submit">Gönder</button><button type="submit" name="action" value="cancel" formnovalidate>Vazgeç</button></form>
<p class="m">${req_.secret ? "Bu değer gizli kabul edilir: sohbete geri dönmez, denetim kaydına yazılmaz, komut çıktısında maskelenir." : `Tür: ${esc(req_.kind)}. Değer <code>$HT_USER_INPUT</code> olarak komutlara geçer.`} ~${mins} dk geçerlidir.</p>`;
    page(200, shell(body));
    return true;
  }
}
