// Capability-URL user input: the model asks a question, the user answers it in a browser
// form, and the answer appears to shell commands as $HT_USER_INPUT. Secret answers are
// never echoed back to the model or written to the audit log, and are masked in shell
// output.
import crypto from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { PolicyError } from "./guard.js";

export type InputKind = "string" | "boolean" | "number" | "array" | "null";

export interface InputRequest {
  id: string;
  title: string;
  kind: InputKind;
  secret: boolean;
  createdAt: number;
  expiresAt: number;
  submittedAt?: number;
  value?: unknown;
}

const MAX_TEXT = 8192;
const MAX_ARRAY_ITEMS = 100;
const MAX_ARRAY_BYTES = 32768;
const MAX_REQUESTS = 32;
const MAX_SECRETS = 16;
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

export class UserInputs {
  private byId = new Map<string, InputRequest>();
  private active = new Map<string, string>(); // owner -> request id
  private secrets: string[] = [];

  create(owner: string, o: { title: string; kind: InputKind; secret: boolean; ttlMs: number }): InputRequest {
    if (!KINDS.includes(o.kind)) throw new PolicyError("bad_input", `kind must be one of ${KINDS.join(", ")}`);
    const title = (o.title ?? "").trim();
    if (!title || title.length > 200) throw new PolicyError("bad_input", "title must be 1–200 characters");
    this.prune();
    if (this.byId.size >= MAX_REQUESTS) throw new PolicyError("too_many_requests", "too many open input requests; clear one first");
    const id = crypto.randomBytes(24).toString("base64url");
    const now = Date.now();
    const req: InputRequest = { id, title, kind: o.kind, secret: o.secret, createdAt: now, expiresAt: now + Math.max(60_000, Math.min(3_600_000, o.ttlMs)) };
    this.byId.set(id, req);
    this.active.set(owner, id);
    return req;
  }

  get(owner: string, id?: string): InputRequest {
    const key = id ?? this.active.get(owner);
    const req = key ? this.byId.get(key) : undefined;
    if (!req || req.expiresAt < Date.now()) throw new PolicyError("not_found", "no open input request (expired or already answered and cleared)");
    return req;
  }

  /** Submit a browser answer. The request id is the capability; a second answer is refused. */
  submit(id: string, raw: string): InputRequest {
    const req = this.byId.get(id);
    if (!req) throw new PolicyError("not_found", "this input request does not exist or was already cleared");
    if (req.expiresAt < Date.now()) { this.byId.delete(id); throw new PolicyError("expired", "this input request expired; ask again from the chat"); }
    if (req.submittedAt !== undefined) throw new PolicyError("already_answered", "this input was already submitted once");
    const value = parseValue(req.kind, raw);
    req.value = value;
    req.submittedAt = Date.now();
    if (req.secret) this.rememberSecret(renderEnv(value));
    return req;
  }

  /** Current unexpired answer of this owner, if any. */
  value(owner: string): { request: InputRequest; env: string } | undefined {
    const key = this.active.get(owner);
    const req = key ? this.byId.get(key) : undefined;
    if (!req || req.submittedAt === undefined || req.expiresAt < Date.now()) return undefined;
    return { request: req, env: renderEnv(req.value) };
  }

  /** Environment for shell children; absent until the user answers. */
  envFor(owner: string): Record<string, string> {
    const v = this.value(owner);
    return v ? { HT_USER_INPUT: v.env } : {};
  }

  clear(owner: string, id?: string): boolean {
    const key = id ?? this.active.get(owner);
    if (!key) return false;
    const req = this.byId.get(key);
    if (req?.secret && req.value !== undefined) this.forgetSecret(renderEnv(req.value));
    this.byId.delete(key);
    if (this.active.get(owner) === key) this.active.delete(owner);
    return true;
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
<style>body{font:16px system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5}input[type=text],input[type=password],textarea{width:100%;padding:.6rem;box-sizing:border-box;font:14px ui-monospace,monospace}button{padding:.6rem 1.2rem;margin-top:.8rem}.m{color:#555;font-size:14px}.e{color:#b00020}label{display:block;margin:1rem 0 .3rem}</style>
<h1>hardtools</h1>${body}`;

    if (!req_ || req_.expiresAt < Date.now()) return page(410, shell(`<p class="e">Bu istek bulunamadı ya da süresi doldu. Sohbetten yeniden iste.</p>`)), true;
    if (req_.submittedAt !== undefined) return page(409, shell(`<p class="e">Bu istek zaten yanıtlandı. Yeni bir istek için sohbetten tekrar iste.</p>`)), true;

    if (req.method === "POST") {
      let size = 0; const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => { size += c.length; if (size <= 65536) chunks.push(c); });
      req.on("end", () => {
        if (size > 65536) return page(413, shell(`<p class="e">Yanıt çok büyük.</p>`));
        const params = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        let value: InputRequest;
        try { value = this.submit(id, params.get("value") ?? params.get("secret") ?? ""); }
        catch (e) { return page(400, shell(`<p class="e">${esc((e as Error).message)}</p><p class="m"><a href="${esc(path)}">Geri dön</a></p>`)); }
        if (!value.secret) return page(200, shell(`<p>Kaydedildi. Sohbete dön; değer <code>$HT_USER_INPUT</code> olarak kullanılabilir.</p>`));
        page(200, shell(`<p>Gizli değer kaydedildi. Sohbete dön.</p><p class="m">Değer bu sayfada tekrar gösterilmez, modelin göreceği çıktıda maskelenir.</p>`));
      });
      req.on("error", () => { if (!res.headersSent) page(400, shell(`<p class="e">Okunamadı.</p>`)); });
      return true;
    }
    if (req.method !== "GET") return page(405, shell(`<p class="e">Yalnız GET/POST.</p>`)), true;

    const field = req_.secret
      ? `<input type="password" name="secret" autocomplete="off" autofocus required>`
      : req_.kind === "boolean"
        ? `<select name="value" autofocus><option value="true">true</option><option value="false">false</option></select>`
        : req_.kind === "array"
          ? `<textarea name="value" rows="4" autofocus placeholder='["a","b"]'></textarea>`
          : req_.kind === "null"
            ? `<input type="text" name="value" value="" placeholder="(boş bırak)" autofocus>`
            : `<input type="text" name="value" autofocus ${req_.kind === "number" ? 'inputmode="decimal"' : ""}>`;
    page(200, shell(`<p><strong>${esc(req_.title)}</strong></p>
<form method="post" action="${esc(path)}" autocomplete="off">${field}<button type="submit">Gönder</button></form>
<p class="m">${req_.secret ? "Bu değer gizli kabul edilir: sohbete geri dönmez, denetim kaydına yazılmaz, komut çıktısında maskelenir." : `Tür: ${esc(req_.kind)}. Değer <code>$HT_USER_INPUT</code> olarak komutlara geçer.`}</p>`));
    return true;
  }
}
