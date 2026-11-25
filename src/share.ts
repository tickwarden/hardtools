import crypto from "node:crypto";
import type http from "node:http";
import path from "node:path";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { Policy } from "./config.js";
import { readBytesNoFollow } from "./fs-tools.js";
import { enforceSecrets, PolicyError, resolveSafe } from "./guard.js";

export const SHARE_CWD = "/_tmp/hardtools-share/";
const sharePrefix = `hardtools-share://local${SHARE_CWD}`;
export const shareTemplate = sharePrefix + "{id}";
const MAX_FILE = 2 << 20, MAX_TOTAL = 16 << 20, MAX_ITEMS = 32;
const idPattern = /^[A-Za-z0-9_-]{43}$/;
export function shareIdFromUri(uri: string): string | null {
  if (uri.length !== sharePrefix.length + 43 || !uri.startsWith(sharePrefix)) return null;
  const id = uri.slice(sharePrefix.length);
  return idPattern.test(id) ? id : null;
}
const mime: Record<string, string> = { ".txt": "text/plain", ".csv": "text/csv", ".md": "text/markdown", ".pdf": "application/pdf", ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".zip": "application/zip" };
type Shared = { owner: string; id: string; name: string; bytes: Buffer; mimeType: string; expires: number; sha256: string };
export interface ShareArgs { action?: "create" | "list" | "revoke"; path?: string; source_path?: string; name?: string; ttl_minutes?: number; id?: string }
const summary = (s: Shared) => ({ id: s.id, uri: sharePrefix + s.id, name: s.name, cwd: SHARE_CWD, mime_type: s.mimeType, size: s.bytes.length, sha256: s.sha256, expires_at: new Date(s.expires).toISOString() });
const resource = (s: Shared) => ({ uri: sharePrefix + s.id, mimeType: s.mimeType, blob: s.bytes.toString("base64") });

function sourceFile(p: Policy, a: ShareArgs) {
  if ((a.path === undefined) === (a.source_path === undefined)) throw new PolicyError("bad_input", "supply path (in the share cwd) OR source_path (in a workspace root)");
  let abs: string;
  if (a.source_path !== undefined) abs = path.resolve(p.roots[0], a.source_path);
  else {
    const rel = a.path!.startsWith(SHARE_CWD) ? a.path!.slice(SHARE_CWD.length) : a.path!;
    if (!rel || /[\\:\0]/.test(rel) || rel.split("/").some(c => !c || c === "." || c === "..")) throw new PolicyError("bad_share_path", `path must be a file inside ${SHARE_CWD}`);
    // A mounted logical cwd, not a reason to mkdir /_tmp with elevated permissions.
    abs = path.join(p.roots[0], SHARE_CWD.slice(1), rel);
  }
  const r = resolveSafe(p, abs, "read");
  if (!r.exists) throw new PolicyError("not_found", `no such source file; stage path under ${SHARE_CWD} or use source_path`);
  if (r.abs !== abs || path.relative(r.root, r.abs).split(path.sep).some(c => [".git", ".ht-trash"].includes(c.toLowerCase())))
    throw new PolicyError("share_protected", "links, trash and version-control metadata cannot be shared");
  return r.abs;
}

/** One explicit export snapshots one file; a URL never maps a request path to disk. */
export class Shares {
  private items = new Map<string, Shared>();
  constructor(private now = Date.now, private persist?: import("./persist.js").Persist) {
    const saved = persist?.read<Array<Omit<Shared, "bytes"> & { b64: string }>>([]) ?? [];
    for (const r of saved) {
      if (!r || typeof r.id !== "string" || r.expires <= this.now()) continue;
      try { this.items.set(r.id, { ...r, bytes: Buffer.from(r.b64, "base64") } as Shared); } catch { /* atla */ }
    }
  }
  private save() {
    if (!this.persist) return;
    this.persist.write([...this.items.values()].map(({ bytes, ...rest }) => ({ ...rest, b64: bytes.toString("base64") })));
  }
  private prune() {
    const before = this.items.size;
    for (const [k, s] of this.items) if (s.expires <= this.now()) this.items.delete(k);
    if (this.items.size !== before) this.save();
  }
  private forOwner(owner: string, id?: string) {
    this.prune(); const s = id && idPattern.test(id) ? this.items.get(id) : undefined;
    if (!s || s.owner !== owner) throw new PolicyError("share_missing", "share not found or expired");
    return s;
  }
  readResource(owner: string, id: string) { return resource(this.forOwner(owner, id)); }
  tool(p: Policy, owner: string, a: ShareArgs, origin?: string): CallToolResult {
    this.prune();
    const createInputs = a.path !== undefined || a.source_path !== undefined || a.name !== undefined || a.ttl_minutes !== undefined;
    if ((a.action === "list" && (createInputs || a.id !== undefined)) || (a.action === "revoke" && createInputs) || ((a.action ?? "create") === "create" && a.id !== undefined))
      throw new PolicyError("bad_input", "do not mix creation, listing and revocation arguments");
    if (a.action === "list") {
      const files = [...this.items.values()].filter(s => s.owner === owner).map(s => ({ ...summary(s), ...(origin && { url: origin + SHARE_CWD + s.id }) }));
      return { content: [{ type: "text", text: JSON.stringify({ cwd: SHARE_CWD, files }) }] };
    }
    if (a.action === "revoke") {
      const s = this.forOwner(owner, a.id); this.items.delete(s.id); this.save();
      return { content: [{ type: "text", text: "REVOKED: future downloads and resource reads are disabled" }] };
    }
    if (!p.fs.writeEnabled) throw new PolicyError("write_disabled", "creating a share requires write permission");
    const abs = sourceFile(p, a), name = (a.name ?? path.basename(abs)).normalize("NFC");
    if (!name || name.startsWith(".") || /[\\/<>:"|?*\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/u.test(name) || Buffer.byteLength(name) > 180)
      throw new PolicyError("bad_name", "supply a safe display filename (at most 180 bytes)");
    const ttl = a.ttl_minutes ?? 10;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 60) throw new PolicyError("bad_ttl", "ttl_minutes must be 1–60");
    if (this.items.size >= MAX_ITEMS) throw new PolicyError("share_limit", "share count limit reached; revoke a share or wait for expiry");
    const bytes = readBytesNoFollow(abs, Math.min(p.fs.maxReadBytes, MAX_FILE), true);
    if ([...this.items.values()].reduce((n, s) => n + s.bytes.length, bytes.length) > MAX_TOTAL) throw new PolicyError("share_limit", "share memory quota reached");
    const warnings = enforceSecrets(p, bytes.toString("latin1"), "shared file");
    const id = crypto.randomBytes(32).toString("base64url");
    const s = { owner, id, bytes, name, mimeType: mime[path.extname(name).toLowerCase()] ?? "application/octet-stream", expires: this.now() + ttl * 60_000, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
    this.items.set(id, s); this.save();
    const url = origin && origin + SHARE_CWD + id;
    const text = JSON.stringify({ ...summary(s), ...(url && { url }), ...(warnings.length && { warnings }) });
    return { content: url ? [{ type: "text", text: `[Dosyayı indir](${url})\n${text}` }] : [{ type: "text", text }, { type: "resource", resource: resource(s) }] };
  }
  /** Host / Origin / global request limits are enforced by the HTTP entrypoint first. */
  download(req: http.IncomingMessage, res: http.ServerResponse, pathname: string): boolean {
    if (!pathname.startsWith(SHARE_CWD)) return false;
    this.prune(); const id = pathname.slice(SHARE_CWD.length), s = idPattern.test(id) ? this.items.get(id) : undefined;
    const headers = { "cache-control": "private, no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'; sandbox" };
    if (!s) { res.writeHead(404, headers); res.end(); return true; }
    if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405, { ...headers, allow: "GET, HEAD" }); res.end(); return true; }
    const encoded = encodeURIComponent(s.name).replace(/['()*]/g, c => "%" + c.charCodeAt(0).toString(16).toUpperCase());
    res.writeHead(200, { ...headers, "content-type": "application/octet-stream", "content-length": s.bytes.length, "content-disposition": `attachment; filename*=UTF-8''${encoded}` });
    res.end(req.method === "HEAD" ? undefined : s.bytes); return true;
  }
}
