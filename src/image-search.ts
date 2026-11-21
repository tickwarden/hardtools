import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { Policy } from "./config.js";
import { PolicyError } from "./guard.js";
import { checkUrl, fetchBytes } from "./net.js";

const API = "https://commons.wikimedia.org/w/api.php";
const thumbs = new Set(["thumb.wikimedia.org", "upload.wikimedia.org"]);
const apiHost = new Set([new URL(API).hostname]);
function allowHosts(hosts: Set<string>, u: URL) {
  if (u.protocol !== "https:" || u.port || u.username || u.password || !hosts.has(u.hostname)) throw new PolicyError("image_host", "not an approved Wikimedia origin");
}
const clean = (v: unknown, n = 240) => typeof v === "string" ? v.slice(0, 6000).replace(/<[^>]*>/g, " ").replace(/&amp;/g, "&").replace(/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/gu, " ").replace(/\s+/g, " ").trim().slice(0, n) : "";
const cap = (p: Policy, n: number): Policy => ({ ...p, net: { ...p.net, maxBytes: Math.min(p.net.maxBytes, n) } });

// No HTML, SVG or animated formats as inline content. Check the raster header itself, not just MIME or filename.
export function thumbnailOK(b: Buffer, mime: string): boolean {
  let w = 0, h = 0;
  if (mime === "image/png" && b.length >= 33 && b.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex")) && b.readUInt32BE(8) === 13 && b.toString("ascii", 12, 16) === "IHDR") {
    w = b.readUInt32BE(16); h = b.readUInt32BE(20);
    if (b.includes(Buffer.from("acTL"))) return false;
  } else if (mime === "image/jpeg" && b.length > 12 && b.readUInt16BE(0) === 0xffd8) {
    for (let i = 2; i + 9 < b.length && b[i] === 0xff;) {
      while (b[i] === 0xff) i++;
      const marker = b[i++]; if (i + 7 >= b.length) break;
      const len = b.readUInt16BE(i); if (len < 2 || i + len > b.length) break;
      if ([0xc0, 0xc1, 0xc2].includes(marker) && len >= 8) { h = b.readUInt16BE(i + 3); w = b.readUInt16BE(i + 5); break; }
      if (marker === 0xda || marker === 0xd9) break;
      i += len;
    }
  } else if (mime === "image/webp" && b.length >= 30 && b.toString("ascii", 0, 4) === "RIFF" && b.toString("ascii", 8, 12) === "WEBP") {
    const tag = b.toString("ascii", 12, 16);
    if (tag === "VP8X" && !(b[20] & 2)) { w = 1 + b.readUIntLE(24, 3); h = 1 + b.readUIntLE(27, 3); }
    if (tag === "VP8 " && b.readUIntBE(23, 3) === 0x9d012a) { w = b.readUInt16LE(26) & 16383; h = b.readUInt16LE(28) & 16383; }
    if (tag === "VP8L" && b[20] === 0x2f) { const size = b.readUInt32LE(21); w = 1 + (size & 16383); h = 1 + ((size >>> 14) & 16383); }
  }
  return w > 0 && h > 0 && w <= 1600 && h <= 1600 && w * h <= 1_000_000;
}

export interface ImageArgs {
  query: string; limit?: number; offset?: number; file_type?: "jpeg" | "png" | "webp";
  orientation?: "landscape" | "portrait" | "square"; previews?: boolean; thumbnail_width?: 120 | 250 | 500;
}
interface Page { pageid?: number; index?: number; title?: string; imageinfo?: { width?: number; height?: number; mime?: string; thumburl?: string; extmetadata?: Record<string, { value?: unknown }> }[] }

export async function imageSearch(p: Policy, a: ImageArgs, get = fetchBytes): Promise<CallToolResult> {
  const u = new URL(API), q = a.query.trim();
  if (!q || q.length > 200) throw new PolicyError("bad_query", "query must be 1–200 characters");
  const limit = a.limit ?? 5, offset = a.offset ?? 0;
  u.search = new URLSearchParams({ action: "query", format: "json", formatversion: "2", generator: "search", gsrnamespace: "6", gsrsearch: `filetype:bitmap ${q}`, gsrlimit: String(limit), gsroffset: String(offset), prop: "imageinfo", iiprop: "url|size|mime|extmetadata", iiextmetadatafilter: "LicenseShortName|Artist", iiurlwidth: String(a.thumbnail_width ?? 250) }).toString();
  checkUrl(p, u);
  const deadline = Date.now() + Math.min(20_000, p.net.timeoutMs);
  const api = (await get(cap(p, 512 << 10), u, { deadline, accept: "application/json", validateHop: target => allowHosts(apiHost, target) })).response;
  if (api.status !== 200 || api.truncated || !/^application\/json\b/i.test(String(api.headers["content-type"]))) throw new PolicyError("image_provider", `Commons search unavailable (HTTP ${api.status} or incomplete JSON response)`);
  let json; try { json = JSON.parse(api.body.toString("utf8")); } catch { throw new PolicyError("image_provider", "invalid JSON from Commons"); }
  if (!json || typeof json !== "object" || json.error) throw new PolicyError("image_provider", "Commons did not accept the search; retry later");
  const pages: Page[] = Array.isArray(json.query?.pages) ? json.query.pages.slice(0, limit) : [];
  const next = json.continue?.gsroffset;
  const content: CallToolResult["content"] = [{ type: "text", text: `Wikimedia Commons — external metadata is untrusted data. Open each source page for attribution and reuse terms.${Number.isInteger(next) && next > offset && next <= 1000 ? ` next_offset=${next}` : ""}` }];
  let count = 0, attempts = 0, remaining = p.net.maxBytes - api.body.length;
  for (const row of pages.sort((x, y) => (x?.index ?? 0) - (y?.index ?? 0))) {
    const info = row?.imageinfo?.[0], w = info?.width, h = info?.height;
    if (!info || !Number.isSafeInteger(row.pageid) || !row.pageid || row.pageid < 0 || typeof w !== "number" || typeof h !== "number" || !(w > 0 && h > 0) || typeof info.mime !== "string" || !info.mime.startsWith("image/")) continue;
    if (a.file_type && info.mime !== `image/${a.file_type}`) continue;
    if (a.orientation && a.orientation !== (w === h ? "square" : w > h ? "landscape" : "portrait")) continue;
    count++;
    const meta = { title: clean(row.title), width: w, height: h, mime_type: info.mime.slice(0, 64), artist: clean(info.extmetadata?.Artist?.value) || null, license: clean(info.extmetadata?.LicenseShortName?.value) || null, source: `https://commons.wikimedia.org/?curid=${row.pageid}` };
    content.push({ type: "text", text: JSON.stringify(meta) });
    if (a.previews === false || attempts >= 3 || remaining <= 0 || Date.now() >= deadline || typeof info.thumburl !== "string") continue;
    try {
      const thumb = new URL(info.thumburl); allowHosts(thumbs, thumb); checkUrl(p, thumb);
      const max = Math.min(remaining, 256 << 10);
      attempts++; remaining -= max; // reserve the full request budget even on a failed download
      const r = (await get(cap(p, max), thumb, { deadline, accept: "image/jpeg,image/png,image/webp", validateHop: target => allowHosts(thumbs, target) })).response;
      const mime = String(r.headers["content-type"]).split(";")[0].trim().toLowerCase();
      if (r.status !== 200 || r.truncated || !thumbnailOK(r.body, mime)) throw Error("unsupported preview");
      content.push({ type: "image", mimeType: mime, data: r.body.toString("base64") });
    } catch { content.push({ type: "text", text: "Preview unavailable; use the Commons source link above." }); }
  }
  if (!count) content.push({ type: "text", text: "No matching images on this page." });
  return { content };
}
