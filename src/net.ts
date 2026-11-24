// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import zlib from "node:zlib";
import type { Readable } from "node:stream";
import { PolicyError } from "./guard.js";
import { globMatch, hasWildcard } from "./match.js";
import type { Policy } from "./config.js";
import { VERSION } from "./version.js";

const blocked = new net.BlockList();
for (const [a, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as [string, number][]) blocked.addSubnet(a, bits, "ipv4");
for (const [a, bits] of [
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32],
  ["64:ff9b::", 96], ["2002::", 16], ["100::", 64],
] as [string, number][]) blocked.addSubnet(a, bits, "ipv6");

export function isBlockedIp(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, "");
  if (net.isIPv4(bare)) return blocked.check(bare, "ipv4");
  if (net.isIPv6(bare)) return blocked.check(bare, "ipv6");
  return true;
}
function isLoopback(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, "");
  return net.isIPv4(bare) ? bare.startsWith("127.") : bare === "::1";
}

function hostAllowed(policy: Policy, host: string): void {
  const h = host.toLowerCase().replace(/\.$/, "");
  // Eşleştirme: "*" hepsi; joker içeren desen glob olarak (alan adı büyük/küçük harf duyarsız);
  // jokersiz desen eskisi gibi kök alan adı + alt alan adları.
  const match = (d: string) => {
    const raw = d.toLowerCase().trim();
    if (!raw) return false;
    if (raw === "*") return true;
    if (hasWildcard(raw) && globMatch(raw, h)) return true;
    const x = raw.replace(/^\*?\./, "");
    return h === x || h.endsWith("." + x);
  };
  if (policy.net.denyDomains.some(match)) throw new PolicyError("domain_denied", `domain is denied by policy: ${h}`);
  if (policy.net.allowDomains.length === 0) {
    if (policy.net.requireAllowDomains) throw new PolicyError("allowlist_required", "this profile requires net.allowDomains to be configured before ht_fetch can be used");
    return;
  }
  if (!policy.net.allowDomains.some(match)) throw new PolicyError("domain_not_allowed", `domain is not in net.allowDomains: ${h}`);
}

function addrAllowed(policy: Policy, hostname: string, addr: string, port: number): boolean {
  if (!isBlockedIp(addr)) return true;
  const hn = hostname.toLowerCase();
  const isLocalName = hn === "localhost" || hn.endsWith(".localhost") || net.isIP(hn.replace(/^\[|\]$/g, "")) !== 0;
  return isLoopback(addr) && isLocalName && policy.net.loopbackPorts.includes(port);
}

export function checkUrl(policy: Policy, u: URL): { host: string; port: number } {
  if (!policy.net.enabled) throw new PolicyError("net_disabled", "network access is disabled by policy");
  const scheme = u.protocol.replace(":", "") as "http" | "https";
  if (!policy.net.schemes.includes(scheme)) throw new PolicyError("scheme_denied", `scheme not allowed: ${u.protocol}`);
  if (u.username || u.password) throw new PolicyError("credentials_in_url", "URLs with embedded credentials are refused");
  const port = u.port ? Number(u.port) : scheme === "https" ? 443 : 80;
  if (policy.net.ports.length && !policy.net.ports.includes(port) && !policy.net.loopbackPorts.includes(port))
    throw new PolicyError("port_denied", `port not allowed: ${port}`);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (!host) throw new PolicyError("bad_url", "missing host");
  hostAllowed(policy, host);
  if (net.isIP(host) && !addrAllowed(policy, host, host, port))
    throw new PolicyError("private_address", `address is private/reserved and not whitelisted: ${host}`);
  return { host, port };
}

function validatedLookup(policy: Policy, port: number) {
  return (hostname: string, options: any, cb: any) => {
    dns.lookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
      if (err) return cb(err);
      if (!addrs.length) return cb(new Error("no address"));
      // ALL records must be acceptable (defends against mixed public/private answers); the vetted record is the one we connect to (defends against DNS rebinding).
      for (const a of addrs) {
        if (!addrAllowed(policy, hostname, a.address, port))
          return cb(new PolicyError("private_address", `host resolves to a private/reserved address (${a.address}) and is not whitelisted`));
      }
      if (options && options.all) cb(null, addrs); else cb(null, addrs[0].address, addrs[0].family);
    });
  };
}

interface RawResponse { status: number; headers: http.IncomingHttpHeaders; body: Buffer; url: URL; truncated: boolean }

function requestOnce(policy: Policy, url: URL, deadline: number, accept: string): Promise<RawResponse> {
  const { port } = checkUrl(policy, url);
  if (Date.now() >= deadline) throw new PolicyError("request_timeout", "network time budget exhausted");
  return new Promise((resolve, reject) => {
    const mod = url.protocol === "https:" ? https : http;
    const remaining = Math.max(1, deadline - Date.now());
    const req = mod.request({
      protocol: url.protocol, hostname: url.hostname.replace(/^\[|\]$/g, ""), port, path: url.pathname + url.search, method: "GET",
      agent: false, lookup: validatedLookup(policy, port) as any,
      headers: {
        "User-Agent": `hardtools/${VERSION} (https://github.com/tickwarden/hardtools; MCP)`, "Accept": accept,
        "Accept-Encoding": "gzip, deflate, br", "Connection": "close",
      },
    }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode ?? 0) && res.headers.location) {
        resolve({ status: res.statusCode!, headers: res.headers, url, truncated: false, body: Buffer.alloc(0) });
        res.destroy(); return; // do not download intermediate redirect bodies
      }
      const max = policy.net.maxBytes;
      let stream: Readable = res;
      const enc = String(res.headers["content-encoding"] ?? "identity").toLowerCase();
      if (enc === "gzip" || enc === "x-gzip") stream = res.pipe(zlib.createGunzip());
      else if (enc === "deflate") stream = res.pipe(zlib.createInflate());
      else if (enc === "br") stream = res.pipe(zlib.createBrotliDecompress());
      else if (enc !== "identity") { res.destroy(); return reject(new PolicyError("unsupported_encoding", `unsupported content-encoding: ${enc}`)); }
      const chunks: Buffer[] = []; let size = 0; let truncated = false;
      stream.on("data", (c: Buffer) => {
        if (truncated) return;
        size += c.length;
        if (size > max) { // decoded-size cap also defeats decompression bombs
          chunks.push(c.subarray(0, c.length - (size - max))); truncated = true; req.destroy(); stream.destroy(); finish();
        } else chunks.push(c);
      });
      let done = false;
      const finish = () => { if (done) return; done = true; resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks), url, truncated }); };
      stream.on("end", finish);
      stream.on("error", (e) => { if (!done) { done = true; reject(e); } });
      res.on("error", (e) => { if (!done) { done = true; reject(e); } });
    });
    const clock = setTimeout(() => req.destroy(new Error("request timed out")), remaining);
    req.once("close", () => clearTimeout(clock));
    req.on("error", reject);
    req.end();
  });
}

export interface FetchResult {
  finalUrl: string; status: number; contentType: string; title?: string; text: string;
  bytes: number; truncatedDownload: boolean; redirects: string[]; warnings: string[]; fromCache: boolean;
}

let caches = new WeakMap<Policy, Map<string, { at: number; res: FetchResult }>>();

const INJECTION_HINTS: [string, RegExp][] = [
  ["instruction-override phrase", /ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|prompts|messages)/i],
  ["system-prompt impersonation", /<\s*\/?\s*(?:system|assistant|instructions?)\s*>|\[\s*system\s*\]/i],
  ["role reassignment", /\byou are now (?:a|an|the)\b/i],
  ["concealment request", /do not (?:tell|inform|mention (?:this )?to) the user/i],
  ["exfiltration request", /(?:send|post|upload|exfiltrate|email)\b.{0,60}\b(?:api[_ -]?key|token|password|secret|credentials|\.env|ssh key)/i],
];

const ENT: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
function decodeEntities(t: string): string {
  return t.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === "#") { const cp = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(cp); } catch { return " "; } }
    return ENT[e.toLowerCase()] ?? m;
  });
}

function htmlToText(html: string): { title?: string; text: string } {
  const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1];
  let t = html.replace(/<!--[\s\S]*?-->/g, " ").replace(/<(script|style|noscript|template|svg|iframe)\b[\s\S]*?<\/\1>/gi, " ");
  t = t.replace(/<\s*(br|\/p|\/div|\/li|\/tr|\/h[1-6]|\/section|\/article|\/pre|\/table)\b[^>]*>/gi, "\n").replace(/<[^>]+>/g, " ");
  t = decodeEntities(t);
  t = t.replace(/[ \t\f\v\r]+/g, " ").replace(/ ?\n ?/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  return { title: title ? decodeEntities(title).replace(/\s+/g, " ").trim() : undefined, text: t };
}

const TEXTUAL = /^(text\/|application\/(json|xml|javascript|x-javascript|ecmascript|yaml|x-yaml|xhtml\+xml|toml)|.+\+(json|xml))/i;

/** The same connect-time DNS/IP, redirect, absolute deadline and decoded-byte checks serve text and image callers. */
export async function fetchBytes(policy: Policy, initialUrl: URL, options: { validateHop?: (u: URL) => void; accept?: string; deadline?: number } = {}) {
  const deadline = Math.min(options.deadline ?? Infinity, Date.now() + policy.net.timeoutMs);
  let url = initialUrl;
  const redirects: string[] = [];
  let resp: RawResponse | undefined;
  for (let hop = 0; hop <= policy.net.maxRedirects; hop++) {
    options.validateHop?.(url);
    const r = await requestOnce(policy, url, deadline, options.accept ?? "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.5");
    if ([301, 302, 303, 307, 308].includes(r.status) && r.headers.location) {
      let next: URL;
      try { next = new URL(String(r.headers.location), url); } catch { throw new PolicyError("bad_redirect", "invalid redirect target"); }
      redirects.push(next.toString());
      url = next; // re-validated (scheme, port, domain allowlist, DNS/IP) at the top of requestOnce
      continue;
    }
    resp = r; break;
  }
  if (!resp) throw new PolicyError("too_many_redirects", `exceeded ${policy.net.maxRedirects} redirects`);

  return { response: resp, redirects };
}

export async function safeFetch(policy: Policy, rawUrl: string): Promise<FetchResult> {
  let url: URL;
  try { url = new URL(rawUrl); } catch { throw new PolicyError("bad_url", "invalid URL"); }
  let cache = caches.get(policy);
  if (!cache) caches.set(policy, cache = new Map());
  const key = url.toString();
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < policy.net.cacheTtlSec * 1000) {
    checkUrl(policy, url); for (const hop of hit.res.redirects) checkUrl(policy, new URL(hop));
    return { ...hit.res, fromCache: true };
  }

  const { response: resp, redirects } = await fetchBytes(policy, url);
  url = resp.url;
  const ctype = String(resp.headers["content-type"] ?? "application/octet-stream");
  const mime = ctype.split(";")[0].trim().toLowerCase();
  if (!TEXTUAL.test(mime)) throw new PolicyError("unsupported_content_type", `refusing non-text content-type: ${mime} (${resp.body.length} bytes)`);
  const charset = /charset=([^;\s]+)/i.exec(ctype)?.[1]?.replace(/["']/g, "") ?? "utf-8";
  let decoded: string;
  try { decoded = new TextDecoder(charset).decode(resp.body); } catch { decoded = new TextDecoder("utf-8").decode(resp.body); }

  let title: string | undefined; let text = decoded;
  if (/html/.test(mime)) ({ title, text } = htmlToText(decoded));
  const warnings: string[] = [];
  for (const [name, rx] of INJECTION_HINTS) if (rx.test(text)) warnings.push(`possible prompt-injection content (${name}) — heuristic, not proof`);
  if (resp.truncated) warnings.push(`download truncated at ${policy.net.maxBytes} bytes`);
  if (resp.status >= 400) warnings.push(`HTTP ${resp.status}`);

  const result: FetchResult = { finalUrl: url.toString(), status: resp.status, contentType: mime, title, text, bytes: resp.body.length, truncatedDownload: resp.truncated, redirects, warnings, fromCache: false };
  if (policy.net.cacheTtlSec > 0 && resp.status < 400) {
    cache.set(key, { at: Date.now(), res: result });
    if (cache.size > 64) cache.delete(cache.keys().next().value as string);
  }
  return result;
}

export function clearFetchCache(): void { caches = new WeakMap(); }
