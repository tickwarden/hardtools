// Operator opt-in for a single isolated HTTP shell call. No TCP listener on the host;
// the only guest-facing resource is a private Unix socket carrying HTTP CONNECT.
import dns from "node:dns/promises";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import type { Policy } from "./config.js";
import { isInside, PolicyError } from "./guard.js";
import { checkUrl, isBlockedIp } from "./net.js";

const deny = () => new PolicyError("workspace_https_denied", "destination is not an allowed public HTTPS endpoint");
const global6 = new net.BlockList(); global6.addSubnet("2000::", 3, "ipv6");
const special = new net.BlockList();
// Additional special-purpose prefixes and the Azure host-platform virtual IP on hosted runners.
special.addAddress("168.63.129.16");
for (const a of ["192.31.196.0", "192.52.193.0", "192.88.99.0", "192.175.48.0"]) special.addSubnet(a, 24, "ipv4");
special.addSubnet("2001::", 23, "ipv6"); special.addSubnet("3fff::", 20, "ipv6"); special.addSubnet("2620:4f:8000::", 48, "ipv6");

export function requireWorkspaceHttps(p: Policy): void {
  if (p.shellWorker !== "workspace" || !p.shell.enabled || !p.workspaceHttps || !p.net.enabled || !p.net.schemes.includes("https") ||
      (p.net.ports.length > 0 && !p.net.ports.includes(443)) || (p.net.requireAllowDomains && !p.net.allowDomains.length))
    throw new PolicyError("workspace_https_unavailable", "an enabled workspace shell and a policy permitting public HTTPS:443 are required");
}

// getaddrinfo itself cannot be canceled; cap outstanding resolutions across commands,
// including clients which disconnected while their DNS request was in flight.
let resolving = 0;
async function lookupHost(host: string) {
  if (resolving >= 16) throw deny();
  resolving++;
  try { return await dns.lookup(host + ".", { all: true, verbatim: true }); }
  finally { resolving--; }
}

/** Resolve once, check *every* answer, then dial just the chosen numeric address. Never inherit ht_fetch loopback exceptions. */
export async function workspacePeer(p: Policy, authority: string) {
  requireWorkspaceHttps(p);
  if (authority.length > 260 || !/^(?:[a-z0-9.-]+|\[[a-f0-9:.]+\]):443$/i.test(authority)) throw deny();
  const url = new URL(`https://${authority}/`);
  const { host: raw } = checkUrl(p, url);
  const host = raw.toLowerCase().replace(/\.$/, "");
  const family = net.isIP(host);
  if (!family && (!host.includes(".") || host.split(".").some(s => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s)) ||
      /(?:^|\.)(?:localhost|local|localdomain|internal|home\.arpa)$/.test(host))) throw deny();
  // An exact DNS name (trailing dot) avoids the runner's search domains.
  const records = family ? [{ address: host, family }] : await lookupHost(host);
  const self = new net.BlockList();
  for (const a of Object.values(os.networkInterfaces()).flat()) if (a) {
    const f = a.family === "IPv6" ? "ipv6" : "ipv4", ip = a.address.split("%")[0];
    self.addAddress(ip, f);
    // A directly attached LAN can use global addresses too.
    if (a.cidr) self.addSubnet(ip, Number(a.cidr.split("/")[1]), f);
  }
  if (!records.length || !records.every(r => {
    const f = r.family === 6 ? "ipv6" : "ipv4";
    return net.isIP(r.address) === r.family && !r.address.includes("%") && (r.family === 4 || global6.check(r.address, "ipv6")) &&
      !isBlockedIp(r.address) && !special.check(r.address, f) && !self.check(r.address, f);
  })) throw deny();
  return records.find(r => r.family === 4) ?? records[0];
}

export interface EgressLease { readonly socketPath: string; close(): void }
export async function openWorkspaceEgress(p: Policy): Promise<EgressLease> {
  requireWorkspaceHttps(p);
  // Do not create management files anywhere reachable from a writable project mount.
  if (p.roots.some(r => isInside(r, "/tmp"))) throw new PolicyError("worker_root", "the project cannot contain the egress socket directory");
  const dir = fs.mkdtempSync("/tmp/ht-egress-"), socketPath = dir + "/proxy.sock";
  const peers = new Set<net.Socket>();
  // 0.5.3: büyük indirmeler yarıda kesilmesin. Bütçe ve boşta kalma süresi ortamdan
  // ayarlanabilir; varsayılan 4 GiB / 120 sn (eskiden 64 MB / 15 sn idi ve yavaş bir
  // aynadan gelen indirme "Proxy CONNECT aborted" ile düşüyordu).
  const budgetMb = Number(process.env.HARDTOOLS_WORKSPACE_EGRESS_MB ?? 4096);
  const idleMs = Number(process.env.HARDTOOLS_WORKSPACE_EGRESS_IDLE_S ?? 120) * 1000;
  let stopped = false, accepted = 0;
  let remaining = (Number.isFinite(budgetMb) && budgetMb > 0 ? budgetMb : 4096) * 1024 * 1024;
  const server = http.createServer({ maxHeaderSize: 4096, headersTimeout: 5000, requestTimeout: 10000 }, (_req, res) => {
    res.writeHead(405, { connection: "close", "content-length": 0 }).end();
  });
  const track = (s: net.Socket) => {
    peers.add(s); s.once("close", () => peers.delete(s)); s.on("error", () => s.destroy());
    s.setTimeout(Number.isFinite(idleMs) && idleMs > 0 ? idleMs : 120_000, () => s.destroy()); // veri aktığı sürece sıfırlanır
  };
  server.maxConnections = 8;
  server.on("connection", s => { track(s); if (stopped || ++accepted > 256 || remaining <= 0) s.destroy(); });
  server.on("clientError", (_e, s) => s.destroy());
  server.on("upgrade", (_req, s) => s.destroy());
  const charge = (b: Buffer) => {
    remaining -= b.length;
    if (remaining < 0) for (const s of peers) s.destroy();
    return remaining >= 0;
  };
  server.on("connect", async (req, _stream, head) => {
    const client = req.socket;
    try {
      const { address, family } = await workspacePeer(p, req.url ?? "");
      if (stopped || client.destroyed || remaining <= 0) return client.destroy();
      const upstream = net.createConnection({ host: address, family, port: 443 });
      track(upstream);
      client.once("close", () => upstream.destroy()); upstream.once("close", () => client.destroy());
      upstream.once("error", () => client.destroy());
      upstream.once("connect", () => {
        if (stopped || client.destroyed || !charge(head)) return upstream.destroy();
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head.length) upstream.write(head);
        client.on("data", charge); upstream.on("data", charge);
        client.pipe(upstream); upstream.pipe(client);
      });
    } catch { if (!client.destroyed) client.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); }
  });
  const close = () => {
    if (stopped) return;
    stopped = true; for (const s of peers) s.destroy(); server.close();
    fs.rmSync(socketPath, { force: true }); fs.rmdirSync(dir);
  };
  try {
    await new Promise<void>((ok, fail) => { server.once("error", fail); server.listen(socketPath, ok); });
    fs.chmodSync(socketPath, 0o600);
    return { socketPath, close };
  } catch (e) { close(); throw e; }
}
