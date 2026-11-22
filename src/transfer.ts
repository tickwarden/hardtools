// Copy a file that lives outside the workspace (an upload directory, Claude's own home)
// into the sandbox. Only an explicit list of source directories is readable, only regular
// files are copied, and the destination still goes through the normal root confinement.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";
import { isInside, PolicyError, resolveSafe } from "./guard.js";

/** Upload/home directories that exist in the *client's* container, not on a remote host. */
export const DEFAULT_SOURCES = ["/home/claude", "/mnt/user-data/uploads", "/mnt/user-data", "/data/uploads"];
const MAX_TRANSFER = 64 << 20;

export function transferSources(): string[] {
  const raw = (process.env.HARDTOOLS_TRANSFER_SOURCES ?? "").trim();
  const list = raw ? raw.split(/[,:]/).map(s => s.trim()).filter(Boolean) : DEFAULT_SOURCES;
  const seen = new Set<string>();
  for (const p of list) { try { seen.add(fs.realpathSync(p)); } catch { seen.add(path.resolve(p)); } }
  return [...seen];
}

export interface TransferArgs {
  action?: "copy" | "sources";
  source_path?: string; dest_path?: string; overwrite?: boolean; max_bytes?: number;
}

function realpathOrNull(p: string): string | null {
  try { return fs.realpathSync(p); } catch { return null; }
}

export function htTransferFile(policy: Policy, a: TransferArgs): string {
  const sources = transferSources();
  if ((a.action ?? "copy") === "sources") {
    return JSON.stringify({
      sources: sources.map(dir => ({ dir, exists: fs.existsSync(dir) })),
      hint: "Set HARDTOOLS_TRANSFER_SOURCES (comma-separated) to add more. On a remote host only paths that exist on that host can be read.",
    }, null, 2);
  }
  if (!a.source_path || !a.dest_path) throw new PolicyError("bad_input", "source_path and dest_path are required");
  if (!path.isAbsolute(a.source_path)) throw new PolicyError("bad_input", "source_path must be absolute and inside a configured source directory");

  const source = realpathOrNull(a.source_path);
  if (!source) throw new PolicyError("not_found", `source does not exist on this host: ${a.source_path}`);
  const owner = sources.find(dir => isInside(dir, source));
  if (!owner) throw new PolicyError("source_denied", `source is outside the transfer sources (${sources.join(", ")})`);

  let st: fs.Stats;
  try { st = fs.statSync(source); } catch { throw new PolicyError("not_found", "source is not readable"); }
  if (!st.isFile()) throw new PolicyError("not_a_file", "only regular files can be transferred");
  const limit = Math.min(MAX_TRANSFER, Math.max(1, a.max_bytes ?? MAX_TRANSFER));
  if (st.size > limit) throw new PolicyError("too_large", `source is ${st.size} bytes; limit is ${limit}`);

  const dest = resolveSafe(policy, a.dest_path, "write");
  if (dest.exists && !a.overwrite) throw new PolicyError("exists", `destination exists: ${a.dest_path} (pass overwrite=true to replace it)`);

  const data = fs.readFileSync(source, { flag: "r" });
  if (data.length > limit) throw new PolicyError("too_large", `source grew past the limit while reading (${data.length} bytes)`);
  const sha256 = crypto.createHash("sha256").update(data).digest("hex");

  fs.mkdirSync(path.dirname(dest.abs), { recursive: true });
  const tmp = `${dest.abs}.ht-transfer-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  fs.writeFileSync(tmp, data, { mode: 0o644, flag: "wx" });
  fs.renameSync(tmp, dest.abs);

  return JSON.stringify({
    action: "copy", from: source, into: dest.abs, source_dir: owner,
    bytes: data.length, sha256, created: !dest.exists,
    external: !isInside(policy.roots[0], source),
  }, null, 2);
}
