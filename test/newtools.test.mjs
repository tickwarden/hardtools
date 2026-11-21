// AI-generated (Claude, Anthropic), 2026-11-12. Requires human security review before production use.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const text = (r) => r.content.map(c => c.text).join("\n");

async function session(cfgExtra = {}) {
  const root = tmp("ht-nt-"), audit = tmp("ht-nt-audit-"), outside = tmp("ht-nt-out-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: path.join(audit, "log") }, ...cfgExtra }));
  const env = { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg }; delete env.HARDTOOLS_PROFILE;
  const client = new Client({ name: "t", version: "0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry, "--profile", "balanced"], env, stderr: "ignore" }));
  const call = async (name, args) => { const r = await client.callTool({ name, arguments: args }); return { err: !!r.isError, t: text(r) }; };
  return { root, outside, client, call };
}
const R = (s, p) => path.join(s.root, p);

test("ht_glob: matches, sorting, hidden/protected/symlink handling, confinement", async () => {
  const s = await session();
  try {
    fs.mkdirSync(R(s, "src/a/b"), { recursive: true }); fs.mkdirSync(R(s, "node_modules/x"), { recursive: true }); fs.mkdirSync(R(s, ".git"));
    fs.writeFileSync(R(s, "src/A.java"), "x"); fs.writeFileSync(R(s, "src/a/b/C.java"), "x"); fs.writeFileSync(R(s, "src/a/note.txt"), "x");
    fs.writeFileSync(R(s, "node_modules/x/skip.java"), "x"); fs.writeFileSync(R(s, ".git/h.java"), "x"); fs.writeFileSync(R(s, ".hidden.java"), "x");
    fs.writeFileSync(R(s, ".env"), "SECRET=1"); fs.writeFileSync(path.join(s.outside, "o.java"), "x");
    fs.symlinkSync(s.outside, R(s, "linkdir")); fs.symlinkSync(path.join(s.outside, "o.java"), R(s, "link.java"));
    let r = await s.call("ht_glob", { pattern: "**/*.java" });
    assert.ok(!r.err, r.t); assert.match(r.t, /src\/A\.java/); assert.match(r.t, /src\/a\/b\/C\.java/);
    assert.doesNotMatch(r.t, /skip\.java|h\.java|\.hidden\.java|o\.java|link\.java/);
    assert.match(r.t, /2 symlinks skipped/);
    r = await s.call("ht_glob", { pattern: "*.java", include_hidden: true }); assert.match(r.t, /\.hidden\.java/); assert.doesNotMatch(r.t, /h\.java\b.*\n.*\.git/);
    assert.doesNotMatch((await s.call("ht_glob", { pattern: "h.java", include_hidden: true })).t, /\.git/); // .git is always skipped
    r = await s.call("ht_glob", { pattern: ".env", include_hidden: true }); assert.doesNotMatch(r.t, /\.env\t/); assert.match(r.t, /protected hidden/);
    r = await s.call("ht_glob", { pattern: "*", type: "dir" }); assert.match(r.t, /src\//); assert.doesNotMatch(r.t, /node_modules|linkdir/);
    r = await s.call("ht_glob", { pattern: "**/*.java", max_results: 1 }); assert.match(r.t, /showing 1/);
    for (const bad of ["../*", "/etc/*", "a/../../b"]) assert.ok((await s.call("ht_glob", { pattern: bad })).err, bad);
    r = await s.call("ht_glob", { pattern: "*", path: s.outside }); assert.ok(r.err); assert.match(r.t, /outside_roots/);
    r = await s.call("ht_glob", { pattern: "*", path: "linkdir" }); assert.ok(r.err); assert.doesNotMatch(r.t, /o\.java/);
  } finally { await s.client.close(); }
});

test("ht_mkdir: creates nested dirs, idempotent, refuses files/.git/outside", async () => {
  const s = await session();
  try {
    let r = await s.call("ht_mkdir", { path: "a/b/c" }); assert.ok(!r.err, r.t); assert.ok(fs.statSync(R(s, "a/b/c")).isDirectory());
    r = await s.call("ht_mkdir", { path: "a/b/c" }); assert.ok(!r.err && /already exists/.test(r.t));
    fs.writeFileSync(R(s, "f"), "x"); r = await s.call("ht_mkdir", { path: "f" }); assert.ok(r.err);
    fs.mkdirSync(R(s, ".git")); r = await s.call("ht_mkdir", { path: ".git/evil" }); assert.ok(r.err); assert.ok(!fs.existsSync(R(s, ".git/evil")));
    r = await s.call("ht_mkdir", { path: path.join(s.outside, "x") }); assert.ok(r.err); assert.ok(!fs.existsSync(path.join(s.outside, "x")));
    r = await s.call("ht_mkdir", { path: "../esc" }); assert.ok(r.err);
    fs.symlinkSync(s.outside, R(s, "lnk")); r = await s.call("ht_mkdir", { path: "lnk/new" }); assert.ok(r.err); assert.ok(!fs.existsSync(path.join(s.outside, "new")));
  } finally { await s.client.close(); }
});

test("ht_move: rename/move, never overwrites, mkdirp, dir moves, and all refusals", async () => {
  const s = await session();
  try {
    fs.writeFileSync(R(s, "a.txt"), "AAA"); fs.writeFileSync(R(s, "b.txt"), "BBB"); fs.mkdirSync(R(s, "d/sub"), { recursive: true }); fs.writeFileSync(R(s, "d/sub/f.txt"), "F");
    let r = await s.call("ht_move", { from: "a.txt", to: "a2.txt" }); assert.ok(!r.err, r.t); assert.ok(!fs.existsSync(R(s, "a.txt"))); assert.equal(fs.readFileSync(R(s, "a2.txt"), "utf8"), "AAA");
    r = await s.call("ht_move", { from: "a2.txt", to: "b.txt" }); assert.ok(r.err); assert.match(r.t, /exists/); assert.equal(fs.readFileSync(R(s, "b.txt"), "utf8"), "BBB"); assert.ok(fs.existsSync(R(s, "a2.txt")));
    r = await s.call("ht_move", { from: "a2.txt", to: "new/dir/a.txt" }); assert.ok(r.err); assert.match(r.t, /no_parent/);
    r = await s.call("ht_move", { from: "a2.txt", to: "new/dir/a.txt", mkdirp: true }); assert.ok(!r.err, r.t); assert.equal(fs.readFileSync(R(s, "new/dir/a.txt"), "utf8"), "AAA");
    r = await s.call("ht_move", { from: "d", to: "d2" }); assert.ok(!r.err, r.t); assert.ok(fs.existsSync(R(s, "d2/sub/f.txt")));
    r = await s.call("ht_move", { from: "d2", to: "d2/sub/inner" }); assert.ok(r.err); assert.match(r.t, /into_self/);
    r = await s.call("ht_move", { from: "b.txt", to: "d2" }); assert.ok(r.err); assert.match(r.t, /exists/); // no "move into dir" semantics
    r = await s.call("ht_move", { from: "nope", to: "x" }); assert.ok(r.err); assert.match(r.t, /not_found/);
    r = await s.call("ht_move", { from: ".", to: "x" }); assert.ok(r.err);
    fs.mkdirSync(R(s, ".git")); fs.writeFileSync(R(s, ".git/config"), "x");
    r = await s.call("ht_move", { from: ".git", to: "gitcopy" }); assert.ok(r.err); assert.ok(fs.existsSync(R(s, ".git/config")));
    r = await s.call("ht_move", { from: "b.txt", to: ".git/b.txt" }); assert.ok(r.err); assert.ok(fs.existsSync(R(s, "b.txt")));
    fs.writeFileSync(path.join(s.outside, "o.txt"), "OUT");
    r = await s.call("ht_move", { from: path.join(s.outside, "o.txt"), to: "stolen.txt" }); assert.ok(r.err); assert.ok(fs.existsSync(path.join(s.outside, "o.txt")));
    r = await s.call("ht_move", { from: "b.txt", to: path.join(s.outside, "b.txt") }); assert.ok(r.err); assert.ok(!fs.existsSync(path.join(s.outside, "b.txt")));
    fs.symlinkSync(path.join(s.outside, "o.txt"), R(s, "sl")); r = await s.call("ht_move", { from: "sl", to: "sl2" }); assert.ok(r.err); assert.match(r.t, /symlink|outside_roots/); assert.ok(fs.existsSync(path.join(s.outside, "o.txt")));
    fs.symlinkSync(R(s, "b.txt"), R(s, "inroot-link")); r = await s.call("ht_move", { from: "inroot-link", to: "moved-link" }); assert.ok(r.err); assert.match(r.t, /symlink_source/); assert.ok(fs.existsSync(R(s, "b.txt")));
    fs.writeFileSync(R(s, ".env"), "S=1"); r = await s.call("ht_move", { from: ".env", to: "env.txt" }); assert.ok(r.err); assert.ok(fs.existsSync(R(s, ".env")));
  } finally { await s.client.close(); }
});

test("ht_trash: reversible delete with manifest; refuses roots/.git/outside and re-trashing", async () => {
  const s = await session();
  try {
    fs.writeFileSync(R(s, "x.txt"), "KEEP-ME"); fs.mkdirSync(R(s, "dir/in"), { recursive: true }); fs.writeFileSync(R(s, "dir/in/y.txt"), "Y");
    let r = await s.call("ht_trash", { path: "x.txt" }); assert.ok(!r.err, r.t); assert.ok(!fs.existsSync(R(s, "x.txt")));
    const tdir = R(s, ".ht-trash"); const items = fs.readdirSync(tdir).filter(n => n !== "index.jsonl"); assert.equal(items.length, 1);
    assert.equal(fs.readFileSync(path.join(tdir, items[0]), "utf8"), "KEEP-ME");
    assert.equal(JSON.parse(fs.readFileSync(path.join(tdir, "index.jsonl"), "utf8").trim()).original, "x.txt");
    assert.equal(fs.statSync(tdir).mode & 0o777, 0o700);
    r = await s.call("ht_move", { from: `.ht-trash/${items[0]}`, to: "x.txt" }); assert.ok(!r.err, r.t); assert.equal(fs.readFileSync(R(s, "x.txt"), "utf8"), "KEEP-ME"); // restore
    r = await s.call("ht_trash", { path: "dir" }); assert.ok(r.err); assert.match(r.t, /needs_recursive/); assert.ok(fs.existsSync(R(s, "dir/in/y.txt")));
    r = await s.call("ht_trash", { path: "dir", recursive: true }); assert.ok(!r.err, r.t); assert.ok(!fs.existsSync(R(s, "dir")));
    const after = fs.readdirSync(tdir).filter(n => n !== "index.jsonl"); assert.equal(after.length, 1);
    const dirItem = after.find(n => n.endsWith("-dir")); r = await s.call("ht_trash", { path: `.ht-trash/${dirItem}`, recursive: true }); assert.ok(r.err); assert.match(r.t, /already_in_trash/); assert.ok(fs.existsSync(path.join(tdir, dirItem, "in/y.txt")));
    r = await s.call("ht_trash", { path: ".ht-trash", recursive: true }); assert.ok(r.err); assert.ok(fs.existsSync(tdir));
    r = await s.call("ht_trash", { path: ".", recursive: true }); assert.ok(r.err); assert.ok(fs.existsSync(R(s, "x.txt")));
    fs.mkdirSync(R(s, ".git")); fs.writeFileSync(R(s, ".git/HEAD"), "ref"); r = await s.call("ht_trash", { path: ".git", recursive: true }); assert.ok(r.err); assert.ok(fs.existsSync(R(s, ".git/HEAD")));
    r = await s.call("ht_trash", { path: ".git/HEAD" }); assert.ok(r.err); assert.ok(fs.existsSync(R(s, ".git/HEAD")));
    fs.writeFileSync(path.join(s.outside, "o.txt"), "OUT"); r = await s.call("ht_trash", { path: path.join(s.outside, "o.txt") }); assert.ok(r.err); assert.ok(fs.existsSync(path.join(s.outside, "o.txt")));
    fs.symlinkSync(path.join(s.outside, "o.txt"), R(s, "lnk")); r = await s.call("ht_trash", { path: "lnk" }); assert.ok(r.err); assert.ok(fs.existsSync(path.join(s.outside, "o.txt")));
    r = await s.call("ht_trash", { path: "missing" }); assert.ok(r.err); assert.match(r.t, /not_found/);
    // a pre-planted .ht-trash symlink must not redirect the trash outside the root
    const s2 = await session(); try {
      fs.symlinkSync(s2.outside, R(s2, ".ht-trash")); fs.writeFileSync(R(s2, "v.txt"), "V");
      const rr = await s2.call("ht_trash", { path: "v.txt" }); assert.ok(rr.err); assert.ok(fs.existsSync(R(s2, "v.txt"))); assert.equal(fs.readdirSync(s2.outside).length, 0);
    } finally { await s2.client.close(); }
  } finally { await s.client.close(); }
});

test("write-disabled policy disables ht_mkdir/ht_move/ht_trash but not ht_glob", async () => {
  const s = await session({ fs: { writeEnabled: false } });
  try {
    fs.writeFileSync(R(s, "a.txt"), "A");
    for (const [n, a] of [["ht_mkdir", { path: "d" }], ["ht_move", { from: "a.txt", to: "b.txt" }], ["ht_trash", { path: "a.txt" }]]) { const r = await s.call(n, a); assert.ok(r.err, n); assert.match(r.t, /write_disabled/, n); }
    assert.ok(fs.existsSync(R(s, "a.txt"))); assert.ok(!(await s.call("ht_glob", { pattern: "*.txt" })).err);
  } finally { await s.client.close(); }
});
