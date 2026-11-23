// 0.5.1 — keepalive: sağlıklı sunucuda 0, ölü sunucuda 1, parametresiz 2.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";

const script = path.resolve("scripts/keepalive.sh");
const hasSh = fs.existsSync("/bin/sh");

const run = (args, env = {}) => new Promise((resolve) => {
  const child = spawn("sh", [script, ...args], { env: { ...process.env, KEEPALIVE_GAP: "0", KEEPALIVE_TRIES: "1", ...env } });
  let out = ""; child.stdout.on("data", (d) => { out += d; }); child.stderr.on("data", (d) => { out += d; });
  child.on("close", (code) => resolve({ code, out }));
});

test("keepalive: healthy /healthz exits 0, dead endpoint exits 1, no argument exits 2", { skip: !hasSh }, async (t) => {
  const srv = http.createServer((req, res) => {
    if (req.url === "/healthz") { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ ok: true, version: "test" })); return; }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", () => r()));
  t.after(() => srv.close());
  const port = srv.address().port;

  const healthy = await run([`http://127.0.0.1:${port}`]);
  assert.equal(healthy.code, 0, healthy.out);
  assert.match(healthy.out, /sağlıklı/);

  const dead = await run([`http://127.0.0.1:${port + 1}`]);
  assert.equal(dead.code, 1, dead.out);

  const usage = await run([]);
  assert.equal(usage.code, 2, usage.out);
});
