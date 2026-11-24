// ht_user_input: yetenek URL'si, tip doğrulama, tek kullanımlık yanıt, sır maskeleme.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { parseValue, renderEnv, UserInputs } from "../dist/user-input.js";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef";

test("user input: types are parsed strictly and unknown shapes are refused", () => {
  assert.equal(parseValue("string", "merhaba"), "merhaba");
  assert.equal(parseValue("boolean", "true"), true);
  assert.equal(parseValue("boolean", "false"), false);
  assert.equal(parseValue("number", "42.5"), 42.5);
  assert.deepEqual(parseValue("array", '["a",1,true,null]'), ["a", 1, true, null]);
  assert.equal(parseValue("null", ""), null);
  assert.throws(() => parseValue("boolean", "evet"), /true or false/);
  assert.throws(() => parseValue("number", "12abc"), /expected a number/);
  assert.throws(() => parseValue("array", '{"a":1}'), /JSON array/);
  assert.throws(() => parseValue("array", "[1,2,3,4,5,6,7,8,9,10,11].repeat(20)"), /array/);
  assert.throws(() => parseValue("string", "x".repeat(9000)), /longer than/);
  assert.equal(renderEnv("düz metin"), "düz metin");
  assert.equal(renderEnv(["a", 1]), '["a",1]');
  assert.equal(renderEnv(null), "null");
});

test("user input: one answer per request, secrets masked and never enumerated", () => {
  const inputs = new UserInputs();
  const req = inputs.create("static", { title: "API anahtarın?", kind: "string", secret: true, ttlMs: 60_000 });
  assert.equal(inputs.envFor("static").HT_USER_INPUT, undefined);
  inputs.submit(req.id, "sk-canary-1234567890");
  assert.equal(inputs.envFor("static").HT_USER_INPUT, "sk-canary-1234567890");
  assert.throws(() => inputs.submit(req.id, "ikinci"), /already submitted/);
  assert.match(inputs.mask("çıktı: sk-canary-1234567890 son"), /\[redacted:HT_USER_INPUT\]/);
  assert.doesNotMatch(inputs.mask("çıktı: sk-canary-1234567890 son"), /sk-canary/);
  // Maskeleme sır değerleriyle sınırlı: sır olmayan yanıt çıktıda görünür.
  const plain = inputs.create("other", { title: "Ad?", kind: "string", secret: false, ttlMs: 60_000 });
  inputs.submit(plain.id, "tickwarden");
  assert.equal(inputs.mask("selam tickwarden"), "selam tickwarden");
  assert.equal(inputs.clear("static"), true);
  assert.deepEqual(inputs.envFor("static"), {});
  assert.throws(() => inputs.get("static"), /no open input request/);
});

function mcp(port, token, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: "/mcp", method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` } }, (res) => {
      let data = ""; res.on("data", (c) => { data += c; });
      res.on("end", () => {
        const line = data.split("\n").find(l => l.startsWith("data: "));
        resolve(line ? JSON.parse(line.slice(6)) : { raw: data, status: res.statusCode });
      });
    });
    req.on("error", reject); req.write(JSON.stringify(body)); req.end();
  });
}
const callTool = async (port, token, name, args) => {
  const r = await mcp(port, token, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });
  const text = r?.result?.content?.[0]?.text ?? JSON.stringify(r);
  return { isError: Boolean(r?.result?.isError), text, raw: r };
};

function request(port, { method = "GET", target, headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = ""; res.on("data", (c) => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

async function startServer(t) {
  const root = tmp("ht-ui-root-");
  const audit = tmp("ht-ui-audit-");
  const cfg = path.join(audit, "config.json");
  // Kabuk kapalı: bu test UI + araç akışını doğrular; ht_shell env enjeksiyonu Fly'da,
  // bwrap gerektirdiği için burada ayrıca sınanmıyor.
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: true }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}` },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 80; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise(r => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, `sunucu başlamadı: ${err}`);
  return { port, root, auditDir: audit };
}

test("user input: a browser form round-trips into the model, once", async (t) => {
  const { port, auditDir } = await startServer(t);
  const created = await callTool(port, TOKEN, "ht_user_input", { title: "Proje adı ne olsun?", kind: "string" });
  assert.match(created.text, /"request_id"/, created.text);
  const info = JSON.parse(created.text);
  assert.match(info.url, new RegExp(`^http://127.0.0.1:${port}/ui/input/[A-Za-z0-9_-]{20,}$`));

  const form = await request(port, { target: new URL(info.url).pathname });
  assert.equal(form.status, 200, form.body);
  assert.match(form.body, /Proje adı ne olsun\?/);
  assert.match(String(form.headers["content-security-policy"]), /default-src 'none'/);

  const pending = JSON.parse((await callTool(port, TOKEN, "ht_user_input", { action: "get" })).text);
  assert.equal(pending.status, "pending");

  const submit = await request(port, { method: "POST", target: new URL(info.url).pathname,
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "value=" + encodeURIComponent("hardtools-2") });
  assert.equal(submit.status, 200, submit.body);

  const ready = JSON.parse((await callTool(port, TOKEN, "ht_user_input", { action: "get" })).text);
  assert.equal(ready.status, "ready");
  assert.equal(ready.value, "hardtools-2");

  const again = await request(port, { method: "POST", target: new URL(info.url).pathname,
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "value=ikinci" });
  assert.equal(again.status, 409, "aynı istek iki kez yanıtlanamamalı");

  const status = JSON.parse((await callTool(port, TOKEN, "ht_status", {})).text);
  assert.equal(status.userInput.env, "HT_USER_INPUT");
  assert.equal(status.userInput.active, true);

  const cleared = JSON.parse((await callTool(port, TOKEN, "ht_user_input", { action: "clear" })).text);
  assert.equal(cleared.cleared, true);
  const afterClear = JSON.parse((await callTool(port, TOKEN, "ht_status", {})).text);
  assert.equal(afterClear.userInput.active, false);

  // Denetim kaydında yanıtın kendisi yok.
  const auditText = fs.readdirSync(auditDir).filter(f => f.endsWith(".jsonl")).map(f => fs.readFileSync(path.join(auditDir, f), "utf8")).join("");
  assert.doesNotMatch(auditText, /hardtools-2/);
  assert.match(auditText, /"ev":"input_request"/);
});

test("user input: secret answers never come back to the model", async (t) => {
  const { port, root, auditDir } = await startServer(t);
  const info = JSON.parse((await callTool(port, TOKEN, "ht_user_input", { title: "OpenAI API anahtarı", kind: "string", secret: true })).text);
  assert.equal(info.secret, true);

  const form = await request(port, { target: new URL(info.url).pathname });
  assert.match(form.body, /type="password"/, "gizli alan password olmalı");
  const secret = "sk-canary-" + crypto.randomBytes(8).toString("hex");
  const submit = await request(port, { method: "POST", target: new URL(info.url).pathname,
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "secret=" + encodeURIComponent(secret) });
  assert.equal(submit.status, 200);
  assert.doesNotMatch(submit.body, new RegExp(secret), "yanıt sayfası sırrı tekrar basmamalı");

  const ready = JSON.parse((await callTool(port, TOKEN, "ht_user_input", { action: "get" })).text);
  assert.equal(ready.status, "ready");
  assert.equal(ready.secret, true);
  assert.equal(ready.value, null, "sır modelin gördüğü yanıtta olmamalı");
  assert.equal(ready.env, "HT_USER_INPUT");

  // Sır bir dosyaya düştüyse kabuk çıktısında maskelenir.
  fs.writeFileSync(path.join(root, "notlar.txt"), `anahtar=${secret}\n`);
  const read = await callTool(port, TOKEN, "ht_shell", { argv: ["cat", "notlar.txt"] });
  assert.match(read.text, /redacted:HT_USER_INPUT/);
  assert.doesNotMatch(read.text, new RegExp(secret));

  const auditText = fs.readdirSync(auditDir).filter(f => f.endsWith(".jsonl")).map(f => fs.readFileSync(path.join(auditDir, f), "utf8")).join("");
  assert.doesNotMatch(auditText, new RegExp(secret), "sır denetim kaydına yazılmamalı");
});

test("user input: unknown, expired and mistyped requests fail closed", async (t) => {
  const { port } = await startServer(t);
  const unknown = await request(port, { target: "/ui/input/" + "A".repeat(32) });
  assert.equal(unknown.status, 410);

  const info = JSON.parse((await callTool(port, TOKEN, "ht_user_input", { title: "Sayı gir", kind: "number" })).text);
  const bad = await request(port, { method: "POST", target: new URL(info.url).pathname,
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "value=on-iki" });
  assert.equal(bad.status, 400);
  assert.match(bad.body, /expected a number/);

  const inputs = new UserInputs();
  assert.throws(() => inputs.submit("olmayan-bilet", "x"), /does not exist or was already cleared/);
  const ok = inputs.create("static", { title: "süreli", kind: "string", secret: false, ttlMs: 60_000 });
  ok.expiresAt = Date.now() - 1; // süresi dolmuş gibi davran
  assert.throws(() => inputs.submit(ok.id, "geç"), /expired/);
});
