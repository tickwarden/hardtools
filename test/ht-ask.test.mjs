// 0.5.4 — ht_ask: tek çağrıda soru + seçenek, çoklu seçim, serbest metin, uzun yoklama.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { UserInputs } from "../dist/user-input.js";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef";

const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));

function request(port, { method = "GET", target, headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method, headers }, (res) => {
      let data = ""; res.on("data", (c) => { data += c; }); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

function rpc(port, payload) {
  return request(port, {
    method: "POST", target: "/mcp",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify(payload),
  });
}

const parse = (res) => {
  const line = res.body.split("\n").find((l) => l.startsWith("data: "));
  return line ? JSON.parse(line.slice(6)) : JSON.parse(res.body);
};

async function start(t) {
  const root = tmp("ht-ask-root-");
  const audit = tmp("ht-ask-audit-");
  const cfg = path.join(audit, "config.json");
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: audit, failClosed: false }, fs: { writeEnabled: true }, shell: { enabled: false } }));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [entry, "--http", "--port", String(port), "--profile", "balanced"], {
    env: { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg, HARDTOOLS_HTTP_TOKEN: TOKEN, HARDTOOLS_ALLOWED_HOSTS: `127.0.0.1:${port}` },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = ""; child.stderr.on("data", (d) => { err += d; });
  for (let i = 0; i < 80; i++) { if (/listening/.test(err) || child.exitCode !== null) break; await new Promise((r) => setTimeout(r, 100)); }
  t.after(() => child.kill("SIGKILL"));
  assert.match(err, /listening/, `sunucu başlamadı: ${err}`);
  return { port };
}

const callTool = async (port, args, id = 1) =>
  JSON.parse(parse(await rpc(port, { jsonrpc: "2.0", id, method: "tools/call", params: { name: "ht_ask", arguments: args } })).result.content[0].text);

test("ht_ask: çoklu seçim alanı onay kutusu üretir ve dizi olarak saklanır", () => {
  const inputs = new UserInputs();
  const req = inputs.create("static", {
    title: "Hangi ortamlar?", kind: "string", secret: false, ttlMs: 60_000,
    fields: [{ name: "env", title: "Ortamlar", kind: "array", secret: false, required: true, choices: ["dev", "stage", "prod"], multiple: true }],
  });
  assert.equal(req.fields[0].multiple, true);
  inputs.submit(req.id, { env: JSON.stringify(["dev", "prod"]) });
  assert.deepEqual(JSON.parse(inputs.envFor("static").HT_USER_INPUT).env, ["dev", "prod"]);

  const again = inputs.create("s2", {
    title: "Tekrar", kind: "string", secret: false, ttlMs: 60_000,
    fields: [{ name: "env", title: "Ortamlar", kind: "array", secret: false, required: true, choices: ["dev", "prod"], multiple: true }],
  });
  assert.throws(() => inputs.submit(again.id, { env: JSON.stringify(["yok"]) }), /seçeneklerden biri değil/);

  // multiple olmadan choices verilirse tek seçim (select) olarak kalır
  const single = inputs.create("s3", { title: "Tek", kind: "string", secret: false, ttlMs: 60_000, choices: ["a", "b"] });
  assert.equal(single.multiple, undefined);
});

test("ht_ask: soru sorulur, cevap aynı çağrıda döner (multi + serbest metin)", async (t) => {
  const { port } = await start(t);

  // 1) kısa bekleme: cevap yok -> pending + url
  const pending = await callTool(port, { question: "Hangi ortamlar?", options: ["dev", "stage", "prod"], multi: true, wait_seconds: 1 });
  assert.equal(pending.status, "pending", JSON.stringify(pending));
  assert.match(pending.url, /\/ui\/input\//);

  // 2) kullanıcı formu dolduruyor
  const id = pending.url.split("/ui/input/")[1];
  const submitted = await request(port, {
    method: "POST", target: `/ui/input/${id}`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "answer=dev&answer=prod&custom=" + encodeURIComponent("ayrıca test"),
  });
  assert.equal(submitted.status, 200, submitted.body);

  // 3) cevap okunur
  const answer = await callTool(port, { request_id: pending.request_id, wait_seconds: 4 }, 2);
  assert.equal(answer.status, "answered", JSON.stringify(answer));
  assert.deepEqual(answer.selected, ["dev", "prod"]);
  assert.equal(answer.custom, "ayrıca test");

  // 4) aynı soru tekrar sorulursa açık form yeniden kullanılmaz (cevaplanmış), yeni form açılır
  const fresh = await callTool(port, { question: "Hangi ortamlar?", options: ["dev", "stage", "prod"], multi: true, wait_seconds: 0 }, 3);
  assert.equal(fresh.status, "pending");
  assert.notEqual(fresh.request_id, pending.request_id);

  // 5) iptal
  const cancelled = await callTool(port, { action: "cancel", request_id: fresh.request_id }, 4);
  assert.equal(cancelled.status, "cancelled");
});

test("ht_ask: tek seçim + serbest metin, en az iki seçenek kuralı", async (t) => {
  const { port } = await start(t);
  const bad = await rpc(port, { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "ht_ask", arguments: { question: "Tek seçenek?", options: ["x"] } } });
  assert.match(bad.body, /Too small|at least 2 choices/);

  const p = await callTool(port, { question: "Hangisi?", options: [{ label: "Fly", description: "ucuz" }, "Yerel"], allow_custom: true, wait_seconds: 1 }, 1);
  const id = p.url.split("/ui/input/")[1];
  await request(port, {
    method: "POST", target: `/ui/input/${id}`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "answer=" + encodeURIComponent("Fly — ucuz") + "&custom=",
  });
  const answer = await callTool(port, { request_id: p.request_id, wait_seconds: 4 }, 2);
  assert.equal(answer.status, "answered", JSON.stringify(answer));
  assert.deepEqual(answer.selected, ["Fly — ucuz"]);
  assert.equal(answer.custom, undefined);
  assert.equal(answer.answer, "Fly — ucuz");
});

test("ht_ask: yeniden başlatmaya dayanıklı — cevap diskte kalır, sırlar yazılmaz", async (t) => {
  const dir = tmp("ht-ask-store-");
  const store = path.join(dir, "state", "inputs.json");
  const { UserInputs } = await import("../dist/user-input.js");

  const a = new UserInputs({ store });
  const open = a.create("static", { title: "Açık soru", kind: "string", secret: false, ttlMs: 600_000,
    fields: [{ name: "answer", title: "Cevap", kind: "string", required: true, choices: ["evet", "hayır"] }] });
  a.submit(open.id, { answer: "evet" });

  const secretForm = a.create("static", { title: "Sır", kind: "string", secret: false, ttlMs: 600_000,
    fields: [{ name: "token", title: "Token", kind: "string", required: true, secret: true }] });
  a.submit(secretForm.id, { token: "sk-canary-1234567890" });
  assert.equal(fs.readFileSync(store, "utf8").includes("sk-canary"), false, "sır diske yazılmamalı");

  // yeni süreç gibi: aynı dosyadan taze örnek
  const b = new UserInputs({ store: store });
  const restored = b.view(b.get("static", open.id));
  assert.equal(restored.status, "ready");
  assert.equal(restored.values.answer, "evet");
  assert.throws(() => b.get("static", secretForm.id), /does not exist|cleared/, "sır formu geri yüklenmez");
});

test("ht_ask: kayıp request_id bir hata değil, status=lost döner", async (t) => {
  const { port } = await start(t);
  const lost = await callTool(port, { request_id: "A".repeat(40) }, 1);
  assert.equal(lost.status, "lost", JSON.stringify(lost));
  assert.match(lost.next, /yeniden sor/);
});
