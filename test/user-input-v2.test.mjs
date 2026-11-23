// 0.5.1 — ht_user_input v2: çok alanlı form, seçenekler, uzun yoklama, iptal, dedupe.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { UserInputs, fieldEnvName } from "../dist/user-input.js";

const post = (port, path, body) => new Promise((resolve, reject) => {
  const req = http.request({ host: "127.0.0.1", port, path, method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" } }, (res) => {
    let data = ""; res.on("data", (c) => { data += c; }); res.on("end", () => resolve({ status: res.statusCode, body: data }));
  });
  req.on("error", reject); req.write(body); req.end();
});

test("user input v2: multi-field form answers become $HT_USER_INPUT and $HT_USER_INPUT_<NAME>", () => {
  const inputs = new UserInputs();
  const req = inputs.create("static", {
    title: "Yeni servis",
    kind: "string", secret: false, ttlMs: 60_000,
    fields: [
      { name: "ad", title: "Ad", kind: "string", secret: false, required: true },
      { name: "port", title: "Port", kind: "number", secret: false, required: true, default: "8080" },
      { name: "mod", title: "Mod", kind: "string", secret: false, required: false, choices: ["a", "b"] },
      { name: "token", title: "Token", kind: "string", secret: true, required: false },
    ],
  });
  assert.equal(inputs.envFor("static").HT_USER_INPUT, undefined);
  inputs.submit(req.id, { ad: "api", port: "", mod: "b", token: "sk-canary-1234567890" });
  const env = inputs.envFor("static");
  assert.deepEqual(JSON.parse(env.HT_USER_INPUT), { ad: "api", port: 8080, mod: "b", token: "sk-canary-1234567890" });
  assert.equal(env[fieldEnvName("ad")], "api");
  assert.equal(env[fieldEnvName("port")], "8080");
  assert.match(inputs.mask("gizli: sk-canary-1234567890"), /\[redacted:HT_USER_INPUT\]/);
  // Model yüzeyinde sır yok:
  const view = inputs.view(req);
  assert.equal(view.status, "ready");
  assert.equal(view.values.token, null);
  assert.equal(view.filled.token, true);
  assert.equal(view.values.ad, "api");
  assert.equal(view.kind, "form");
});

test("user input v2: choices, defaults, required and per-kind validation are enforced", () => {
  const inputs = new UserInputs();
  const single = inputs.create("s1", { title: "Ortam?", kind: "string", secret: false, ttlMs: 60_000, choices: ["dev", "prod"], default: "dev" });
  assert.throws(() => inputs.submit(single.id, "staging"), /one of the offered choices/);
  inputs.submit(single.id, "prod");
  assert.equal(inputs.envFor("s1").HT_USER_INPUT, "prod");

  const form = inputs.create("s2", { title: "Form", kind: "string", secret: false, ttlMs: 60_000, fields: [
    { name: "ad", title: "Ad", kind: "string", secret: false, required: true },
    { name: "sayi", title: "Sayı", kind: "number", secret: false, required: false },
  ] });
  assert.throws(() => inputs.submit(form.id, { ad: "", sayi: "1" }), /required/);
  assert.throws(() => inputs.submit(form.id, { ad: "x", sayi: "12abc" }), /expected a number/);
  inputs.submit(form.id, { ad: "x", sayi: "" });
  assert.equal(inputs.envFor("s2")[fieldEnvName("sayi")], undefined);
});

test("user input v2: dedupe reuses an open link, list/status/cancel behave", async () => {
  const inputs = new UserInputs();
  const a = inputs.create("o", { title: "A", kind: "string", secret: false, ttlMs: 60_000, dedupeKey: "k1" });
  const b = inputs.create("o", { title: "A", kind: "string", secret: false, ttlMs: 60_000, dedupeKey: "k1" });
  assert.equal(a.id, b.id);
  assert.equal(inputs.list("o").length, 1);
  assert.equal(inputs.list("o")[0].status, "pending");

  // Uzun yoklama: 200 ms sonra yanıtlanınca bekleme erken döner.
  const waiter = inputs.wait("o", a.id, 5000);
  setTimeout(() => inputs.submit(a.id, "tamam"), 200);
  const done = await waiter;
  assert.equal(done?.submittedAt !== undefined, true);
  assert.equal(inputs.status(done), "ready");

  const c = inputs.create("o2", { title: "B", kind: "boolean", secret: false, ttlMs: 60_000 });
  assert.equal(inputs.cancel(c.id), true);
  assert.equal(inputs.status(inputs.get("o2", c.id)), "cancelled");
  assert.equal(inputs.envFor("o2").HT_USER_INPUT, undefined);
});

test("user input v2: browser form renders selects, textareas, secret boxes and a cancel button", () => {
  const inputs = new UserInputs();
  const req = inputs.create("ui", { title: "Kurulum", kind: "string", secret: false, ttlMs: 60_000, help: "Hepsini doldur", fields: [
    { name: "ad", title: "Ad", kind: "string", secret: false, required: true, placeholder: "api" },
    { name: "mod", title: "Mod", kind: "string", secret: false, required: false, choices: ["a", "b"], default: "b" },
    { name: "liste", title: "Liste", kind: "array", secret: false, required: false },
    { name: "gizli", title: "Gizli", kind: "string", secret: true, required: false },
  ] });
  const res = {
    headersSent: false, statusCode: 0, body: "",
    writeHead(code) { this.statusCode = code; },
    end(body) { this.body = body; },
  };
  inputs.handle({ method: "GET", url: `/ui/input/${req.id}`, headers: {}, on() {} }, res, `/ui/input/${req.id}`, "http://127.0.0.1:1");
  assert.equal(res.statusCode, 200);
  assert.match(res.body, /<select id="f_mod"/);
  assert.match(res.body, /<option selected>b<\/option>/);
  assert.match(res.body, /<textarea id="f_liste"/);
  assert.match(res.body, /type="password" id="f_gizli"/);
  assert.match(res.body, /name="action" value="cancel"/);
  assert.match(res.body, /Kurulum/);
});

test("user input v2: POST submit and cancel work over the real HTTP handler", async (t) => {
  const inputs = new UserInputs();
  const srv = http.createServer((req, res) => { if (!inputs.handle(req, res, (req.url ?? "").split("?")[0], "http://127.0.0.1:1")) { res.writeHead(404); res.end(); } });
  await new Promise((r) => srv.listen(0, "127.0.0.1", () => r()));
  t.after(() => srv.close());
  const port = srv.address().port;

  const form = inputs.create("http", { title: "İki alan", kind: "string", secret: false, ttlMs: 60_000, fields: [
    { name: "a", title: "A", kind: "string", secret: false, required: true },
    { name: "b", title: "B", kind: "string", secret: true, required: false },
  ] });
  const ok = await post(port, `/ui/input/${form.id}`, "a=deger&b=cok-gizli-1234");
  assert.equal(ok.status, 200, ok.body);
  assert.doesNotMatch(ok.body, /cok-gizli-1234/); // sır sayfada tekrar gösterilmez
  assert.equal(inputs.envFor("http")[fieldEnvName("a")], "deger");

  const second = inputs.create("http2", { title: "İptal", kind: "string", secret: false, ttlMs: 60_000 });
  const cancelled = await post(port, `/ui/input/${second.id}`, "action=cancel");
  assert.equal(cancelled.status, 200);
  assert.equal(inputs.status(inputs.get("http2", second.id)), "cancelled");
});
