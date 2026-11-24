// ht_new_shell_env / ht_stop / ht_transfer_file: ortam rotasyonu, oturum kapatma
// direktifi ve dışarıdan dosya aktarma.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const tmp = (p) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));

async function connect(t, { root, audit, envs, sources } = {}) {
  root = root ?? tmp("ht-env-root-");
  audit = audit ?? tmp("ht-env-audit-");
  const cfg = path.join(audit, "config.json");
  fs.mkdirSync(path.join(audit, "log"), { recursive: true });
  fs.writeFileSync(cfg, JSON.stringify({ audit: { dir: path.join(audit, "log") } }));
  const base = { ...process.env, HARDTOOLS_ROOTS: root, HARDTOOLS_CONFIG: cfg };
  delete base.HARDTOOLS_PROFILE;
  const client = new Client({ name: "envs-test", version: "0" });
  await client.connect(new StdioClientTransport({
    command: process.execPath, args: [entry, "--profile", "balanced"],
    env: {
      ...base,
      ...(envs ? { HARDTOOLS_ENVS_DIR: envs } : {}),
      ...(sources ? { HARDTOOLS_TRANSFER_SOURCES: sources } : {}),
    },
    stderr: "ignore",
  }));
  t.after(() => client.close());
  return { client, root, audit };
}
const text = (r) => r.content.map(c => c.text ?? "").join("\n");

test("ht_new_shell_env: a fresh root, the old tree in the recycle bin, variables cleared", async (t) => {
  const root = tmp("ht-env-root-"); const envs = tmp("ht-env-base-");
  const { client } = await connect(t, { root, envs });
  await client.callTool({ name: "ht_shell", arguments: { argv: ["node", "-e", "const fs=require('fs'),p=require('path');fs.mkdirSync(p.dirname(process.argv[1])||'.',{recursive:true});fs.writeFileSync(process.argv[1],process.argv[2])", "eski.txt", "eski içerik\n"] } });
  await client.callTool({ name: "ht_add_var", arguments: { name: "RENK", value: "mavi" } });

  const res = await client.callTool({ name: "ht_new_shell_env", arguments: { label: "temiz" } });
  assert.ok(!res.isError, text(res));
  const info = JSON.parse(text(res));
  assert.match(info.name, /^env-.+-temiz$/);
  assert.ok(fs.existsSync(info.root), "yeni kök oluşmalı");
  assert.equal(fs.readdirSync(info.root).length, 0, "yeni ortam boş olmalı");
  assert.ok(info.previous_moved_to && fs.existsSync(info.previous_moved_to), "eski ağaç geri dönüşümde olmalı");
  assert.ok(fs.existsSync(path.join(info.previous_moved_to, "eski.txt")), "eski dosya recycle'a taşınmalı");
  assert.equal(info.variables_cleared, 1);

  // Yeni kök aktif: yazma buraya gider, eski dosya görünmez.
  const w = await client.callTool({ name: "ht_shell", arguments: { argv: ["node", "-e", "const fs=require('fs'),p=require('path');fs.mkdirSync(p.dirname(process.argv[1])||'.',{recursive:true});fs.writeFileSync(process.argv[1],process.argv[2])", "yeni.txt", "yeni\n"] } });
  assert.ok(!w.isError, text(w));
  assert.ok(fs.existsSync(path.join(info.root, "yeni.txt")));
  const rd = await client.callTool({ name: "ht_shell", arguments: { argv: ["cat", "eski.txt"] } });
  assert.ok(rd.isError, "eski dosya yeni kökte olmamalı");

  const status = JSON.parse(text(await client.callTool({ name: "ht_status", arguments: {} })));
  assert.equal(status.roots[0], info.root);
  assert.equal(status.environment.name, info.name);
  assert.deepEqual(status.variables, { enabled: true, inheritByDefault: false });
  assert.deepEqual(JSON.parse(text(await client.callTool({ name: "ht_list_vars", arguments: {} }))), { names: [] });
});

test("ht_new_shell_env: carry_files=true keeps the tree, and bad labels are refused", async (t) => {
  const root = tmp("ht-env-root-"); const envs = tmp("ht-env-base-");
  const { client } = await connect(t, { root, envs });
  await client.callTool({ name: "ht_shell", arguments: { argv: ["node", "-e", "const fs=require('fs'),p=require('path');fs.mkdirSync(p.dirname(process.argv[1])||'.',{recursive:true});fs.writeFileSync(process.argv[1],process.argv[2])", "kalsin.txt", "veri\n"] } });
  const res = JSON.parse(text(await client.callTool({ name: "ht_new_shell_env", arguments: { carry_files: true } })));
  assert.equal(res.previous_moved_to, null);
  assert.ok(fs.existsSync(path.join(res.root, "kalsin.txt")), "taşınan dosya yeni kökte olmalı");
  const bad = await client.callTool({ name: "ht_new_shell_env", arguments: { label: "Büyük Harf" } });
  assert.ok(bad.isError, "geçersiz etiket reddedilmeli");
});

test("ht_new_shell_env: the default base stays put across rotations", async (t) => {
  const root = tmp("ht-env-root-");
  const { client } = await connect(t, { root });
  const first = JSON.parse(text(await client.callTool({ name: "ht_new_shell_env", arguments: {} })));
  const second = JSON.parse(text(await client.callTool({ name: "ht_new_shell_env", arguments: {} })));
  assert.equal(first.base, second.base, "taban her rotasyonda aynı kalmalı");
  assert.equal(first.base, path.join(path.dirname(root), "envs"));
  assert.ok(second.name.startsWith("env-"));
  assert.ok(second.root.startsWith(second.base + path.sep));
  const status = JSON.parse(text(await client.callTool({ name: "ht_status", arguments: {} })));
  assert.equal(status.environment.name, second.name, "aktif ortam adı görünmeli");
  assert.equal(status.environment.base, second.base);
});

test("ht_stop: reset + yapılandırılmış end_conversation direktifi", async (t) => {
  const root = tmp("ht-env-root-"); const envs = tmp("ht-env-base-"); const audit = tmp("ht-env-audit-");
  const { client } = await connect(t, { root, envs, audit });
  await client.callTool({ name: "ht_shell", arguments: { argv: ["node", "-e", "const fs=require('fs'),p=require('path');fs.mkdirSync(p.dirname(process.argv[1])||'.',{recursive:true});fs.writeFileSync(process.argv[1],process.argv[2])", "is.txt", "x\n"] } });
  const res = await client.callTool({ name: "ht_stop", arguments: { title: "Refactor bitti", reason: "İş tamamlandı" } });
  assert.ok(!res.isError, text(res));
  const info = JSON.parse(text(res));
  assert.equal(info.action, "stop");
  assert.equal(info.title, "Refactor bitti");
  assert.equal(info.reason, "İş tamamlandı");
  assert.equal(info.reset_environment, true);
  assert.equal(info.directive.name, "end_conversation");
  assert.equal(info.directive.title, "Refactor bitti");
  assert.ok(fs.existsSync(info.environment.previous_moved_to));
  assert.equal(fs.readdirSync(info.environment.root).length, 0);

  const none = JSON.parse(text(await client.callTool({ name: "ht_stop", arguments: { title: "t", reason: "r", reset_environment: false, directive: "none" } })));
  assert.equal(none.directive, null);
  assert.equal(none.reset_environment, false);

  // Denetim kaydında başlık ve sebep var.
  const logDir = path.join(audit, "log");
  const log = fs.readdirSync(logDir).map(f => fs.readFileSync(path.join(logDir, f), "utf8")).join("");
  assert.match(log, /"ev":"stop"/);
  assert.match(log, /Refactor bitti/);
});

test("ht_transfer_file: kaynak dizinden kopyalar, dışarıyı ve boyut sınırını reddeder", async (t) => {
  const root = tmp("ht-env-root-"); const uploads = tmp("ht-uploads-");
  fs.writeFileSync(path.join(uploads, "rapor.txt"), "uzun sohbet eki\n");
  const { client } = await connect(t, { root, sources: uploads });

  const sources = JSON.parse(text(await client.callTool({ name: "ht_transfer_file", arguments: { action: "sources" } })));
  assert.equal(sources.sources[0].dir, uploads);
  assert.equal(sources.sources[0].exists, true);

  const res = await client.callTool({ name: "ht_transfer_file", arguments: { source_path: path.join(uploads, "rapor.txt"), dest_path: "gelen/rapor.txt" } });
  assert.ok(!res.isError, text(res));
  const info = JSON.parse(text(res));
  const expected = crypto.createHash("sha256").update("uzun sohbet eki\n").digest("hex");
  assert.equal(info.sha256, expected);
  assert.equal(info.bytes, Buffer.byteLength("uzun sohbet eki\n"));
  assert.ok(fs.existsSync(path.join(root, "gelen", "rapor.txt")));

  const again = await client.callTool({ name: "ht_transfer_file", arguments: { source_path: path.join(uploads, "rapor.txt"), dest_path: "gelen/rapor.txt" } });
  assert.ok(again.isError, "üzerine yazmak için overwrite gerekli");
  const ok = await client.callTool({ name: "ht_transfer_file", arguments: { source_path: path.join(uploads, "rapor.txt"), dest_path: "gelen/rapor.txt", overwrite: true } });
  assert.ok(!ok.isError, text(ok));

  const outside = await client.callTool({ name: "ht_transfer_file", arguments: { source_path: "/etc/hostname", dest_path: "x.txt" } });
  assert.ok(outside.isError);
  assert.match(text(outside), /DENIED \[source_denied\]/);
  const tooBig = await client.callTool({ name: "ht_transfer_file", arguments: { source_path: path.join(uploads, "rapor.txt"), dest_path: "y.txt", max_bytes: 4 } });
  assert.ok(tooBig.isError);
  const dir = await client.callTool({ name: "ht_transfer_file", arguments: { source_path: uploads, dest_path: "z.txt" } });
  assert.ok(dir.isError);
});
