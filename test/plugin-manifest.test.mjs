// Eklenti manifesti: userConfig secenekleri, MCP sunucu bildirimleri ve bunlarin
// gercekten calisan ortam degiskenlerine baglandigini dogrular.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { envFlag, localToolsDisabled } from "../dist/config.js";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(fs.readFileSync(new URL(".claude-plugin/plugin.json", root), "utf8"));
const dotMcp = JSON.parse(fs.readFileSync(new URL(".mcp.json", root), "utf8"));
const entry = path.resolve(process.env.HT_ENTRY ?? "dist/index.js");
const tmp = (prefix) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
const text = (result) => result.content.map(item => item.text).join("\n");

const EXPECTED_OPTIONS = {
  profile: { type: "string", default: "balanced", options: ["balanced", "strict", "open"] },
  workspace_root: { type: "directory" },
  allow_local_tools: { type: "boolean", default: true },
  allow_workspace_https: { type: "boolean", default: false },
  workspace_name: { type: "string", default: "project" },
  auto_renew: { type: "boolean", default: false },
  mcp_url: { type: "string" },
  mcp_token: { type: "string", sensitive: true }
};

function walkStrings(value, visit) {
  if (typeof value === "string") visit(value);
  else if (Array.isArray(value)) value.forEach(item => walkStrings(item, visit));
  else if (value && typeof value === "object") Object.values(value).forEach(item => walkStrings(item, visit));
}

function envFor(userRoot, audit, extra = {}) {
  const config = path.join(audit, "config.json");
  fs.writeFileSync(config, JSON.stringify({ audit: { dir: path.join(audit, "log") } }));
  const base = { ...process.env, HARDTOOLS_ROOTS: userRoot, HARDTOOLS_CONFIG: config };
  for (const key of ["HARDTOOLS_PROFILE", "HARDTOOLS_ALLOW_LOCAL_TOOLS", "HARDTOOLS_WORKSPACE_HTTPS", "HARDTOOLS_HTTP_ALLOW_LOCAL_TOOLS"]) delete base[key];
  return { ...base, ...extra };
}

async function withServer(extraEnv, run) {
  const userRoot = tmp("ht-plugin-root-");
  const audit = tmp("ht-plugin-audit-");
  const client = new Client({ name: "plugin-manifest-test", version: "0" });
  await client.connect(new StdioClientTransport({
    command: process.execPath,
    args: [entry],
    env: envFor(userRoot, audit, extraEnv),
    stderr: "ignore"
  }));
  try {
    return await run(client, userRoot);
  } finally {
    await client.close();
  }
}

test("plugin manifest: every userConfig option is a complete, strict object", () => {
  const options = manifest.userConfig;
  assert.ok(options && typeof options === "object", "userConfig eksik");
  assert.deepEqual(Object.keys(options).sort(), Object.keys(EXPECTED_OPTIONS).sort());
  for (const [key, expected] of Object.entries(EXPECTED_OPTIONS)) {
    const option = options[key];
    assert.match(key, /^[a-z][a-z0-9_]*$/, `${key} anahtar bicimi`);
    assert.ok(["string", "number", "boolean", "directory", "file"].includes(option.type), `${key}.type gecersiz`);
    assert.equal(option.type, expected.type, `${key}.type`);
    assert.ok(typeof option.title === "string" && option.title.trim(), `${key}.title zorunlu`);
    assert.ok(typeof option.description === "string" && option.description.trim(), `${key}.description zorunlu`);
    for (const unknown of Object.keys(option)) {
      assert.ok(["type", "title", "description", "required", "default", "options", "multiple", "sensitive", "min", "max"].includes(unknown), `${key}.${unknown} bilinmeyen alan`);
    }
    if ("default" in expected) assert.deepEqual(option.default, expected.default, `${key}.default`);
    if (expected.options) {
      assert.deepEqual(option.options, expected.options, `${key}.options`);
      assert.ok(option.options.includes(option.default), `${key}.default bir secenek olmali`);
    }
    if (expected.sensitive) assert.equal(option.sensitive, true, `${key}.sensitive`);
  }
});

test("plugin manifest: MCP servers declare no literal credential and only declared options", () => {
  const servers = manifest.mcpServers;
  assert.deepEqual(Object.keys(servers).sort(), ["hardtools", "hardtools-remote"]);

  const local = servers.hardtools;
  assert.equal(local.command, "node");
  assert.deepEqual(local.args, ["${CLAUDE_PLUGIN_ROOT}/bundle/index.js"]);
  assert.deepEqual(local.env, {
    HARDTOOLS_PROFILE: "${user_config.profile}",
    HARDTOOLS_ROOTS: "${user_config.workspace_root}",
    HARDTOOLS_ALLOW_LOCAL_TOOLS: "${user_config.allow_local_tools}",
    HARDTOOLS_WORKSPACE_HTTPS: "${user_config.allow_workspace_https}"
  });

  const remote = servers["hardtools-remote"];
  assert.equal(remote.type, "http");
  assert.equal(remote.url, "${user_config.mcp_url}");
  assert.deepEqual(remote.headers, { Authorization: "Bearer ${user_config.mcp_token}" });

  walkStrings(manifest, value => {
    for (const match of value.matchAll(/\$\{user_config\.([A-Za-z0-9_]+)\}/g)) {
      assert.ok(manifest.userConfig[match[1]], `bildirilmemis user_config anahtari: ${match[1]}`);
    }
    assert.ok(!/\b(gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer [A-Za-z0-9._-]{20,})\b/.test(value), "manifestte duz metin kimlik bilgisi var");
  });
});

test("plugin manifest: the inline local server matches .mcp.json used outside plugins", () => {
  const fromFile = dotMcp.mcpServers.hardtools;
  const fromManifest = manifest.mcpServers.hardtools;
  assert.equal(fromManifest.command, fromFile.command);
  assert.deepEqual(fromManifest.args, fromFile.args);
  assert.equal(fromManifest.env.HARDTOOLS_PROFILE, "${user_config.profile}");
  assert.equal(fromFile.env.HARDTOOLS_PROFILE, "balanced", ".mcp.json user_config referansi tasimamali");
});

test("plugin manifest: option names are wired to the environment the server reads", () => {
  const saved = { ...process.env };
  try {
    process.env.HARDTOOLS_ALLOW_LOCAL_TOOLS = "false";
    assert.equal(localToolsDisabled(), true);
    for (const value of ["true", "1", "", "evet"]) {
      process.env.HARDTOOLS_ALLOW_LOCAL_TOOLS = value;
      assert.equal(localToolsDisabled(), false, `${value} kapatmamali`);
    }
    for (const value of ["1", "true", "yes", "on"]) {
      process.env.HARDTOOLS_WORKSPACE_HTTPS = value;
      assert.equal(envFlag("HARDTOOLS_WORKSPACE_HTTPS"), true, `${value} acmali`);
    }
    for (const value of ["0", "false", "", "hayir"]) {
      process.env.HARDTOOLS_WORKSPACE_HTTPS = value;
      assert.equal(envFlag("HARDTOOLS_WORKSPACE_HTTPS"), false, `${value} acmamali`);
    }
  } finally {
    process.env = saved;
  }
});

test("plugin manifest: allow_local_tools=false really makes the plugin read-only", async () => {
  await withServer({ HARDTOOLS_ALLOW_LOCAL_TOOLS: "false" }, async (client, userRoot) => {
    const status = JSON.parse(text(await client.callTool({ name: "ht_status", arguments: {} })));
    assert.equal(status.shell.execution, "disabled");
    assert.equal(status.shell.enabled, false);
    const write = await client.callTool({ name: "ht_write", arguments: { path: "yeni.txt", content: "x\n" } });
    assert.ok(write.isError, "yazma reddedilmeli");
    assert.ok(!fs.existsSync(path.join(userRoot, "yeni.txt")));
    const shell = await client.callTool({ name: "ht_shell", arguments: { argv: ["echo", "x"] } });
    assert.ok(shell.isError, "kabuk reddedilmeli");
  });
});

test("plugin manifest: defaults and true keep the previous writable behaviour", async () => {
  await withServer({ HARDTOOLS_ALLOW_LOCAL_TOOLS: "true" }, async (client) => {
    const status = JSON.parse(text(await client.callTool({ name: "ht_status", arguments: {} })));
    assert.equal(status.shell.execution, "host");
    const write = await client.callTool({ name: "ht_write", arguments: { path: "ok.txt", content: "selam\n" } });
    assert.ok(!write.isError, text(write));
  });
  await withServer({}, async (client) => {
    const status = JSON.parse(text(await client.callTool({ name: "ht_status", arguments: {} })));
    assert.equal(status.profile, "balanced");
    assert.equal(status.shell.execution, "host", "ortam degiskeni yoksa davranis degismemeli");
  });
});

test("plugin manifest: the profile option reaches the server as HARDTOOLS_PROFILE", async () => {
  await withServer({ HARDTOOLS_PROFILE: "strict" }, async (client) => {
    const status = JSON.parse(text(await client.callTool({ name: "ht_status", arguments: {} })));
    assert.equal(status.profile, "strict");
  });
});

test("plugin sürümü package.json ile aynı (Claude'un gösterdiği sürüm kaymasın)", () => {
  const pkg = JSON.parse(fs.readFileSync(new URL("package.json", root), "utf8"));
  assert.equal(manifest.version, pkg.version, "0.4.0'da takılı kalmıştı: .claude-plugin/plugin.json elle güncellenmeli");
});
