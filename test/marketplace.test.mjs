import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const json = url => JSON.parse(readFileSync(url, 'utf8'));

test('marketplace: the documented install ID resolves to the shipped stdio plugin and bundle', () => {
  const catalog = json(new URL('.claude-plugin/marketplace.json', root));
  assert.equal(catalog.name, 'hardtools-marketplace');
  assert.ok(catalog.owner.name.trim());
  const entries = catalog.plugins.filter(p => p.name === 'hardtools');
  assert.equal(entries.length, 1);
  assert.equal(entries[0].source, './'); // relative to the marketplace root, not .claude-plugin/
  const pluginRoot = new URL(entries[0].source, root);
  const plugin = json(new URL('.claude-plugin/plugin.json', pluginRoot));
  assert.equal(plugin.name, entries[0].name);
  const server = json(new URL('.mcp.json', pluginRoot)).mcpServers[plugin.name];
  assert.equal(server.command, 'node');
  const path = server.args[0];
  assert.equal(path, '${CLAUDE_PLUGIN_ROOT}/bundle/index.js');
  assert.ok(statSync(new URL(path.slice('${CLAUDE_PLUGIN_ROOT}/'.length), pluginRoot)).isFile());
});
