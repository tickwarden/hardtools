import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { equalSecret } from '../dist/credentials.js';
import { SHARE_CWD, shareIdFromUri } from '../dist/share.js';

// The consent form, static bearer and signed MAC comparisons use the same exact-byte check.
test('opaque credentials compare the complete UTF-8 bytes, including length, not a fast password hash', () => {
  for (const s of ['ASCII', 'çok baytlı', 'pad\0', '']) assert.equal(equalSecret(s, s), true);
  for (const [a,b] of [['same-length', 'same-lengti'], ['key', 'key\0'], ['key-more','key'], ['é','e\u0301'], ['', 'x']]) {
    assert.equal(equalSecret(a,b), false);
    assert.equal(equalSecret(b,a), false);
  }
});

test('resource routes accept only the literal share prefix and one complete opaque ID', () => {
  const prefix = 'hardtools-share://local' + SHARE_CWD, id = 'aZ-_012345'.repeat(4) + 'abc';
  assert.equal(shareIdFromUri(prefix + id), id);
  for (const uri of [prefix, prefix + id.slice(1), prefix + id + 'a', prefix + id + '?view', prefix + id + '#x', prefix + id + '/', prefix + 'a'.repeat(41) + '**', prefix + 'a'.repeat(42) + '\n', prefix.replace('://local/', '://other/') + id])
    assert.equal(shareIdFromUri(uri), null);
});

test('MCP schema validation and tool calls work with V8 string code generation forbidden', async () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ht-interpreted-')));
  const root = path.join(dir, 'root'), settings = path.join(dir,'settings');
  fs.mkdirSync(root); fs.mkdirSync(settings);
  const cfg = path.join(settings,'config.json'); fs.writeFileSync(cfg, JSON.stringify({ audit: { dir:path.join(dir,'log') } }));
  const client = new Client({name:'interpreter-test',version:'1'});
  try {
    await client.connect(new StdioClientTransport({ command:process.execPath, args:['--disallow-code-generation-from-strings', path.resolve(process.env.HT_ENTRY ?? 'dist/index.js')], env:{PATH:process.env.PATH, HARDTOOLS_CONFIG:cfg, HARDTOOLS_ROOTS:root}, stderr:'ignore' }));
    const {tools} = await client.listTools(); const write = tools.find(t=>t.name==='ht_write');
    assert.equal(write.inputSchema.properties.content.type, 'string');
    const bad = await client.callTool({ name:'ht_write', arguments:{path:'file.txt', content:7} });
    assert.equal(bad.isError,true); assert.equal(fs.existsSync(path.join(root,'file.txt')),false);
    const good = await client.callTool({ name:'ht_write', arguments:{path:'file.txt', content:'ok'} });
    assert.ok(!good.isError, good.content[0]?.text); assert.equal(fs.readFileSync(path.join(root,'file.txt'),'utf8'),'ok');
  } finally { await client.close(); fs.rmSync(dir, {recursive:true,force:true}); }
});
