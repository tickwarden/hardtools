// Deterministic, self-contained offline reader. All libraries are bundled at build time.
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
const read = p => readFile(join(root, p), 'utf8');
const hash = s => createHash('sha256').update(s).digest('base64');

export async function buildReader() {
  const built = await build({ absWorkingDir: root, entryPoints: ['reader/app.mjs'], platform: 'browser', target: ['chrome100', 'firefox110'], charset: 'utf8', format: 'iife', minify: true, bundle: true, write: false, legalComments: 'none' });
  const js = built.outputFiles[0].text.trim().replace(/<\/script/gi, '<\\/script');
  const css = (await read('reader/style.css')).trim();
  const deps = ['age-encryption', 'fflate', '@noble/ciphers', '@noble/curves', '@noble/hashes', '@noble/post-quantum', '@scure/base'];
  const notices = (await Promise.all(deps.map(async n => n + '\n' + await read(`node_modules/${n}/LICENSE`)))).join('\n').replaceAll('--', '—');
  const parts = { JS: js, CSS: css, JSHASH: hash(js), CSSHASH: hash(css), NOTICES: notices };
  const html = (await read('reader/template.html')).replace(/@@(JS|CSS|JSHASH|CSSHASH|NOTICES)@@/g, (_, part) => parts[part]);
  await mkdir(join(root, 'bundle'), { recursive: true });
  await writeFile(join(root, 'bundle/BAGLAN.html'), html);
}
