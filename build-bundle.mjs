// AI-generated (Claude, Anthropic), 2026-11-12.
import { build } from "esbuild";
await build({
  entryPoints: { index: "src/index.ts", "search-worker": "src/search-worker.ts" },
  outdir: "bundle", bundle: true, platform: "node", format: "esm", target: "node20", minify: false, sourcemap: false, legalComments: "none",
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
});
