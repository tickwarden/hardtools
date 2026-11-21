// AI-assisted. Build the same interpreted validators as the unbundled CLI, without embedding an unused JIT compiler.
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { buildReader } from "./scripts/build-reader.mjs";

const zodCore = fileURLToPath(import.meta.resolve("zod/v4/core"));
const interpretedObjects = {
  name: "zod-interpreted-objects",
  setup(builder) {
    builder.onLoad({ filter: /[/\\]v4[/\\]core[/\\]index\.js$/ }, async ({ path }) => {
      if (path !== zodCore) return;
      // Zod Classic asks its own core barrel for the object constructor. The explicit
      // re-export takes precedence over the original export *, selecting Zod's real
      // non-generating parser (also used by Mini). No edits to installed packages.
      return { loader: "js", resolveDir: dirname(path), watchFiles: [path], contents:
        (await readFile(path, "utf8")) + '\nexport { $ZodObject as $ZodObjectJIT } from "./schemas.js";\n' };
    });
  },
};

const { metafile } = await build({
  entryPoints: { index: "src/index.ts", "search-worker": "src/search-worker.ts", "workspace-bridge": "src/workspace-bridge.ts" },
  outdir: "bundle", bundle: true, platform: "node", format: "esm", target: "node20", minify: false, sourcemap: false, legalComments: "none",
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
  plugins: [interpretedObjects], metafile: true,
});
// Check what was actually emitted (not just imported for tree shaking). A dependency update
// that reintroduces a compiler, general template matcher or URL adapter must be reviewed.
const unnecessary = ["/zod/v4/core/doc.js", "/zod/v4/core/compile.js", "/@hono/node-server/", "/@modelcontextprotocol/sdk/dist/esm/shared/uriTemplate.js"];
for (const output of Object.values(metafile.outputs)) {
  for (const [file, { bytesInOutput }] of Object.entries(output.inputs)) {
    if (bytesInOutput && unnecessary.some(part => file.replaceAll("\\", "/").includes(part)))
      throw new Error(`Unexpected dependency in the hardtools runtime: ${file}`);
  }
}
await buildReader();
