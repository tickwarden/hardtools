# Credits / AI involvement

The original source code, tests, build scripts and documentation were **written by an AI model (Claude, Anthropic)** in a chat session on 2026-11-12, at the request of the repository owner.

- Original source files carry an `AI-generated (Claude, Anthropic)` header. The later connection reader and workspace tools were AI-assisted as well.
- The code was compiled and exercised by the automated test suite in `test/` (see `SECURITY.md` for what is and is not covered), but it has **not had an independent human security review**. Do that before trusting it with anything that matters.
- The one-file connection card uses Web Crypto. Its offline importer also bundles `age-encryption` (legacy packets) and `fflate` (ZIP) at build time; their licenses and bundled transitive library notices are included in `BAGLAN.html`.
- Image search uses the Wikimedia Commons API and, for the Minecraft Fabric project logo, the official [FabricMC site](https://fabricmc.net/). The logo is fetched on request, not redistributed in the package; no reuse license is assumed. Individual works have their own authors and licenses; the source page is returned with each result.
- Third-party dependencies: `@modelcontextprotocol/sdk`, `zod` (runtime); `typescript`, `esbuild`, `@types/node` (build).
