import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);

// src/workspace-bridge.ts
import net from "node:net";
var relay = net.createServer((client) => {
  const upstream = net.createConnection("/runtime/https.sock");
  client.on("error", () => client.destroy());
  upstream.on("error", () => upstream.destroy());
  client.once("close", () => upstream.destroy());
  upstream.once("close", () => client.destroy());
  client.pipe(upstream);
  upstream.pipe(client);
});
relay.maxConnections = 8;
relay.on("error", () => {
  console.error("workspace HTTPS relay unavailable");
  process.exit(125);
});
relay.listen(0, "127.0.0.1", () => {
  const address = relay.address();
  if (!address || typeof address === "string") process.exit(125);
  process.stdout.write(`${address.port}
`);
});
