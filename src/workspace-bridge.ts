// Guest-only entry point, mounted read-only and run *after* Bubblewrap isolation.
// The loopback listener is in a fresh network namespace. Its Unix peer is a
// CONNECT-only broker, not a host port, general network interface or resolver.
import net from "node:net";

const relay = net.createServer(client => {
  const upstream = net.createConnection("/runtime/https.sock");
  client.on("error", () => client.destroy()); upstream.on("error", () => upstream.destroy());
  client.once("close", () => upstream.destroy()); upstream.once("close", () => client.destroy());
  client.pipe(upstream); upstream.pipe(client);
});
relay.maxConnections = 8;
relay.on("error", () => { console.error("workspace HTTPS relay unavailable"); process.exit(125); });
relay.listen(0, "127.0.0.1", () => {
  const address = relay.address();
  if (!address || typeof address === "string") process.exit(125);
  // The parent guest shell reads this once before exec; no command or caller data here.
  process.stdout.write(`${address.port}\n`);
});
