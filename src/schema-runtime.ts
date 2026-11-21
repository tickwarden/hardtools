// Import before the SDK constructs any of its schemas: Zod selects the object parser at construction.
// No change to validation semantics. Use the interpreter in both the npm CLI and the offline bundle.
import { config } from "zod/v4/core";
config({ jitless: true });
