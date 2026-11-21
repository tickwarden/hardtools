import { timingSafeEqual } from "node:crypto";

/** Compare opaque protocol values, not password hashes. The trusted length controls the
 * comparison; checking the original lengths afterwards prevents truncation/padding matches. */
export function equalSecret(candidate: string, expected: string): boolean {
  const incoming = Buffer.from(candidate, "utf8"), known = Buffer.from(expected, "utf8");
  const fixed = Buffer.alloc(known.length);
  incoming.copy(fixed, 0, 0, known.length);
  return timingSafeEqual(fixed, known) && incoming.length === known.length;
}
