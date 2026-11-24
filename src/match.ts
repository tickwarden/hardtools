// Allowlist eşleştirme yardımcıları: joker desteği ('*' her dizi, '?' tek karakter).
// Joker içermeyen desenler eskisi gibi birebir eşleşir; büyük/küçük harf duyarsız kullanım için
// çağıran taraf küçük harfe çevirir.

/** Desende joker var mı? */
export function hasWildcard(pattern: string): boolean {
  return pattern.includes("*") || pattern.includes("?");
}

/** Tek desen eşleşmesi. '*' sıfır veya daha çok karakter, '?' tek karakter. */
export function globMatch(pattern: string, value: string): boolean {
  if (pattern === "*") return true;
  if (!hasWildcard(pattern)) return pattern === value;
  let re = "^";
  for (const ch of pattern) {
    if (ch === "*") re += ".*";
    else if (ch === "?") re += ".";
    else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  re += "$";
  try { return new RegExp(re, "i").test(value); } catch { return false; }
}

/** Desen listesinden herhangi biri eşleşiyor mu? */
export function anyMatch(patterns: readonly string[], value: string): boolean {
  return patterns.some(p => globMatch(p, value));
}
