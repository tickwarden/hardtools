// Allowlist joker eşleştirmesi: '*' her dizi, '?' tek karakter; jokersiz desen birebir.
import test from "node:test";
import assert from "node:assert/strict";
import { globMatch, hasWildcard, anyMatch } from "../dist/match.js";

test("globMatch: joker '*' hepsini eşler", () => {
  assert.equal(globMatch("*", "ls"), true);
  assert.equal(globMatch("*", ""), true);
});

test("globMatch: önek/sonek ve tek karakter jokerleri", () => {
  assert.equal(globMatch("git*", "git"), true);
  assert.equal(globMatch("git*", "git-lfs"), true);
  assert.equal(globMatch("git*", "ls"), false);
  assert.equal(globMatch("e?ho", "echo"), true);
  assert.equal(globMatch("e?ho", "echoo"), false);
  assert.equal(globMatch("*.github.com", "api.github.com"), true);
  assert.equal(globMatch("*.github.com", "github.com"), false);
  assert.equal(globMatch("api*.example.com", "api2.example.com"), true);
});

test("globMatch: jokersiz desen birebir eşleşir", () => {
  assert.equal(globMatch("echo", "echo"), true);
  assert.equal(globMatch("echo", "echox"), false);
  assert.equal(hasWildcard("echo"), false);
  assert.equal(hasWildcard("ec*"), true);
});

test("anyMatch: listeden herhangi biri yeter", () => {
  assert.equal(anyMatch(["git"], "git"), true);
  assert.equal(anyMatch(["git"], "ls"), false);
  assert.equal(anyMatch(["git", "ls*"], "lsblk"), true);
  assert.equal(anyMatch([], "ls"), false);
});
