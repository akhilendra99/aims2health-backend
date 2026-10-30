const test = require("node:test");
const assert = require("node:assert/strict");
const {
  MIN_PASSWORD_CHARACTERS,
  MAX_PASSWORD_CHARACTERS,
  MAX_PASSWORD_BYTES,
  INVALID_PASSWORD_MESSAGE,
  isPasswordValid,
  generateInitialPassword,
} = require("../utils/password-policy");

test("shared password policy enforces the documented character and category boundaries", () => {
  assert.equal(MIN_PASSWORD_CHARACTERS, 8);
  assert.equal(MAX_PASSWORD_CHARACTERS, 12);
  assert.equal(MAX_PASSWORD_BYTES, 72);
  assert.equal(isPasswordValid("G7!mR2pa"), true, "minimum length is accepted");
  assert.equal(isPasswordValid("W8!qz3Lm2AaB"), true, "maximum length is accepted");
  for (const password of [
    undefined,
    null,
    12345678,
    "",
    "Aa1!aaa",
    "Aa1!aaaa12345",
    "aa1!aaaa", // missing uppercase
    "AA1!AAAA", // missing lowercase
    "Aaa!aaaa", // missing number
    "Aa11aaaa", // missing supported special character
    "Aa1!aa a",
    "Aa1!a\na",
    "Aa1!😀abc",
    "Äa1!aaaa\u0308", // no implicit Unicode normalization
    "A".repeat(73),
    "bad\uD800char1!",
  ]) {
    assert.equal(isPasswordValid(password), false, `rejects ${String(password)}`);
  }
  assert.equal(isPasswordValid("Äbcdef1!"), false, "non-ASCII letters are rejected");
  assert.equal(isPasswordValid("Abcdef١!"), false, "non-ASCII numerals are rejected");
});

test("common and easy password families are blocked locally", () => {
  for (const password of ["Password1!", "P@ssw0rd!", "Qwerty123!", "Welcome12!", "Admin123!", "Aims2health1!", "Aa1!aaaa"]) {
    assert.equal(isPasswordValid(password), false, `${password} is on the local blocklist`);
  }
  assert.match(INVALID_PASSWORD_MESSAGE, /8-12 ASCII characters/);
});

test("generated initial credentials satisfy the same policy and are not the shared legacy default", () => {
  const generated = new Set();
  for (let index = 0; index < 100; index++) {
    const password = generateInitialPassword();
    assert.equal(isPasswordValid(password), true);
    generated.add(password);
  }
  assert.ok(generated.size > 90, "generated credentials have no fixed/reused default");
});
