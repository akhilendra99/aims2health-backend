const crypto = require("crypto");

const MIN_PASSWORD_CHARACTERS = 8;
const MAX_PASSWORD_CHARACTERS = 12;
// bcrypt processes no more than 72 UTF-8 bytes. The character limit is tighter
// for supported passwords, but keep the byte guard explicit at every boundary.
const MAX_PASSWORD_BYTES = 72;
const ALLOWED_SPECIAL_CHARACTERS = "!@#$%^&*";
const INVALID_PASSWORD_MESSAGE =
  "Password must be 8-12 ASCII characters and include uppercase, lowercase, a number, and one of !@#$%^&*; spaces and common passwords are not allowed.";

// Kept local so raw passwords are never sent to an external password checker.
// Additions should be reviewed and tested alongside the policy.
const BLOCKED_PASSWORDS = new Set([
  "password1!", "password12!", "password123!", "p@ssw0rd!", "passw0rd!",
  "qwerty123!", "qwerty12!", "welcome1!", "welcome12!", "admin123!",
  "admin12!", "letmein1!", "letmein12!", "changeme1!", "iloveyou1!",
  "abc123!!", "aa1!aaaa", "aa123456!", "test1234!", "aims2health1!", "virtualsathi1!",
]);
const BLOCKED_PASSWORD_FAMILIES = /^(?:password|qwerty|welcome|admin|letmein|changeme|iloveyou|test|aims2health|virtualsathi)[0-9]{0,3}[!@#$%^&*]{1,2}$/i;
const ALLOWED_CHARACTERS = /^[A-Za-z0-9!@#$%^&*]+$/;
const UPPERCASE = /[A-Z]/;
const LOWERCASE = /[a-z]/;
const NUMBER = /[0-9]/;
const SPECIAL = /[!@#$%^&*]/;

function isPasswordValid(password) {
  if (typeof password !== "string") return false;
  if (password.length < MIN_PASSWORD_CHARACTERS || password.length > MAX_PASSWORD_CHARACTERS) return false;
  if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) return false;
  if (!ALLOWED_CHARACTERS.test(password)) return false;
  if (!UPPERCASE.test(password) || !LOWERCASE.test(password) || !NUMBER.test(password) || !SPECIAL.test(password)) return false;

  // Lowercase only for common-password comparison; never trim or normalize
  // the accepted ASCII value that gets hashed.
  const comparable = password.toLowerCase();
  if (BLOCKED_PASSWORDS.has(comparable) || BLOCKED_PASSWORD_FAMILIES.test(password)) return false;
  return true;
}

function generateInitialPassword() {
  const groups = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    ALLOWED_SPECIAL_CHARACTERS,
  ];
  const alphabet = groups.join("");
  const characters = groups.map(group => group[crypto.randomInt(group.length)]);
  while (characters.length < MAX_PASSWORD_CHARACTERS) {
    characters.push(alphabet[crypto.randomInt(alphabet.length)]);
  }
  for (let index = characters.length - 1; index > 0; index--) {
    const swap = crypto.randomInt(index + 1);
    [characters[index], characters[swap]] = [characters[swap], characters[index]];
  }
  const password = characters.join("");
  if (!isPasswordValid(password)) return generateInitialPassword();
  return password;
}

module.exports = {
  MIN_PASSWORD_CHARACTERS,
  MAX_PASSWORD_CHARACTERS,
  MAX_PASSWORD_BYTES,
  ALLOWED_SPECIAL_CHARACTERS,
  INVALID_PASSWORD_MESSAGE,
  isPasswordValid,
  generateInitialPassword,
};
