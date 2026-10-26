const bcrypt = require("bcryptjs");

// These fixed dummy hashes are used only to perform comparable work when an
// account is absent (or a doctor account is not yet approved). Their values
// are not credentials and they are never used to create or update accounts.
const DUMMY_HASHES = Object.freeze({
  11: "$2a$11$byl/pE1km9pRTOIhTA8ileMgqlkVS3TPYliKnjyj/pI25IsjTsFrq",
  12: "$2a$12$cuxboNji6lAD19stXyNTf.bkEI6MyhYMLNhvKfmwMpY0WvF7qpEEm",
});

function comparePasswordOrDummy(password, passwordHash, cost = 11) {
  const candidate = typeof password === "string" ? password : "";
  const hash = typeof passwordHash === "string" && passwordHash
    ? passwordHash
    : DUMMY_HASHES[cost] || DUMMY_HASHES[11];
  return bcrypt.compare(candidate, hash);
}

module.exports = { comparePasswordOrDummy };
