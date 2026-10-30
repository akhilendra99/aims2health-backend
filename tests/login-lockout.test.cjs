const test = require("node:test");
const assert = require("node:assert/strict");

process.env.LOGIN_LOCKOUT_SECRET = "login-lockout-test-secret-value-2026-10-27";
process.env.LOGIN_LOCKOUT_MAX_FAILURES = "5";
process.env.LOGIN_LOCKOUT_WINDOW_SECONDS = "900";
process.env.LOGIN_LOCKOUT_DURATION_SECONDS = "900";
const {
  createLoginLockKeys,
  isLoginLocked,
  recordLoginFailure,
  clearLoginFailures,
  lockoutConfig,
} = require("../utils/login-lockout");

class FakeLockoutDatabase {
  constructor() {
    this.rows = new Map();
    this.now = 1_800_000_000_000;
    this.fail = false;
    this.recordSql = "";
  }

  async query(sql, values = []) {
    if (this.fail) throw new Error("simulated revocation-store outage");
    if (/^\s*SELECT lock_key FROM login_lockout_state/i.test(sql)) {
      return [values.filter(key => (this.rows.get(key)?.lockedUntil || 0) > this.now).map(lock_key => ({ lock_key })), []];
    }
    if (/^\s*INSERT INTO login_lockout_state/i.test(sql)) {
      this.recordSql = sql;
      const [key, retentionSeconds, windowSeconds, threshold, lockSeconds] = values;
      const current = this.rows.get(key);
      if (!current) {
        this.rows.set(key, {
          windowStartedAt: this.now,
          failedAttempts: 1,
          lockedUntil: 0,
          expiresAt: this.now + retentionSeconds * 1000,
        });
      } else if (current.lockedUntil <= this.now) {
        if (current.windowStartedAt <= this.now - windowSeconds * 1000) {
          current.windowStartedAt = this.now;
          current.failedAttempts = 1;
          current.lockedUntil = 0;
        } else {
          current.failedAttempts += 1;
          if (current.failedAttempts >= threshold) current.lockedUntil = this.now + lockSeconds * 1000;
        }
        current.expiresAt = this.now + retentionSeconds * 1000;
      }
      return [{ affectedRows: 1 }, []];
    }
    if (/^\s*DELETE FROM login_lockout_state WHERE lock_key IN/i.test(sql)) {
      let affectedRows = 0;
      for (const key of values) affectedRows += this.rows.delete(key) ? 1 : 0;
      return [{ affectedRows }, []];
    }
    if (/^\s*DELETE FROM login_lockout_state WHERE expires_at/i.test(sql)) {
      for (const [key, value] of this.rows) if (value.expiresAt <= this.now) this.rows.delete(key);
      return [{ affectedRows: 0 }, []];
    }
    throw new Error(`Unexpected test SQL: ${sql}`);
  }
}

test("threshold locks temporarily; successful login clears state and expiry unlocks", async () => {
  const db = new FakeLockoutDatabase();
  const keys = createLoginLockKeys({ identifier: "person@example.invalid", role: "patient", accountId: 12 });
  assert.equal(keys.length, 2);
  assert.equal(keys.some(key => key.includes("person@example.invalid")), false, "raw identifier is not stored as a key");
  assert.deepEqual(lockoutConfig(), {
    maxFailures: 5,
    failureWindowSeconds: 900,
    lockDurationSeconds: 900,
  });

  for (let attempt = 0; attempt < 4; attempt++) await recordLoginFailure(db, keys);
  assert.equal(await isLoginLocked(db, keys), false);
  await recordLoginFailure(db, keys);
  assert.equal(await isLoginLocked(db, keys), true, "the fifth failed verification locks the identifier/account");
  assert.match(db.recordSql, /ON DUPLICATE KEY UPDATE/i, "counter increment and threshold transition are one atomic SQL upsert");

  db.now += 15 * 60 * 1000 + 1;
  assert.equal(await isLoginLocked(db, keys), false, "lock automatically expires");
  await clearLoginFailures(db, keys);
  assert.equal(db.rows.size, 0, "successful login reset removes identifier and account counters");
});

test("concurrent failure updates do not lose counter increments", async () => {
  const db = new FakeLockoutDatabase();
  const keys = createLoginLockKeys({ identifier: "concurrent@example.invalid" });
  await Promise.all(Array.from({ length: 32 }, () => recordLoginFailure(db, keys)));
  assert.equal(await isLoginLocked(db, keys), true);
  assert.equal(db.rows.get(keys[0]).failedAttempts, 5, "once locked, later concurrent updates cannot reduce or bypass the threshold");
});

test("identifier normalization and helper aliases map to shared, privacy-preserving keys", () => {
  const lower = createLoginLockKeys({ identifier: " PERSON@EXAMPLE.INVALID " });
  const upper = createLoginLockKeys({ identifier: "person@example.invalid", role: "doctor", accountId: 7 });
  assert.equal(lower[0], upper[0], "same normalized identifier shares a counter across roles");
  const helperEmail = createLoginLockKeys({ identifier: "helper@example.invalid", role: "helper", accountId: 33 });
  const helperPhone = createLoginLockKeys({ identifier: "+1 (555) 010-2020", identifierType: "phone", role: "helper", accountId: 33 });
  assert.ok(helperEmail.includes(helperPhone[1]), "server-resolved helper aliases share the account counter");
  assert.notEqual(helperEmail[0], helperPhone[0], "email and phone identifiers remain type-separated");
});

test("lockout-store errors propagate so login handlers can fail closed", async () => {
  const db = new FakeLockoutDatabase();
  db.fail = true;
  const keys = createLoginLockKeys({ identifier: "failure@example.invalid" });
  await assert.rejects(isLoginLocked(db, keys), /simulated revocation-store outage/);
  await assert.rejects(recordLoginFailure(db, keys), /simulated revocation-store outage/);
  await assert.rejects(clearLoginFailures(db, keys), /simulated revocation-store outage/);
});
