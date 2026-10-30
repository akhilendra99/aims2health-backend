const crypto = require("crypto");
require("dotenv").config();

const MAX_FAILURES = readPositiveInteger("LOGIN_LOCKOUT_MAX_FAILURES", 5);
const FAILURE_WINDOW_SECONDS = readPositiveInteger("LOGIN_LOCKOUT_WINDOW_SECONDS", 15 * 60);
const LOCK_DURATION_SECONDS = readPositiveInteger("LOGIN_LOCKOUT_DURATION_SECONDS", 15 * 60);
const STATE_RETENTION_SECONDS = FAILURE_WINDOW_SECONDS + LOCK_DURATION_SECONDS;

function readPositiveInteger(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function hmacKey() {
  // Prefer a dedicated stable secret. Deriving a separated key from the
  // patient signing secret keeps existing deployments functional while
  // preserving consistency across instances that share JWT verification keys.
  const secret = process.env.LOGIN_LOCKOUT_SECRET || process.env.JWT_SECRET_PATIENT;
  if (typeof secret !== "string" || secret.length < 32) {
    throw new Error("Login lockout requires a stable secret of at least 32 characters");
  }
  return crypto.createHmac("sha256", secret)
    .update("aims2health:login-lockout:hmac-key:v1")
    .digest();
}

function digest(value) {
  return crypto.createHmac("sha256", hmacKey()).update(value).digest("hex");
}

function normalizedIdentifier(value, type) {
  if (typeof value !== "string") return null;
  const normalized = type === "phone"
    ? value.replace(/\D/g, "")
    : value.trim().toLowerCase();
  return normalized ? `${type}:${normalized}` : null;
}

function createLoginLockKeys({ identifier, identifierType = "email", role, accountId }) {
  const keys = [];
  const normalized = normalizedIdentifier(identifier, identifierType);
  // Identifier hashes are shared across role endpoints to prevent moving the
  // same submitted username to another login URL to avoid its failure count.
  if (normalized) keys.push(digest(`identifier:${normalized}`));
  // Resolved identity keys also bind helper email and phone aliases to one
  // account, while remaining derived from server-returned database identity.
  if (role && (typeof accountId === "string" || Number.isSafeInteger(accountId))) {
    keys.push(digest(`account:${role}:${accountId}`));
  }
  return [...new Set(keys)];
}

function rowsFromResult(result) {
  if (Array.isArray(result) && result.length === 2 && Array.isArray(result[0])) return result[0];
  return result;
}

function queryRows(connection, sql, values = []) {
  if (connection.query.length >= 3) {
    return new Promise((resolve, reject) => {
      connection.query(sql, values, (error, rows) => error ? reject(error) : resolve(rows));
    });
  }
  return Promise.resolve(connection.query(sql, values)).then(rowsFromResult);
}

async function isLoginLocked(connection, keys) {
  if (!keys.length) return false;
  const placeholders = keys.map(() => "?").join(",");
  const rows = await queryRows(
    connection,
    `SELECT lock_key FROM login_lockout_state
      WHERE lock_key IN (${placeholders}) AND locked_until > UTC_TIMESTAMP(3) LIMIT 1`,
    keys,
  );
  return rows.length > 0;
}

const RECORD_FAILURE_SQL = `INSERT INTO login_lockout_state
  (lock_key, window_started_at, failed_attempts, locked_until, expires_at)
  VALUES (?, UTC_TIMESTAMP(3), 1, NULL,
    DATE_ADD(UTC_TIMESTAMP(3), INTERVAL ? SECOND))
  ON DUPLICATE KEY UPDATE
    locked_until = CASE
      WHEN locked_until > UTC_TIMESTAMP(3) THEN locked_until
      WHEN window_started_at <= DATE_SUB(UTC_TIMESTAMP(3), INTERVAL ? SECOND) THEN NULL
      WHEN failed_attempts + 1 >= ? THEN DATE_ADD(UTC_TIMESTAMP(3), INTERVAL ? SECOND)
      ELSE NULL
    END,
    failed_attempts = CASE
      WHEN locked_until > UTC_TIMESTAMP(3) THEN failed_attempts
      WHEN window_started_at <= DATE_SUB(UTC_TIMESTAMP(3), INTERVAL ? SECOND) THEN 1
      ELSE failed_attempts + 1
    END,
    window_started_at = CASE
      WHEN window_started_at <= DATE_SUB(UTC_TIMESTAMP(3), INTERVAL ? SECOND) THEN UTC_TIMESTAMP(3)
      ELSE window_started_at
    END,
    expires_at = CASE
      WHEN locked_until > UTC_TIMESTAMP(3) THEN expires_at
      ELSE DATE_ADD(UTC_TIMESTAMP(3), INTERVAL ? SECOND)
    END`;

async function recordLoginFailure(connection, keys) {
  for (const key of keys) {
    await queryRows(connection, RECORD_FAILURE_SQL, [
      key,
      STATE_RETENTION_SECONDS,
      FAILURE_WINDOW_SECONDS,
      MAX_FAILURES,
      LOCK_DURATION_SECONDS,
      FAILURE_WINDOW_SECONDS,
      FAILURE_WINDOW_SECONDS,
      STATE_RETENTION_SECONDS,
    ]);
  }
  // Opportunistically prune expired identifiers. The indexed expiry column
  // bounds work and prevents the table growing indefinitely from random names.
  await queryRows(connection,
    "DELETE FROM login_lockout_state WHERE expires_at <= UTC_TIMESTAMP(3) ORDER BY expires_at LIMIT 500");
}

async function clearLoginFailures(connection, keys) {
  if (!keys.length) return;
  const placeholders = keys.map(() => "?").join(",");
  await queryRows(connection,
    `DELETE FROM login_lockout_state WHERE lock_key IN (${placeholders})`, keys);
}

function lockoutConfig() {
  return {
    maxFailures: MAX_FAILURES,
    failureWindowSeconds: FAILURE_WINDOW_SECONDS,
    lockDurationSeconds: LOCK_DURATION_SECONDS,
  };
}

module.exports = {
  createLoginLockKeys,
  isLoginLocked,
  recordLoginFailure,
  clearLoginFailures,
  lockoutConfig,
};
