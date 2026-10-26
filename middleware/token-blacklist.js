// In-process token blacklist used to invalidate JWTs on logout.
// Revocations are retained until the token's own expiry. In particular, helper
// JWTs can live longer than the 1h patient/doctor/admin tokens.
// NOTE: this is per-process state. If the app ever runs as multiple Node
// processes/instances, replace this with a shared store (e.g. Redis SET
// with TTL) so logout on one instance invalidates the token everywhere.
const blacklist = new Map();
const MAX_TIMER_MS = 0x7fffffff;

function scheduleCleanup(token, expiresAt) {
  const remaining = expiresAt - Date.now() + 1000;
  if (remaining <= 0) {
    blacklist.delete(token);
    return;
  }
  const timer = setTimeout(() => scheduleCleanup(token, expiresAt), Math.min(remaining, MAX_TIMER_MS));
  if (typeof timer.unref === 'function') timer.unref();
}

function blacklistToken(token) {
  if (!token) return;
  let exp;
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    exp = payload.exp;
  } catch {
    // Callers should pass a verified JWT. If the expiry cannot be established,
    // retain the revocation for this process lifetime rather than risk making
    // logout ineffective after an arbitrary cleanup period.
    exp = undefined;
  }

  const expiresAt = Number.isFinite(exp) ? exp * 1000 : Infinity;
  if (expiresAt <= Date.now()) return;

  blacklist.set(token, expiresAt);
  if (Number.isFinite(expiresAt)) scheduleCleanup(token, expiresAt);
}

function isBlacklisted(token) {
  const expiresAt = blacklist.get(token);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    blacklist.delete(token);
    return false;
  }
  return true;
}

module.exports = { blacklistToken, isBlacklisted };
