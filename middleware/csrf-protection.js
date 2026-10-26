const crypto = require("crypto");

const CSRF_HEADER = "x-csrf-token";
const CSRF_COOKIE = "csrf_token";
const AUTH_COOKIES = ["auth_token"];
const STATE_CHANGING_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

function generateCsrfToken() {
  return crypto.randomBytes(24).toString("hex");
}

function extractOrigin(req) {
  if (req.headers.origin) return req.headers.origin;
  if (req.headers.referer) {
    try {
      return new URL(req.headers.referer).origin;
    } catch {
      return null;
    }
  }
  return null;
}

// Defense-in-depth: reject state-changing requests whose Origin/Referer
// isn't one of the app's known frontends. Only enforced when a browser
// context sends one of these headers at all — non-browser clients
// (server-to-server calls, curl) don't send Origin/Referer and are left
// to the normal auth checks.
function requireTrustedOrigin(allowedOrigins) {
  return (req, res, next) => {
    if (!STATE_CHANGING_METHODS.includes(req.method)) return next();
    const origin = extractOrigin(req);
    if (!origin) return next();
    if (!allowedOrigins.includes(origin)) {
      return res.status(403).json({ message: "Request blocked: untrusted origin." });
    }
    next();
  };
}

// Double-submit CSRF check. Only enforced when the request carries one of
// the HttpOnly auth cookies — i.e. only when the request could ride on
// ambient cookie auth. Requests authenticating via a manually-attached
// Authorization header (the pre-existing call sites) aren't exploitable
// via CSRF in the first place (a forged cross-site request can't set a
// custom header or read this app's localStorage), so they're left alone.
//
// Login endpoints are always exempt: they're the entry point that issues
// the auth_token/csrf_token cookie pair in the first place, so a request
// there can never legitimately already have a matching csrf_token — and a
// *stale* auth_token cookie left over from a previous/different session
// (e.g. logging in as a different role in the same browser) must not block
// a fresh login attempt.
function requireCsrfToken(req, res, next) {
  if (!STATE_CHANGING_METHODS.includes(req.method)) return next();
  if (req.path.toLowerCase().endsWith("login")) return next();
  const hasAuthCookie = req.cookies && AUTH_COOKIES.some((name) => req.cookies[name]);
  if (!hasAuthCookie) return next();

  const cookieToken = req.cookies[CSRF_COOKIE];
  const headerToken = req.headers[CSRF_HEADER];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ message: "Request blocked: missing or invalid CSRF token." });
  }
  next();
}

module.exports = {
  generateCsrfToken,
  requireTrustedOrigin,
  requireCsrfToken,
  CSRF_COOKIE,
};
