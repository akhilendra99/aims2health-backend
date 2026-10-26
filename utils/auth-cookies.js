// Secure by default. Set COOKIE_SECURE=false only for local http:// dev,
// where browsers won't send a Secure-flagged cookie back over plain HTTP.
const isSecure = process.env.COOKIE_SECURE !== "false";

// Unset by default (host-only cookie — required for localhost dev, where a
// server can't set a Domain outside its own hostname). In production, set
// COOKIE_DOMAIN=.aims2health.co.in so the csrf_token cookie set by
// backend.aims2health.co.in is readable via document.cookie by frontend JS
// running on aims2health.co.in — without this, the double-submit CSRF check
// silently blocks every state-changing request once logged in, since the
// frontend can never read the token it's supposed to echo back.
const cookieDomain = process.env.COOKIE_DOMAIN || undefined;

const AUTH_MAX_AGE_MS = 60 * 60 * 1000; // 1h, matches the JWT expiresIn used by patient/doctor/admin logins

// maxAgeMs override needed for patient_helpers.js, whose JWT_EXPIRES_IN
// defaults to 7d rather than the 1h used everywhere else.
function authCookieOptions(maxAgeMs = AUTH_MAX_AGE_MS) {
  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: "lax",
    maxAge: maxAgeMs,
    path: "/",
  };
}

// Not HttpOnly on purpose: the double-submit CSRF pattern requires the
// frontend to read this value and echo it back as a request header. Needs
// COOKIE_DOMAIN so it's readable cross-subdomain (frontend vs backend host).
function csrfCookieOptions(maxAgeMs = AUTH_MAX_AGE_MS) {
  const opts = {
    httpOnly: false,
    secure: isSecure,
    sameSite: "lax",
    maxAge: maxAgeMs,
    path: "/",
  };
  if (cookieDomain) opts.domain = cookieDomain;
  return opts;
}

function clearCookieOptions() {
  return { path: "/" };
}

// Must carry the same domain the csrf_token cookie was set with, or
// res.clearCookie targets a different (host-only) cookie and the real one
// never gets cleared — this was the original bug.
function csrfClearCookieOptions() {
  const opts = { path: "/" };
  if (cookieDomain) opts.domain = cookieDomain;
  return opts;
}

module.exports = {
  authCookieOptions,
  csrfCookieOptions,
  clearCookieOptions,
  csrfClearCookieOptions,
};
