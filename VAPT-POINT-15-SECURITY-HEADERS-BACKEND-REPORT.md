# VAPT Point #15: Multiple Security Headers Missing — Backend Report

## Root cause and audit

The Express backend already registers Helmet through `middleware/security-headers.js` near the beginning of `app.js`, before CORS, parsers, file delivery, and API routers. Helmet 7.2.0 already supplied `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and the repository's CSP includes `frame-ancestors 'none'`. The concrete gaps/unsafe configuration were:

- No central Cache-Control policy existed. Protected file responses only set `private, no-store`, which did not match the required directive set.
- Helmet HSTS was configured with `includeSubDomains: true` and `preload: true` without repository evidence that all subdomains support HTTPS or preload prerequisites had been met.
- Helmet emitted HSTS even when the direct request was plain HTTP. This was confirmed by the focused test before changing the middleware.

The report's affected URL `/dlogin` is not served as an HTML page by this backend checkout. `app.js` mounts API routers and protected files; `appspec.yml` deploys this backend, and no Angular static hosting configuration is present. Backend headers therefore do not establish the headers on the frontend's `/dlogin` document response.

## Existing deployment/header configuration inspected

Inspected `app.js`, `middleware/security-headers.js`, `middleware/protected-files.js`, the current CSP report/test, `package.json`, `server.js`, `Procfile`, `appspec.yml`, `buildspec.yml`, and `deploy_scripts/`. No Nginx, Apache, CDN, or TLS-termination configuration is checked into this repository, so external header duplication/replacement and live TLS behavior cannot be verified here.

`app.js` sets `trust proxy` to `1`; its comment states Nginx is directly in front of the backend. The security middleware now uses Express `req.secure` for HSTS, which relies on that existing proxy trust when TLS terminates upstream. Production safety depends on the backend being reachable only through the trusted proxy and that proxy overwriting/sanitizing forwarded protocol headers. The actual proxy configuration and network exposure remain unverified.

## Implemented policy

- `Cache-Control: no-store, no-cache, must-revalidate` is set centrally on all backend responses, including API success, authentication/validation errors, server errors, health, and protected files. This backend has no public fingerprinted-asset serving path; `/images` is authorization-controlled file delivery.
- `X-Content-Type-Options: nosniff` remains provided by Helmet.
- `X-Frame-Options: DENY` remains provided by Helmet. The existing CSP's `frame-ancestors 'none'` is consistent; no separate framing policy was added.
- `Strict-Transport-Security: max-age=31536000` is set only when Express reports `req.secure`. `includeSubDomains` and `preload` are disabled. No preload recommendation is made.
- CORS, authentication, authorization, OTP, session, and response payload logic were not changed.

## Files changed

- `middleware/security-headers.js`: wraps the existing Helmet middleware with the central no-store cache policy; disables Helmet's unconditional HSTS and adds one-year, host-only HSTS only for Express-secure requests.
- `middleware/protected-files.js`: aligns the protected file response Cache-Control value with the backend policy.
- `tests/security-headers.test.cjs`: verifies headers and single occurrences on login, private API, validation-error and server-error responses; checks HTTP/HTTPS HSTS behavior and untrusted forwarded-protocol handling.
- `tests/authorization.test.cjs`: updates the opt-in protected-file assertion to the required Cache-Control value.
- `VAPT-POINT-15-SECURITY-HEADERS-BACKEND-REPORT.md`: this audit and verification record.

## Verification

- Focused: `node --test tests/security-headers.test.cjs tests/csp-headers.test.cjs` — **3 passed, 0 failed, 0 skipped**. These tests use isolated local Express servers and the production middleware; they do not exercise production TLS or proxy configuration.
- Full backend: `npm.cmd test` — **32 passed, 0 failed, 1 skipped** (33 total). The skipped test is the opt-in real-MySQL authorization fixture; no production database was used.
- Syntax checks passed: `node --check middleware/security-headers.js`, `node --check middleware/protected-files.js`, `node --check tests/security-headers.test.cjs`, and `node --check app.js`.
- `npm run build` was not run: this repository's `build` script starts `server.js`, which loads application configuration and attempts database connections; it is not a compile-only build. The backend code changes were syntax-checked and tested through local HTTP fixtures.

## Staging verification and remaining risks

1. Verify the exact production ingress: Nginx/TLS termination, backend network exposure, forwarded-protocol overwrite behavior, and that the configured single trusted proxy hop matches reality.
2. Apply/deploy the middleware, then inspect the real HTTPS API response for one each of Cache-Control, nosniff, DENY, CSP, and `Strict-Transport-Security: max-age=31536000`; check HTTP responses omit HSTS. Include 200, 400, 401, 404, and 500 responses.
3. Inspect Nginx/CDN headers for duplicate or contradictory Cache-Control, HSTS, X-Frame-Options, X-Content-Type-Options, or CSP values.
4. Inspect `https://aims2health.co.in/dlogin` at the actual frontend hosting layer. This backend repository does not serve that Angular document; configure its Cache-Control and other required headers at the frontend host/reverse proxy if absent.
5. Confirm authorized image/PDF delivery still works and returns no-store headers; confirm public fingerprinted assets, if served by another host, retain their intended cache policy.
6. Do not enable `includeSubDomains` or preload until ownership confirms all affected subdomains and their HTTPS readiness. Complete external VAPT retesting before claiming closure.

Local tests do not verify the public frontend, production TLS termination, or proxy/CDN behavior. The finding is not claimed closed.