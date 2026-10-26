# VAPT Finding #7: CSP bypass (backend)

## Audit and root cause

The backend already uses Helmet 7.2.0. It is registered near the start of `app.js`, before CORS, body parsing, file delivery, and all API routes, so the Node/Express response layer already emitted an enforced `Content-Security-Policy` header.

The existing policy was weaker than the requested configuration: `style-src` allowed `'unsafe-inline'`, `img-src` accepted the broad `https:` scheme, and directives such as `font-src`, `object-src`, `base-uri`, `frame-ancestors`, and `form-action` depended on Helmet defaults instead of an explicit application policy. Repository search found no second CSP declaration or Nginx/Apache/CDN configuration. Deployment files run this backend behind Nginx but do not contain its configuration, so a proxy/CDN header cannot be ruled out from this checkout.

The finding names `https://aims2health.co.in/`, while this repository configures a distinct Express backend and lists frontend/backend hosts in its CORS allowlist. The backend deployment files do not deploy the Angular frontend. A CSP emitted by this API cannot establish which CSP is returned by the homepage host.

## Implemented policy

Helmet remains the only CSP middleware, now configured by `middleware/security-headers.js` and mounted once in `app.js` before routes. Defaults are disabled so the emitted policy is explicit. The enforced policy is:

```text
default-src 'self'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; frame-src 'none'; form-action 'self'
```

All resource directives use same-origin only, except `img-src` also permits `data:` to retain support for embedded image data. `object-src 'none'` disables plugin content; `base-uri 'self'` prevents injected base URL changes; both frame directives deny framing; and `form-action 'self'` restricts form submissions. Inline script/style attributes, wildcard sources, `unsafe-inline`, and `unsafe-eval` are not allowed. No external origins were added: the CORS allowlist identifies browser/API origins, but that alone is not evidence that HTML served by the backend needs to load those origins. This policy does not change CORS, CSRF, authentication, cookies, or route behavior.

## Files modified

- `app.js`: mounts the extracted security-header middleware once before routes.
- `middleware/security-headers.js`: centralizes the explicit CSP and preserves existing Helmet HSTS, frameguard, no-sniff, powered-by, and same-site resource policy settings.
- `tests/csp-headers.test.cjs`: verifies CSP on an HTML response, important directives, absence of weak sources, single policy semantics, and existing frame/no-sniff headers.
- `VAPT-CSP-BYPASS-BACKEND-REPORT.md`: records the audit, policy, tests, and outstanding deployment checks.

## Automated verification

- `node --test tests/csp-headers.test.cjs` — **1 passed, 0 failed, 0 skipped**.
- `npm.cmd test` — **15 passed, 0 failed, 1 skipped** (16 total). The skipped test is the opt-in MySQL authorization integration test; it was not run against a database.
- Syntax checks: `node --check app.js`, `node --check middleware/security-headers.js`, and `node --check tests/csp-headers.test.cjs` — all passed.

The focused test instantiates the exact exported middleware used by `app.js` and verifies one CSP policy value on an HTML response. It does not contact the deployed app or inspect Nginx/CDN headers.

## Deployment dependencies and manual verification

The Nginx configuration, CDN configuration, and homepage hosting configuration are absent from this repository. Confirm that those layers do not append, replace, or duplicate CSP headers. Since the finding targets the frontend homepage, the production frontend host must also be inspected and configured at its actual serving layer if its document response lacks an appropriate enforced policy. The API CSP does not by itself remediate a missing CSP on a separately hosted Angular document. Staging compatibility must also be checked, especially if backend HTML or documentation is later added; the current backend serves API responses, a text health response, and protected files.

Manual header checks (run against staging, then production after deployment):

```sh
curl -sS -D - -o /dev/null https://aims2health.co.in/ | grep -i '^content-security-policy:'
curl -sS -D - -o /dev/null https://backend.aims2.health/health | grep -i '^content-security-policy:'
```

The backend hostname above appears in the repository CORS allowlist; verify that it is the deployed API host before using it. Check for duplicate policy lines:

```sh
curl -sS -D - -o /dev/null https://backend.aims2.health/health | awk 'tolower($1) == "content-security-policy:" { n++ } END { print "CSP header count:", n; exit n != 1 }'
```

Inspect the returned value for all directives above and ensure no intermediary adds a second or contradictory policy. Repeat against the exact staging and production homepage and API hosts. Browser-test expected frontend behavior, API calls, and image/PDF delivery. Automated checks and repository inspection do not establish that the public staging headers or application compatibility have been verified; do not mark the VAPT finding closed until those checks pass.
