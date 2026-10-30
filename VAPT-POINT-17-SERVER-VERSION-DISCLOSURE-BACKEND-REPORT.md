# VAPT Point #17: Server Version Disclosure — Backend Remediation

## Finding and root cause

The reported URL, `https://aims2health.co.in/helper-login`, is a frontend page path. This backend mounts helper APIs under `/api/helper`; it does not define a `/helper-login` page route. Production headers for the reported URL were not available, so the layer that actually emitted the reported version cannot be conclusively identified from this checkout.

The Express app did not explicitly disable its `X-Powered-By` setting. However, the existing Helmet middleware (`helmet` 7.2.0) was installed before routes and already used `hidePoweredBy: true`, so the app middleware removed that header on its responses. No application source explicitly sets a `Server` header or writes a server version. Node's HTTP server setup is in `server.js`.

`app.js` documents Nginx directly in front of Node at `127.0.0.1:9000`, and deployment scripts run the service with PM2 on EC2. No Nginx/Apache/CDN/load-balancer config is present in this repository. A `Server: nginx/...` or hosting header, if observed on the reported frontend URL, would originate outside Express and needs verification/configuration by the deployment or frontend-hosting owner.

## Changes made

- `app.js`: explicitly calls `app.disable("x-powered-by")` immediately after app creation. Express no longer emits its framework header, independent of Helmet.
- `tests/security-headers.test.cjs`: adds an integration test loading the actual `app.js` pipeline with route/database dependencies stubbed. It checks the Express setting and verifies no `X-Powered-By`, no Node-generated `Server`, and no software/version-signaling response headers on success, 404, and a 500 response.
- `VAPT-POINT-17-SERVER-VERSION-DISCLOSURE-BACKEND-REPORT.md`: records source findings, exact app-level fix, test results, and infrastructure/staging requirements.

Existing Helmet security headers, CSP, CORS, cookies, CSRF, cache policy, and routing were not changed. Existing unrelated working-tree changes were preserved.

## Expected headers

| Layer / header | Before this change | After this change |
|---|---|---|
| Express `X-Powered-By` | Helmet `hidePoweredBy` already removed it on responses using the normal app pipeline; Express setting itself remained enabled | Explicitly disabled in Express and still removed by Helmet; absent on success, 404, and error responses in local app tests |
| Node `Server` header | No explicit Node/app assignment found; not emitted by the local Node HTTP server test | Still not emitted by the Node app; local response tests verify absence |
| Reverse-proxy / frontend-host `Server` header | Not verifiable from repository; Nginx is mentioned as the direct proxy, but no proxy config is checked in | Not controlled by this Express change; deployment owner must inspect and configure the layer that emits it |

If staging shows `Server: nginx/<version>`, the Nginx owner should set `server_tokens off;` in the appropriate config and reload through the normal deployment process; this hides the version but may leave the product name (`Server: nginx`). If the requirement is to remove the product name too, use an approved CDN/load-balancer header-removal feature or an already-supported Nginx module/configuration. Do not assume that `server_tokens off` removes the whole header. If the header is from a frontend hosting platform, its hosting owner must apply the platform's header policy instead.

## Tests and checks

- Focused command: `node --test tests/security-headers.test.cjs` — **3 passed, 0 failed, 0 skipped**. Includes prior security-header/HSTS coverage plus normal response, 404, and 500 checks through the app's actual middleware configuration with route dependencies stubbed.
- Full backend suite: `npm.cmd test` — **34 passed, 0 failed, 1 skipped** (35 total). The skipped case is the opt-in MySQL authorization integration test requiring `TEST_MYSQL=1`/its MySQL integration configuration. No production database or data was used.
- Syntax checks: `node --check app.js` and `node --check tests/security-headers.test.cjs` — passed.
- Repository search: no explicit `Server` header assignment or proxy header configuration was found. `app.js` documents Nginx, but its deployment configuration is external to this repository.

The app integration test stubs route/database dependencies and exercises a local HTTP server. It cannot observe headers added after the Node process by Nginx, a load balancer, CDN, or hosting platform.

## Staging verification and remaining requirements

1. Request the affected frontend URL and the deployed backend API over HTTPS, recording all response headers for normal, 404, and error responses:

   ```sh
   curl -sS -D - -o /dev/null https://aims2health.co.in/helper-login
   curl -sS -D - -o /dev/null https://backend.aims2health.co.in/api/health
   curl -sS -D - -o /dev/null https://backend.aims2health.co.in/not-a-real-route
   ```

   Confirm `X-Powered-By` is absent, identify the source of any `Server` header, and check that neither header reappears on errors.
2. Ask the proxy/frontend-host owner to inspect the actual Nginx/CDN/load-balancer configuration. If applicable, hide Nginx version disclosure and configure product-name removal only using a supported, approved mechanism.
3. Repeat checks against the public staging edge after deployment; responses observed directly from Node are not sufficient to validate edge headers.
4. Confirm required Helmet security headers, CORS, cookie/CSRF behavior, and frontend/API functionality remain intact.
5. Record response headers and have the external VAPT tester retest the affected URL.

Finding #17 remains open until the public staging response headers are verified and external VAPT retesting succeeds. This report does not claim that an external `Server` header has been changed.
