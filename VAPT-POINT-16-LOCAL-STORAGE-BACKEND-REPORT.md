# VAPT Point #16: Sensitive Information Exposure via Local Storage — Backend Remediation

## Scope and conclusion

Backend changes cover the earlier token-exposure fixes and this secure session bootstrap endpoint. Admin, doctor, helper, and patient password-login JSON responses omit access JWTs and use the established HttpOnly cookie. Patient OTP login uses the same patient auth-cookie/CSRF-cookie contract and omits its JWT from JSON. Helper registration no longer creates a session; the user proceeds through normal helper login.

`GET /api/auth/session` now supports restoring in-memory Angular identity after a refresh using only the HttpOnly `auth_token` cookie. It reuses existing JWT verification, revocation, role, and database identity policies. No frontend changes were made. Point #16 is not claimed closed; frontend integration, staging checks, deployment-topology verification, and external VAPT retesting remain required.

## Authentication and authorization flow

- `middleware/authenticate.js` verifies HS256 against existing role signing domains, checks expiry and the token blacklist, validates role/identifier claims, and sets `req.userData` only from the verified token. Its new opt-in cookie-only mode ignores Authorization headers; existing APIs retain bearer-or-cookie behavior.
- `routes/auth.js` exposes `GET /session`. It uses that cookie-only verifier, checks the verified account ID/email through existing `utils/authorization.identity()`, then selects only role-specific profile fields by parameterized query. Doctor approval (`validated = 1`) is checked according to existing authorization policy. Missing/invalid/expired/revoked credentials and deleted/ineligible accounts return the same generic 401 body. Database errors fail closed with generic 503.
- Account status follows current policy: doctors must be validated. Patient, helper, and admin identity policy checks existence and matching email; no additional disabled/status rule was present in existing authorization code/schema usage, so none was invented.
- Responses set `Cache-Control: no-store, no-cache, must-revalidate`. No JWT, refresh token, password, OTP, or secret is returned. Client-supplied role, IDs, name, department, or permissions are ignored.
- `app.js` mounts this router at `/api/auth` under existing security headers, explicit credentialed CORS, cookie parsing, trusted-origin, and CSRF middleware. As a read-only GET it does not need the state-changing CSRF header. This endpoint accepts only the auth cookie, even though existing APIs retain bearer compatibility.
- Logout continues through the existing role routes and blacklist. The blacklist is process-local; production Node process/instance topology remains unknown. Multi-instance logout revocation is not guaranteed absent shared storage.

## Frontend integration contract

Endpoint: `GET /api/auth/session`, with browser credentials enabled. It returns:

```json
{
  "role": "patient | doctor | helper | admin",
  "expiresIn": 1234,
  "userId": 42,
  "userEmail": "user@example.invalid",
  "userName": "Example User"
}
```

Helper responses also include the profile shape used by the dashboard:

```json
{
  "user": {
    "helper_id": 42,
    "email_id": "helper@example.invalid",
    "mobile": "5551234567"
  }
}
```

Patient/doctor names come from the current database record; admin `userName` is its email as in admin login; helper `userName` remains empty as in the current helper login contract. Helper `userEmail` falls back to mobile if email is absent. `expiresIn` is the remaining seconds from the verified JWT `exp`. The endpoint additionally rejects a signed legacy token that has no numeric `exp`, because a session bootstrap response must have a finite lifetime. Angular should map these fields into in-memory auth state only; do not persist them in Local Storage or Session Storage. No existing client currently calls this endpoint, so frontend integration remains pending.

No database migration is required.

## Earlier Point #16 response fixes retained

- `routes/admin.js` admin login JSON contains no JWT; UI metadata remains.
- `routes/doctors.js` doctor login JSON contains no JWT; profile/expiry fields remain.
- `routes/patient_helpers.js` helper password login JSON contains no JWT; profile remains. Helper `POST /register` no longer signs or returns a JWT; response `message`, `helper_id`, and `user` remain. Active Angular registration uses `helper_id` and navigates to login. Legacy `/helper/signup` is not implemented by this backend.
- `routes/patients.js` patient password login omits JWT. Patient `POST /verify-otp-login` sets HttpOnly auth and CSRF cookies with the same options as password login and omits the JWT while preserving profile/expiry fields.

External clients were unavailable for inspection. Confirm external compatibility before deployment.

## Files changed for the bootstrap task

- `middleware/authenticate.js`: added cookie-only option while preserving the default bearer-or-cookie behavior.
- `routes/auth.js`: new role-aware, cookie-only session bootstrap with database identity/profile validation and no-store responses.
- `app.js`: mounts `routes/auth.js` at `/api/auth`.
- `tests/auth-session-bootstrap.test.cjs`: fixture-based route tests for roles, cookies, invalid credentials, identity tampering, cache/CORS headers, and database failures.
- `VAPT-POINT-16-LOCAL-STORAGE-BACKEND-REPORT.md`: updated with endpoint contract, flow, limitations, and results.

The earlier remediation files remain as recorded in previous revisions of this report. No frontend code, schema, CSRF/CORS policy, token signing domain, or revocation architecture was changed in this task.

## Verification

- Bootstrap focused command: `node --test tests/auth-session-bootstrap.test.cjs` — **3 passed, 0 failed, 0 skipped**. It uses a mocked MySQL pool and fixture account rows, not a real database.
- Existing Point #16 focused tests and the full backend suite were rerun after this endpoint change; final counts are recorded below.
- Required cases include valid patient/doctor/helper/admin cookies, missing/malformed/expired/wrong-signature/revoked credentials, bearer-only rejection, forged query identity, deleted accounts, unvalidated doctor, secret-free response, no-store, credentialed CORS, and database failure.

Automated tests do not establish behavior of the deployed browser, external API clients, production database records, or cross-instance revocation.

### Final verification results

- Bootstrap focused command: `node --test tests/auth-session-bootstrap.test.cjs` — 3 passed, 0 failed, 0 skipped. It uses a mocked MySQL pool and fixture account rows, not a real database.
- Full backend command: `npm.cmd test` — **37 passed, 0 failed, 1 skipped** (38 total). The skipped test is the real-MySQL authorization integration test, which requires `TEST_MYSQL=1` and its configured integration database. No production data was accessed.
- Syntax checks: `node --check routes/auth.js`, `node --check middleware/authenticate.js`, `node --check app.js`, and `node --check tests/auth-session-bootstrap.test.cjs` — all passed.

## Remaining deployment risks and staging verification

1. Confirm frontend owner integrates `/api/auth/session` with credentialed GET and restores only in-memory identity. Verify patient/doctor/admin fields and helper profile mapping without writing to browser storage.
2. Test all roles on staging: refresh with valid cookie, missing/expired/revoked cookie, deleted account, unvalidated doctor, and logout followed by refresh. Invalid sessions should return to unauthenticated navigation.
3. Verify cookie domain, Secure, HttpOnly, SameSite, CORS credentials, `Cache-Control`, and allowed-origin behavior through the deployed edge.
4. Confirm no external client depends on former patient OTP JSON JWT or helper registration auto-auth behavior.
5. Confirm production Node process/instance topology. If multiple instances serve traffic, test cross-instance logout revocation and plan shared revocation storage if needed.
6. Run external VAPT retesting. Passing local tests does not close Point #16.

Point #16 remains open pending frontend integration, staging verification, production topology assessment, external compatibility review, and formal retesting.
