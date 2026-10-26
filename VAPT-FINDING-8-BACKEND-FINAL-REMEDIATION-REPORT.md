# VAPT Finding #8: Backend Final Remediation Report

## Status

Backend source remediation and local automated verification are complete for the items described below. Staging integration and external VAPT retesting remain pending; this finding is not closed. Tests use isolated fixtures and do not connect to a production database.

## Audit scope and source of truth

Reviewed the active patient and helper recovery/reset handlers, login/logout handlers, authentication and authorization middleware, route mounts, OTP/recovery rate limits, existing backend tests, and the frontend integration report. Patient reset handling was already role-aware in the current source; the work here added regression coverage rather than rewriting that handler. No application schema migrations were present; the SQL files found are bundled MySQL utility scripts, not project migrations.

Relevant source: `routes/patients.js`, `routes/patient_helpers.js`, `routes/doctors.js`, `routes/admins.js`, `middleware/authenticate.js`, `middleware/require-csrf.js`, `utils/authorization.js`, and `app.js`.

## Reset flow verification

- `POST /patient/forgetpwd` and helper recovery issue 10-minute HS256 reset links bound to role, account ID and email. The reset signature is derived using the existing per-account secret design, which also binds it to the current password hash.
- Shared `POST /patient/forgetpwdresetpwd` validates signature and expiry, then selects the account table and key column only from the fixed role map. Patient claims select `patient_details(patient_id)`; helper claims select `helper_details(helper_id)`. Signed role, identifier and email must match the selected row. Legacy role-less links are accepted only when exactly one account table validates the signed identity.
- Invalid, malformed, expired, tampered, wrong-role, wrong-ID and ambiguous tokens receive the same generic invalid-link response and do not change either password hash. Lookup/update failures return a generic server error.
- Password updates use bcrypt cost 11 and parameterized values. A changed password hash invalidates the previous token, so successful token reuse is rejected. Reset tokens and passwords are not logged or returned in public JSON; the reset token is intentionally delivered in the controlled recovery email link.
- Recovery responses remain account-neutral. Existing email delivery behavior is preserved.

Regression tests cover valid patient/helper reset, table isolation, patient-token/helper-account and helper-token/patient-account mismatches, wrong IDs, malformed/expired/tampered tokens, no password mutation on rejection, hashed password storage, generic responses, and reuse rejection.

## Patient password-login response token

The patient password login handler previously returned a JWT in JSON while also setting the established HttpOnly `auth_token` cookie and readable double-submit CSRF cookie. Repository search found no active frontend consumer for the password-login JSON token; the patient login component uses response metadata only, and the service's password-login result type does not consume a token. The response now returns only user metadata and expiry. Cookie issuance, role claim, CSRF behavior, expiry and logout/revocation are retained. The integration test now authenticates using the cookie, verifies cookie attributes, performs CSRF-protected logout, and confirms revocation.

The separate patient OTP-login endpoint still returns its established JSON token response, and `PatientAuthService.verifyOtp` is typed for that contract although no active component caller was found. It was intentionally not changed without a coordinated OTP client/API compatibility decision. This endpoint and the broader OTP finding require separate review; do not interpret the password-login change as eliminating all JSON-issued JWT responses.

## Role isolation and account flows

- Patient self-registration writes a patient record with the existing self-registration helper marker; helper registration writes a helper record. Tests assert a patient signup creates only the patient fixture.
- Login handlers set server-side role claims from the selected account route, not a submitted client role. Role middleware and account-scoped handlers remain responsible for access checks.
- Logout uses the authenticated cookie, role-specific route behavior, CSRF validation for cookie-authenticated state-changing requests, and token revocation. Tests verify logout clears auth/CSRF cookies and that a logged-out credential is rejected.
- Existing authorization tests cover role and identity boundaries. The real MySQL ownership-query test remains opt-in and was skipped in the default run.

The frontend role/session state is only a navigation/display aid. Backend authorization remains the security boundary for every protected resource.

## Recovery and OTP attempt limits

Recovery routes already had a per-IP limit of five requests per 15 minutes with generic throttling feedback. OTP send routes had a separate five-per-15-minute limiter, but OTP verification routes had no corresponding attempt limiter. Added an independent verification limiter with the same configured window and maximum, mounted before patient login/contact verification and helper contact verification handlers. Send limits remain separate. The focused tests exercise all three recovery routes and all five OTP-send plus five OTP-verification routes, including the sixth request and route-appropriate generic response.

This is a backend brute-force control, but it is not a complete OTP security assessment. Per-IP limits can be affected by proxy/IP configuration and should be observed in staging. OTP lifecycle/replay controls and the separately tracked OTP Bypass finding remain distinct dependencies.

## Changes made

- `app.js` — added the dedicated OTP verification limiter and mounted it before all relevant verification routes.
- `routes/patients.js` — removed the JSON JWT from password-login success; retained established cookies and metadata response.
- `tests/user-enumeration.test.cjs` — expanded reset isolation/negative/reuse/hash tests; verifies login cookie contract, absence of password-login JSON token, logout CSRF behavior and revocation; verifies patient signup role/table isolation.
- `tests/authorization.test.cjs` — updated the opt-in integration path to consume the patient auth cookie and exercise cookie logout/revocation.
- `tests/rate-limits.test.cjs` — added route-mount and behavior coverage for recovery and OTP send/verification throttles.
- `VAPT-FINDING-8-BACKEND-FINAL-REMEDIATION-REPORT.md` — updated this audit, implementation and verification record.

No database schema changes or production database access were made.

## Verification results

- Focused reset and rate-limit tests: `node --test tests/user-enumeration.test.cjs tests/rate-limits.test.cjs` — **4 passed, 0 failed, 0 skipped**.
- Related authorization and OTP tests: `node --test tests/authorization.test.cjs tests/patient-otp.test.cjs tests/otp-bypass.test.cjs` — **7 passed, 0 failed, 1 skipped**. The skipped case is the opt-in MySQL integration fixture.
- Full backend suite after all changes: `npm.cmd test` — **19 passed, 0 failed, 1 skipped** (20 tests). Skipped: real routes/parameterized MySQL ownership queries, which require `TEST_MYSQL=1` and a configured test database.
- Syntax checks: `node --check app.js`, `node --check routes\patients.js`, `node --check tests\user-enumeration.test.cjs`, `node --check tests\authorization.test.cjs`, and `node --check tests\rate-limits.test.cjs` — all exited successfully.
- No production build was run; this Node service has no relevant frontend build step in this task.

## Remaining gaps and dependencies

1. The patient OTP-login JSON-token contract remains for compatibility and needs an explicit API/client decision. Search external/mobile consumers before changing it; if retained, confirm its intended secure handling and expiry in staging.
2. Run the skipped authorization/MySQL integration test against an isolated test database and confirm schema/ownership behavior; do not use production data.
3. Verify `trust proxy` and client-IP derivation at the deployed ingress so per-IP recovery/OTP limits cannot be bypassed or cause excessive shared-IP throttling.
4. Confirm recovery response parity and generic errors at the deployed backend, including status, JSON, cookies and coarse timing for known/unknown identities.
5. Confirm duplicate signup remains an observable success/failure distinction. Generic text does not eliminate enumeration where HTTP outcomes differ.
6. CAPTCHA was not found in the reviewed backend/frontend flows. No CAPTCHA claim is made.
7. Existing frontend integration report has a patient signup address/PIN format dependency. Confirm that API contract with product/backend owners.

## Staging integration and VAPT retest checklist

Use only controlled, owned staging accounts. Capture environment/build, timestamps, HTTP status/body, `Set-Cookie`, email delivery and account state.

1. Compare patient/helper/doctor/admin unknown-user, wrong-password and unapproved-doctor login outcomes for body, status, cookies and coarse timing.
2. Compare known and unknown patient/helper/doctor recovery requests; verify account-neutral response and email-only token delivery.
3. Complete patient and helper reset journeys; confirm each changes only its intended account, passwords authenticate after reset, and old reset links fail.
4. Exercise malformed, expired, altered, wrong-role, wrong-ID, colliding numeric IDs and reused reset links; confirm generic rejection and unchanged account hashes.
5. Test patient password login, OTP login, CSRF-protected state changes, logout cookie clearing and revoked-token rejection with the deployed frontend/backend pairing.
6. Exercise recovery and OTP send/verify throttles from representative network paths, including ingress proxy configuration, and verify legitimate use is not disrupted.
7. Test duplicate signup and the intended patient-branded signup/login routes; compare actual outcomes and confirm account roles match product intent.
8. Run the external VAPT response-replacement and enumeration PoCs against staging. Record results; do not infer closure from local unit tests.

## Security boundary and closure

The server validates signed reset claims, binds account role/identity, hashes replacement passwords, applies request limits, and enforces authentication/authorization. Angular checks and route guards are not authorization controls. Local tests establish behavior only for the covered fixtures; staging deployment behavior, external consumers, the OTP token contract and external VAPT retesting remain pending. Finding #8 is **not closed**.
