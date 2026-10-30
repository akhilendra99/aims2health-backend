# VAPT Finding #11: Absence of Lockout Policy (Backend)

## Status and approved policy

The supplied VAPT report says repeated failed logins are unrestricted and recommends attempt limiting, account lockout, and CAPTCHA. It does not specify numeric thresholds or reset semantics. The following configurable defaults were proposed and explicitly approved by the user in this conversation; they are not attributed to the original report:

- Five failed password verifications within a fixed 15-minute window.
- A temporary 15-minute lockout once the fifth failure is recorded.
- Successful authentication clears the identifier and server-resolved account failure state.
- Lockout expiry is automatic; attempts while locked do not extend the lock.
- Locked identifiers receive the same generic 401 response as all other credential failures. The response does not include lock duration, count, or account state.

This report records implementation and local automated tests only. Staging and external VAPT retesting remain required before closure.

## Active password-login inventory

| API route | Role / identifier | Wrong, unknown, or status failure | Account lockout behavior |
|---|---|---|---|
| `POST /api/patient/login` | Patient; email | Unknown and wrong-password responses are generic 401. | HMAC key for normalized email plus key derived from the server-resolved patient ID. |
| `POST /api/helper/login` | Helper; email or phone | Unknown and wrong-password responses are generic 401. | Normalized identifier key plus server-resolved helper ID key; email and phone attempts therefore share the account key. |
| `POST /api/doctor/login` | Doctor; email | Unknown, wrong-password, and unapproved-doctor responses are generic 401. | HMAC key for normalized email plus key derived from the server-resolved doctor ID. |
| `POST /api/admin/login` | Admin; email | Unknown and wrong-password responses are generic 401. | HMAC key for normalized email plus key derived from the server-resolved admin ID. |

Identifier keys are common across role endpoints, so repeating a submitted email through another role URL does not create a fresh bucket. Resolved identity keys unify aliases such as a helper's email and phone. Email is trimmed and lowercased; phone formatting characters are removed. Only HMAC digests and counters are stored, not raw identifiers or passwords.

Patient OTP login (`/api/patient/send-otp-login` and `/api/patient/verify-otp-login`) remains a separate method. Existing OTP rate limits are unchanged and do not substitute for password-login lockout.

## Implementation and files changed

- `utils/login-lockout.js`: configurable policy, privacy-preserving normalized identifier/account keys, lock checks, atomic failure upserts, success reset, and opportunistic cleanup of expired rows. Counter and threshold transition occur in one MySQL `INSERT ... ON DUPLICATE KEY UPDATE`, so concurrent updates do not lose increments. A valid credential is checked against lock state again before issuing a session.
- `migrations/20261027_login_lockout_state.sql`: additive InnoDB table with indexed expiry. Apply this migration to the target database before deploying the code. No production database was accessed or changed.
- `routes/patients.js`, `routes/patient_helpers.js`, `routes/doctors.js`, `routes/admin.js`: count failed password verification for unknown accounts, wrong passwords, and unapproved doctors; reject locked identifiers generically; clear counters after success. Lockout-store errors return generic HTTP 503 and never issue a token/cookie.
- `.env.example`: documents optional stable `LOGIN_LOCKOUT_SECRET` and settings `LOGIN_LOCKOUT_MAX_FAILURES`, `LOGIN_LOCKOUT_WINDOW_SECONDS`, and `LOGIN_LOCKOUT_DURATION_SECONDS` (defaults 5, 900, 900). The HMAC key uses the dedicated secret when configured; otherwise it derives a separate purpose-specific key from `JWT_SECRET_PATIENT`. All serving instances must use the same secret material.
- `tests/login-lockout.test.cjs`: threshold, automatic expiry, success reset, concurrent counter updates, identifier normalization, alias linking, privacy, and store-error behavior.
- `tests/user-enumeration.test.cjs`: all four role routes, generic lock response, success and expiry behavior, source-IP changes, alternate-role identifier reuse, helper email/phone aliases, and HTTP 503/no-session behavior when the store fails.
- `tests/authorization.test.cjs`: keeps its authorization-only router fixture isolated from the new lockout table.
- This report.

The existing `app.js` per-IP limiter (10 requests per 15 minutes) remains in place and unchanged. It counts requests rather than failed credentials and uses `express-rate-limit`'s default in-memory store; the account-scoped MySQL counters complement it.

## Storage, deployment, and CAPTCHA

All role routers use MySQL configured through `DBHOST`/`DBNAME`; the new state table is in that database. Processes/hosts share lockout state if they connect to the same database and use the same HMAC secret. `deploy_scripts/run.sh` starts a named PM2 app without explicit cluster settings, while `app.js` describes Nginx as the directly trusted proxy. Repository files do not establish production PM2 mode, instance/host count, live proxy sanitization, or whether every instance uses one DB. Verify these with operations before rollout.

The checked-in `appspec.yml`, `buildspec.yml`, `Procfile`, and deploy scripts contain no live topology or schema management workflow. The SQL migration is manual and additive. Because the lockout store fails closed, deploying code before applying the table (or with DB/store errors) makes password login return generic HTTP 503 until the store is available.

No CAPTCHA provider or server-side CAPTCHA verifier was found in the checked backend/frontend. No CAPTCHA credentials or paid dependency were invented. Provider selection and integration remain a separate product/operations decision.

## Tests and checks

- Focused: `node --test tests/login-lockout.test.cjs tests/user-enumeration.test.cjs tests/rate-limits.test.cjs tests/patient-otp.test.cjs` — **15 passed, 0 failed, 0 skipped**. Covers password lockout flow, expiry, reset, alternate roles/IPs, helper aliases, concurrency counter semantics, generic errors, fail-closed store behavior, and unchanged OTP limiting/login flows.
- Full backend: `npm.cmd test` — **30 passed, 0 failed, 1 skipped** (31 total). The skipped test is the opt-in real-MySQL authorization integration fixture; no production data or database was used.
- `node --check` passed for `utils/login-lockout.js`, all four changed route modules, and the changed lockout/authorization/login tests.
- The concurrency regression uses an isolated fake MySQL adapter to exercise atomic upsert semantics; no real isolated MySQL database was available to verify prepared-statement SQL behavior or cross-process state directly.

## Remaining staging checks and risks

1. Review/apply `migrations/20261027_login_lockout_state.sql` to an isolated staging DB before deploying the new code. Confirm the app DB user's table permissions and MySQL version accept the prepared `INTERVAL` upsert expressions.
2. Set a stable random `LOGIN_LOCKOUT_SECRET` identically on all instances (or confirm the JWT patient secret is identically configured while using the derived fallback). Do not rotate existing production JWT secrets as part of this change.
3. Confirm production host count, PM2 mode, DB sharing, Nginx hop/header sanitization, and that clients cannot reach the app port outside the trusted proxy. The existing IP limiter relies on this proxy configuration.
4. For each role, verify four wrong passwords remain eligible, the fifth creates a temporary lock, subsequent correct and incorrect requests return the same generic 401, and login works after 15 minutes. Verify successful login before threshold clears prior failures.
5. Repeat with unknown identifiers, unapproved doctors, helper email/phone aliases, alternate role endpoints, and different source IPs. Confirm no lockout state exposes the identifier, role status, count, or expiry.
6. Exercise concurrent failed requests across all serving instances and confirm the next request is locked. Verify a database/store outage produces generic 503 and never issues authentication cookies/tokens.
7. Confirm the current OTP login and OTP rate-limit behavior remains unchanged. CAPTCHA remains unimplemented pending a provider/configuration decision.
8. Complete external VAPT retesting. Local tests do not establish closure.