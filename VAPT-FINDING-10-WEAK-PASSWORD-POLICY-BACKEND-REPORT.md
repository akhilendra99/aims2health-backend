# VAPT Finding #10: Weak Password Policy (Backend)

## Audit and endpoint inventory

The backend uses Express with direct route handlers, `bcryptjs`, and MySQL `hashed_pwd` columns. No password-policy package or migration/schema files were present. The isolated MySQL authorization fixture defines `hashed_pwd` for patient, helper, doctor, and admin records, but no password-history table/columns. No password creation or change route was found in `routes/admin.js`; it only authenticates admins. The legacy `/helper/changepassword` path does not exist; the active helper endpoint is `/helper/change-password`.

| Endpoint / path | Role | Before remediation | Enforcement / hashing after remediation |
|---|---|---|---|
| `POST /api/helper/register` | Helper create | Required string and 72-byte cap, no strength/common-password check | Shared policy before OTP consumption/database write; bcrypt cost 12 |
| `POST /api/patient/signup` | Patient create | 8â€“16 ASCII characters, digit and listed symbol; did not require uppercase/lowercase | Shared policy; bcrypt cost 11 |
| `POST /api/doctor/signup` | Doctor create | Same partial 8â€“16 rule; handler logged the entire request body, including password | Shared policy; removed request-body log; bcrypt cost 11 |
| `POST /api/helper/add-patient` | Helper creates patient | Password optional; absent value used a shared hardcoded password; bcrypt cost 10 | Supplied passwords use shared policy; omitted password receives a unique cryptographically generated policy-compliant value that is never returned or logged; bcrypt cost 10 |
| `POST /api/patient/add-patients` | Patient creates family account | Partial 8â€“16 rule | Shared policy; bcrypt cost 11 |
| `PUT /api/patient/chpwd` | Authenticated patient change | Partial 8â€“16 rule; current password was checked against caller identity | Shared policy; validates current-password input shape/72-byte cap, retains current-password check and caller identity; bcrypt cost 11 |
| `PUT /api/doctor/chpwd` | Authenticated doctor change | Partial 8â€“16 rule; current password checked against caller identity | Shared policy; validates current-password input shape/72-byte cap, retains current-password check and caller identity; bcrypt cost 11 |
| `POST /api/helper/change-password` | Authenticated helper change | Partial 8â€“16 rule; current password checked against signed-in helper | Shared policy; current-password check and signed-in helper identity retained; bcrypt cost 10 |
| `POST /api/patient/forgetpwdresetpwd` | Patient or helper reset | Reset tokens were already validated by the shared role-aware reset fix; no password policy | Shared policy before lookup/update; existing token role, identity, expiry and single-use behavior retained; bcrypt cost 11 |
| `POST /api/doctor/forgetpwdresetpwd` | Doctor reset | No password-strength validation | Shared policy before lookup/update; existing token verification retained; bcrypt cost 11 |
| `create_pwd.js` | Admin bootstrap hash utility | Embedded and printed a plaintext password | Requires `INITIAL_ADMIN_PASSWORD`, validates it with the shared policy, and prints only the bcrypt hash |

Login routes do not create passwords and remain unchanged. Searches of route writes to `hashed_pwd` found the flows above; inactive commented code and test fixtures are not active writers. No admin account provisioning workflow is implemented in this backend repository.

## Enforced backend policy

- 8â€“12 ASCII characters, inclusive.
- At least one ASCII uppercase letter, lowercase letter, and digit.
- At least one special character from the existing accepted allowlist `!@#$%^&*`.
- No whitespace or other characters outside ASCII letters/digits and that existing symbol allowlist. Inputs are not trimmed or normalized; accepted values are hashed exactly as received.
- Maximum 72 UTF-8 bytes, matching bcrypt's input limit. The stricter 12-ASCII-character limit remains the policy boundary; the explicit byte guard is retained.
- A local, source-controlled common-password list and family-pattern block prevent selected predictable values. Passwords are never submitted to an external checking service.
- Invalid values receive a consistent HTTP 400 message. Passwords are stored with existing bcryptjs cost factors; plaintext passwords are not logged.

The current Angular shared validator and the backend's former signup/change regex both used ASCII-only character classes; the task and current frontend report also specify 8â€“12 characters and all four categories. This remediation aligns backend acceptance with the current Angular ASCII rule and preserves `!@#$%^&*`. The original VAPT PDF available at `D:\all_docs\LATESTVPATAIMS2HEALTH_unlocked.pdf` is a scanned, encrypted image document and could not be text-extracted in this environment, so ASCII-only acceptance cannot be independently attributed to the original report. Treat the approved source document's exact Unicode requirement as pending owner verification; do not infer that the scanned PDF approved ASCII solely from implementation convention. Requests with 13â€“16 characters that previously passed receive HTTP 400 by design.

## Password history and session behavior

Password history is **not implemented**. The repository schema fixtures contain only the current `hashed_pwd`; no history storage, agreed history depth, or migrations/rollback framework was found. No schema migration was added. If product policy requires reuse prevention, agree the history depth and add a table storing only salted bcrypt hashes with a migration and rollback before implementing it.

Successful password changes continue to follow the existing session convention: they do not revoke already-issued access JWTs. Logout revocation remains separate. Active tokens continue until their expiry or logout; password-change session revocation is a remaining security/product decision and was not added here to avoid changing the separate session-management behavior.

The helper dashboard currently omits a password when creating a patient. To remove its shared known default without breaking that request contract, the backend generates and hashes a unique random initial password without returning/logging it. A patient who needs direct password login must use the existing recovery flow if an email address is available. The product should confirm this onboarding behavior and provide an account activation/reset path for accounts without email.

## Files changed

- `utils/password-policy.js`: shared policy, local blocklist, stable validation message, and secure random initial-password generator.
- `routes/patient_helpers.js`: policy enforcement for helper registration, helper password changes, and helper-created patient records; removed the shared default credential.
- `routes/patients.js`: policy enforcement for patient signup, family-account creation, patient password change, and patient/helper reset.
- `routes/doctors.js`: policy enforcement for doctor signup, password change and reset; removed logging of the signup request body.
- `create_pwd.js`: removes the embedded/logged plaintext admin password and applies the shared policy to bootstrap hash generation.
- `tests/password-policy.test.cjs`: policy, category, length, blocklist, Unicode handling, and generated credential tests.
- `tests/user-enumeration.test.cjs`: weak registration/change rejection, current-password checks, valid patient/doctor/helper change and reset flows, and bcrypt storage assertions.
- `tests/otp-bypass.test.cjs`: updates its isolated helper-registration fixture password to the accepted policy and asserts bcrypt storage.
- `VAPT-FINDING-10-WEAK-PASSWORD-POLICY-BACKEND-REPORT.md`: audit and verification record.

## Tests executed

- Focused: `node --test tests/password-policy.test.cjs tests/user-enumeration.test.cjs tests/otp-bypass.test.cjs` â€” **7 passed, 0 failed, 0 skipped**.
- Full backend: `npm.cmd test` â€” **26 passed, 0 failed, 1 skipped** (27 total). The skipped test is the opt-in real-MySQL authorization integration test; no production database was used.
- Syntax checks: `node --check` passed for `utils/password-policy.js`, `routes/patients.js`, `routes/patient_helpers.js`, `routes/doctors.js`, `create_pwd.js`, `tests/password-policy.test.cjs`, `tests/user-enumeration.test.cjs`, and `tests/otp-bypass.test.cjs`.

Tests cover accepted 8- and 12-character boundaries, rejected short/long/missing/wrong-type/category-missing/common inputs, Unicode preservation/rejection behavior, generated credential validity, weak values rejected before database work, authenticated current-password checks, successful helper/patient/doctor registration or password changes/resets where available, and bcrypt hash storage. Helper OTP registration tests use an isolated in-memory database adapter. The real-MySQL authorization integration remains skipped.

## Staging verification required

Staging was not available; the finding is not claimed closed. With isolated test accounts, verify:

1. For helper, patient, doctor, and helper-created patient flows, submit valid 8-character and 12-character passwords, then 7-character, 13-character, missing, non-string, category-missing, blocked, whitespace, and malformed Unicode values. Confirm accepted requests work, invalid requests return HTTP 400 before writes, and stored values are bcrypt hashes.
2. Exercise password changes using correct and incorrect current passwords and tokens for another role/user. Confirm weak values are rejected and another account cannot be changed through request IDs or role fields.
3. Request patient/helper/doctor reset links; verify policy-compliant resets work and weak passwords do not update hashes. Confirm invalid, expired, wrong-account, and reused tokens remain rejected generically.
4. Confirm helper-created patient accounts no longer share a known default password and that the product-approved password activation/reset path works, especially for accounts without an email address.
5. Submit 13â€“16 character legacy passwords through current Angular forms and confirm expected backend 400 behavior; deploy coordinated UI wording/validation before relying on client feedback.
6. Confirm password values do not appear in application logs or bootstrap utility output. Validate session expectations after password change and document whether active JWTs should be revoked in a separate session-management change.

Record status, response body, password-hash/database results, and logs in staging. Do not use production accounts or data. Automated tests do not establish VAPT closure.

## Final cross-layer alignment

`src/app/shared/password-policy.ts` now uses ASCII length, categories, and allowlist checks matching `utils/password-policy.js`; legacy password fixtures using accented characters were changed to valid ASCII examples. The shared Angular tests verify all eight allowlisted symbols and reject non-ASCII letters/numerals, whitespace, and emoji. The original PDF remains non-extractable in this environment, so owner confirmation of ASCII-only scope is still a prerequisite to policy approval. Password history and password-change session revocation remain unimplemented separate decisions as described above. The legacy `/helper/signup` API and no-email patient activation gaps remain unresolved, with evidence recorded in the frontend report.