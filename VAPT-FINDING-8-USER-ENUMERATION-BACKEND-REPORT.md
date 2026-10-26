# VAPT Finding #8: User Enumeration (Backend)

**Finding tracker:** #8 (kept as requested; the original VAPT PDF numbering is unchanged)  
**Affected workflow:** Helper login and related account lookup/recovery endpoints  
**CWE:** CWE-497

## Audit findings

Audited the Express routes, account queries, password checks, API tests, auth/rate-limit middleware, and the adjacent Angular consumers of the affected APIs.

| Role / flow | Endpoints audited | Finding before this change |
|---|---|---|
| Helper | `POST /api/helper/login`, `/register`, `/forgetpwd`, `/sendPhoneVerifyOTP`, `/verifyPhoneOTP`, `/sendEmailVerifyOTP`, `/verifyEmailOTP` | Login already used the same 401 body for an unknown account and wrong password, but skipped bcrypt for unknown accounts. Recovery returned 404 and “email not registered.” OTP send returned explicit “already registered” status/messages; OTP verification distinguished missing/expired from incorrect codes. Duplicate registration had an explicit message. |
| Patient | `POST /api/patient/login`, `/signup`, `/patientExists`, `/send-otp-login`, `/verify-otp-login`, `/forgetpwd`, `/forgetpwdresetpwd`; authenticated `/sendPhoneVerifyOTP`, `/sendEmailVerifyOTP`, `/verifyPhone`, `/verifyEmail` | Password login used the same 401 body but skipped password work for unknown users. OTP login send returned 404 for unknown email and 200 for an existing account. `patientExists` returned a public boolean. Signup duplicate returned an explicit “already exists” message. A duplicate, shadowed `/forgetpwd` handler returned a reset token in JSON if reached; the earlier handler responds without calling `next`, making the token-returning handler unreachable in the current route stack. |
| Doctor | `POST /api/doctor/login`, `/signup`, `/doctorExists`, `/forgetpwd`, `/forgetpwdresetpwd` | Password failures used a generic response, but unapproved accounts disclosed approval state and admin contact details; missing/unapproved users also skipped bcrypt. `doctorExists` returned a public boolean. Signup and reset errors revealed duplicate/account status. |
| Admin | `POST /api/admin/login` | Unknown and wrong-password responses matched, but missing accounts skipped bcrypt. |

Authenticated patient contact-verification endpoints and protected account lookups were reviewed; their identity is already established by patient-session middleware. OTP-send rate-limit configuration is a separate VAPT finding and was not changed here.

## Remediation

All four password login routes now perform bcrypt comparison for missing users using a fixed, non-credential dummy hash. Helper dummy comparisons use cost 12, matching helper registration; patient, doctor, and admin comparisons use cost 11, matching the password-hashing convention in patient/doctor registration. Doctor accounts that are not approved use the dummy path and receive the same generic 401 response as other failed logins. Successful login behavior and response payloads are unchanged.

Recovery endpoints for helper, patient, and doctor now return a generic success message for both eligible and unknown accounts. Actual reset emails remain conditional on an existing account; email delivery failures do not return account-specific errors. Database failures return generic server errors, not SQL or account details. Reset-token failures for helper/doctor reset paths use the same `Invalid or expired reset link.` response for missing accounts and invalid tokens. The unreachable duplicate patient recovery handler that contained a token-in-response response was removed.

Public `patientExists` and `doctorExists` no longer query or return whether an account exists. Signup duplicate responses no longer say “already exists” or “already registered.” Duplicate signup still fails, as required to preserve uniqueness; success versus failure is inherently observable and remains a residual enumeration path for open registration flows that do not require proof of contact ownership.

Patient OTP login send, helper phone/email OTP sends, and helper OTP verification failures now use non-account-specific responses. OTPs/emails are only dispatched to eligible submitted contacts; none are sent to arbitrary addresses to imitate successful delivery. Existing OTP rate-limit rules were left unchanged. A five-request/15-minute limiter based on the existing `express-rate-limit` dependency was added to the three password-recovery endpoints.

### Public response behavior

- Password login: unknown account, wrong password, and unapproved doctor now return the same `401 {"message":"Invalid Authentication Credentials!"}` response.
- Password recovery: existing and unknown account requests return HTTP 200 with `If the account is eligible, password reset instructions will be sent.`; reset tokens are not returned in responses.
- Account availability: patient/doctor checks return HTTP 200 with a generic registration message, without querying account state.
- Helper OTP sends: valid requests return the same generic response shape and status; delivery remains conditional. Missing/expired/incorrect helper OTPs return the same generic 400 message.
- Duplicate signup: the explicit account-existence wording is removed; normal successful registration response behavior remains intact.

## Files changed

- `utils/password-auth.js`: holds fixed cost-11/cost-12 dummy bcrypt hashes and comparison helper.
- `routes/patient_helpers.js`: dummy-hash login comparison; generic duplicate registration, OTP send/verify, and forgot-password responses; no recovery token or raw provider detail in public errors.
- `routes/patients.js`: dummy-hash login comparison; generic patient existence, OTP login, duplicate signup, recovery, and reset responses; removed the unreachable duplicate recovery handler that returned a token.
- `routes/doctors.js`: dummy-hash comparison for missing/unapproved accounts; generic account availability, duplicate signup, forgot-password, and reset responses.
- `routes/admin.js`: dummy-hash comparison for missing accounts.
- `app.js`: adds a five-per-15-minute recovery limiter using the installed rate-limit package; existing login and OTP limiters remain unchanged.
- `tests/user-enumeration.test.cjs`: isolated route tests with fake database and mail/SMS adapters.
- `tests/patient-otp.test.cjs`: expects the new generic 401 for a patient account removed between OTP send and verification.
- `VAPT-FINDING-8-USER-ENUMERATION-BACKEND-REPORT.md`: audit, results, and remaining dependencies.

## Timing mitigation, CAPTCHA, and rate limits

Dummy comparisons perform bcrypt work at the selected account-hash cost for nonexistent users and unapproved doctors. Tests verify cost-specific dummy hashes and compare public responses; they intentionally do not assert exact elapsed durations. This reduces the large timing difference caused by skipping bcrypt, but does not eliminate timing inference: database access, network latency, bcrypt versions/costs on legacy hashes, and infrastructure scheduling can still differ. Hash-round distributions, especially existing admin account hashes, must be checked in a safe non-production environment before claiming equal timing behavior.

No CAPTCHA/Turnstile/reCAPTCHA integration or verification middleware was found in the checked backend or Angular source. This task does not pretend CAPTCHA is implemented. Product owners must choose a provider and frontend/backend verification contract if CAPTCHA is required. Recovery requests are now rate-limited to five per 15 minutes per IP using the existing middleware dependency. Login rate limiting remains as configured. Existing OTP-send limiting remains as configured; OTP verification throttling remains tracked under the separate OTP-rate-limit finding.

The adjacent Angular doctor signup component consumes `doctorExists.message` as a boolean and displays either “already registered” or “not registered.” The backend now returns a generic string, so that preflight UI must be updated in a frontend task to stop making a misleading claim; the actual signup endpoint remains authoritative. The helper registration UI also branches on `vstatus === "OTP sent successfully"`; that response shape is retained for compatibility, with conditional wording, but an already-registered contact will not receive an OTP. Update that UI to explain generic eligibility and provide a login path without revealing account status.

## Tests executed

- `node --test tests/user-enumeration.test.cjs` — **2 passed, 0 failed, 0 skipped**. Covers same login status/body for missing and wrong-password users across helper/patient/doctor/admin; approved and unapproved doctor behavior; valid login remains functional; account recovery parity; generic existence and reset responses; duplicate signup messaging; conditional OTP delivery; and generic OTP verification failures.
- `node --test tests/user-enumeration.test.cjs tests/otp-bypass.test.cjs tests/patient-otp.test.cjs tests/authorization.test.cjs` — first run **8 passed, 1 failed, 1 skipped** because the pre-existing OTP test expected the old 404 when a patient disappeared after OTP send. After updating that assertion to the generic 401, the combined command was not rerun separately; the full suite below includes all those tests and passed.
- `npm.cmd test` — **17 passed, 0 failed, 1 skipped** (18 total). The skipped test is the opt-in MySQL authorization integration test; no production database was used.
- Syntax checks passed: `app.js`, `utils/password-auth.js`, all four changed route modules, `tests/user-enumeration.test.cjs`, and `tests/patient-otp.test.cjs`.

All database, mail, and SMS interactions in the new tests use isolated in-memory fixtures/stubs. No production customer accounts were queried.

## Remaining risks and staging verification

Registration success/failure can still reveal whether a signup identifier is available, particularly for patient/doctor signup flows that do not require verified contact proof. The duplicate error text is generic, but fully masking that distinction would require a product/API contract change such as verified-contact-first registration or a uniform asynchronous registration workflow. The public doctor email preflight and helper OTP UI also require frontend follow-up, described above.

OTP delivery paths perform external provider work only for eligible contacts; provider latency may differ from the no-send path even when response bodies match. The login dummy-hash mitigation also cannot guarantee constant-time behavior across database/network variance or legacy hash work factors. No CAPTCHA was present. The dedicated OTP rate-limit finding remains outside scope.

Staging checks required before closure: compare status/body/header/cookie behavior for existing, nonexistent, unapproved, and wrong-password login attempts across all roles; exercise known/unknown recovery requests with email delivery verified only for eligible accounts; test helper OTP send/verify and patient OTP login with owned fixture addresses; verify reset-link failures and duplicate registration behavior; observe coarse repeated login timings without using exact-duration unit assertions; confirm recovery limiter behavior; and check the updated frontend contract before deployment. Do not use production customer accounts. Automated tests do not establish closure of the VAPT finding.
