# VAPT Finding #9 — OTP Rate Limit (Backend Report)

## 1. Finding summary and status

Finding #9 (CWE-307, Medium) concerns abuse of OTP send and verification endpoints. Source audit found ten active OTP routes. All were already behind five-per-15-minute per-IP limits, but an attacker able to rotate source IPs could target one contact without a contact-scoped cap. The default limiter and OTP challenge stores are in process memory.

Implemented locally: retained the existing per-IP policy, added privacy-preserving per-contact limits for OTP sends and verification, added `Retry-After` on OTP-limit 429 responses, and corrected OTP email expiry text to match the actual eight-minute lifetime. Automated tests pass as recorded below. Staging verification and external VAPT retesting remain pending; Finding #9 is **not closed**.

## 2. Complete OTP endpoint inventory

All paths below are `POST` routes mounted in `app.js`. Each is behind the existing IP limiter and the new contact-scoped limiter, both with a five-request/15-minute maximum. The IP limit executes before body parsing. The contact limit executes after JSON/urlencoded parsing and before the route handler, database lookup, OTP generation, or delivery provider call.

| Route | Caller / purpose | Authentication | OTP behavior and lifecycle |
|---|---|---|---|
| `/api/patient/sendPhoneVerifyOTP` | Patient contact verification | Patient session required | Generates a cryptographically random 4-digit code; stored for 8 minutes and consumed on successful verification. Bound to authenticated patient ID and the patient’s stored phone. |
| `/api/patient/verifyPhone` | Patient contact verification | Patient session required | Checks the patient/contact challenge; successful code is consumed before database update. |
| `/api/patient/sendEmailVerifyOTP` | Patient contact verification | Patient session required | Generates a random 4-digit code; stored for 8 minutes and bound to patient ID/email. |
| `/api/patient/verifyEmail` | Patient contact verification | Patient session required | Successful code is consumed before database update. |
| `/api/patient/send-otp-login` | Patient OTP login | Public | Sends a random 6-digit code when eligible; stored for 5 minutes. Public response is account-neutral. |
| `/api/patient/verify-otp-login` | Patient OTP login | Public | Valid code is consumed before account lookup/token issuance. Invalid, missing, and expired codes fail without issuing a login token. |
| `/api/helper/sendPhoneVerifyOTP` | Helper registration or patient-contact verification | Public | Purpose is `helper-registration` or `patient-contact`; random 4-digit code stored for 8 minutes and keyed by purpose/contact. |
| `/api/helper/verifyPhoneOTP` | Helper registration or patient-contact verification | Public | Correct code is consumed and returns a short-lived verification proof bound to the purpose/contact. |
| `/api/helper/sendEmailVerifyOTP` | Helper registration or patient-contact verification | Public | Purpose-bound random 4-digit code stored for 8 minutes. |
| `/api/helper/verifyEmailOTP` | Helper registration or patient-contact verification | Public | Correct code is consumed and returns a purpose/contact-bound verification proof. |

No doctor or admin OTP generation, send, resend, or verification endpoint was found in the checked route modules. No alternate OTP endpoint was found outside this inventory. Resending a code replaces the current in-memory challenge for that key. Helper verification proofs have a 15-minute lifetime and are single-use at the protected registration/add-patient operation.

## 3. Existing controls audited

- `express-rate-limit` 7.5.1 is already an application dependency; no package was added.
- Existing shared send and verification IP limiters each allow five requests per 15 minutes and are mounted before all listed route handlers. They count failed and successful attempts; failed attempts do not reset the counter.
- `standardHeaders` remains enabled. OTP limit responses now include a calculated `Retry-After` header and generic JSON message.
- Codes use Node `crypto.randomInt`; email/phone OTPs are not returned in public JSON. The checked send paths do not log OTP values.
- Helper challenge keys bind purpose/contact; patient contact challenges bind authenticated patient ID/contact; patient login is a patient-role issuance flow. Successful verification consumes the code. Existing tests cover expiry, replay, role/purpose isolation and the successful flows.
- Patient/helper phone and email verification routes preserve their established authentication and response behavior. No endpoint or payload contract was changed by the rate-limit work.

## 4. Confirmed gaps and fixes

### Contact/IP rotation

Previously the only OTP send and verify controls keyed on `req.ip`. An attacker rotating IPs could obtain additional attempts against the same destination/challenge. Added separate contact-scoped send and verify limiters, each five per 15 minutes. Email identifiers are trimmed/lowercased; phone identifiers are normalized to digits and the final ten digits, matching the helper phone challenge identity. Keys include role scope and OTP purpose, then are HMAC-SHA-256 digested before entering the rate-limit store. Raw contact values are not used as limiter keys or logged.

Malformed/missing contact requests still count against the existing IP limit; requests with a usable contact also count against the contact bucket even when the OTP is missing or malformed. The limiters run before handlers, so a rejected send cannot query the account, generate a code, or call SMS/email providers, and a rejected verification cannot compare a code or issue proof/token.

### Expiry-message mismatch

Patient and helper email templates said ten minutes while their challenge records expired after eight minutes. Updated those OTP messages to say eight minutes and added fixture assertions. The actual expiry durations remain unchanged.

## 5. Files changed

- `app.js` — retained per-IP limiters; added the per-contact send/verification limiters after request parsing and before route mounts; used HMAC contact keys; added `Retry-After` to OTP 429 responses.
- `routes/patients.js` — corrected the patient contact-email OTP lifetime text to eight minutes; challenge lifetime and API contract unchanged.
- `routes/patient_helpers.js` — corrected the helper contact-email OTP lifetime text to eight minutes; challenge lifetime and API contract unchanged.
- `tests/rate-limits.test.cjs` — covers all ten endpoint mounts, five allowed/sixth rejected, retry headers, contact normalization across changing forwarded IPs, purpose scoping, and that a blocked request does not reach the route handler.
- `tests/patient-otp.test.cjs` — asserts patient email text matches the actual eight-minute expiry while retaining success/replay/expiry coverage.
- `tests/otp-bypass.test.cjs` — asserts helper email text matches the actual eight-minute expiry while retaining purpose, replay, expiry and registration coverage.
- `.env.example` — documents optional `OTP_RATE_LIMIT_SECRET` configuration.
- `VAPT-FINDING-9-OTP-RATE-LIMIT-BACKEND-REPORT.md` — this report.

No production data was used and no new package or external service was introduced.

## 6. Final rate-limit policy

| Layer | Routes | Limit | Key and behavior |
|---|---|---|---|
| IP send limit | All five send routes | 5 / 15 minutes | Existing shared process-local Express limiter; counts all attempts. |
| Contact send limit | All five send routes | 5 / 15 minutes | HMAC of operation, role/purpose, contact type and normalized contact. |
| IP verification limit | All five verify routes | 5 / 15 minutes | Existing shared process-local Express limiter; wrong, malformed, missing, expired and successful attempts count. |
| Contact verification limit | All five verify routes | 5 / 15 minutes | HMAC contact/purpose bucket independent of send counts; failures do not reset it. |

Each 429 response keeps generic wording, standard rate-limit headers, and a `Retry-After` value derived from that bucket’s reset time. Send and verification counters are separate, as are contact buckets for role/purpose. A patient-supplied `purpose` field cannot create new patient contact buckets; patient contact endpoints always use the fixed `patient-contact` scope.

## 7. OTP expiry, replay and identity binding

- Patient contact OTPs expire after 8 minutes and are single-use; the patient session and stored contact bind the operation.
- Patient login OTPs expire after 5 minutes and are consumed before patient lookup and JWT issuance. The login email is currently used as the challenge key; existing application behavior expects the submitted email to match the account email.
- Helper OTPs expire after 8 minutes, are keyed by purpose and normalized contact, and are consumed before a verification proof is issued. The proof expires after 15 minutes and is consumed by the relevant protected operation.
- Per-contact verification limits now persist across resend requests and failed code attempts for 15 minutes. Since code lifetime is at most eight minutes, an expired challenge cannot regain guesses when the limiter window ends.
- OTP challenge/proof data remains in process-local `Map` objects. A restart loses outstanding challenges and proofs (verification fails closed); separate processes/hosts do not share them. Rate-limit MemoryStores have the same process-local limitation.

This work adds abuse controls; it does not replace the existing OTP Bypass remediation or establish that all replay/session risks are resolved.

## 8. Proxy, keys and deployment topology

`app.js` sets `trust proxy` to exactly one hop. Its comment describes Nginx directly in front of the app, and `deploy_scripts/run.sh` starts a PM2 app without an explicit cluster/instance count. No Nginx configuration is present in this repository, and those files cannot establish the live ingress path, PM2 mode, number of hosts, or whether the app port is externally reachable. Confirm these before rollout. The one-hop setting is safe only if the app is reachable exclusively through that trusted proxy and the proxy overwrites/sanitizes forwarded headers.

The rate limiter uses express-rate-limit’s default in-memory store. Contact HMAC uses `OTP_RATE_LIMIT_SECRET` when configured, otherwise the existing `JWT_SECRET_PATIENT`, and finally a process-generated random secret as a last-resort local fallback. Configure a high-entropy `OTP_RATE_LIMIT_SECRET` identically on every backend instance. If production uses multiple app processes or hosts, deploy a shared express-rate-limit-compatible store and shared OTP challenge/proof storage; otherwise limits and OTP state are per process. Redis was not introduced because repository/deployment configuration does not establish that it exists.

Shared-IP users may collectively consume the existing five-per-15-minute IP bucket. The contact layer adds a separate destination-specific cap without increasing that IP limit. Validate legitimate NAT/corporate usage in staging.

## 9. Tests and actual results

- Focused: `node --test tests/rate-limits.test.cjs tests/patient-otp.test.cjs tests/otp-bypass.test.cjs` — **11 passed, 0 failed, 0 skipped**.
- Full backend suite: `npm.cmd test` — **23 passed, 0 failed, 1 skipped** (24 tests). The skipped test is the opt-in MySQL authorization/ownership integration test; it requires an isolated configured test database.
- Syntax: `node --check app.js`, `node --check routes\patients.js`, `node --check routes\patient_helpers.js`, and checks of all three changed OTP test files — all passed.
- Limiter tests use isolated Express applications and mock route handlers/providers; no real SMS/email was sent. Existing OTP fixture suites use stubbed delivery providers and cover legitimate success, invalid/malformed/missing, expiry, replay and helper purpose binding.
- No production build applies to this backend-only change.

## 10. Remaining deployment dependencies

1. Confirm the deployed proxy topology, that only one trusted proxy hop is present, and that direct access to the app port cannot spoof `X-Forwarded-For`.
2. Set one random `OTP_RATE_LIMIT_SECRET` consistently across instances; preserve it across restarts.
3. Confirm whether production runs more than one process/host. If so, provision a shared rate-limit store and shared challenge/proof store before enabling multi-instance OTP workflows.
4. Observe legitimate requests behind shared NAT to confirm the five-per-15-minute per-IP limit is workable.
5. Confirm actual SMS/email provider behavior and expiry wording with controlled accounts; automated tests never contacted providers.
6. Perform the external VAPT retest on the deployed configuration. Local tests are not staging evidence.

## 11. Staging verification checklist

Use owned test accounts and numbers only. Record deployment/build, ingress path, timestamps, response status/body/headers, provider delivery, and challenge outcomes.

1. For all ten routes, make five attempts and a sixth attempt from the same client IP; confirm generic 429, rate-limit headers and `Retry-After`.
2. Repeat sends and incorrect/missing/malformed verification attempts for the same normalized contact from different client IPs; confirm the contact-scoped sixth request is rejected and no provider, database, OTP comparison, proof, or token side effect occurs.
3. Try email case/whitespace and phone formatting variants; confirm they share the intended contact bucket. Confirm different role/purpose contacts and different addresses retain separate buckets.
4. Verify correct OTP and fresh registration/login/contact-verification workflows still succeed below the limit. Verify resend replaces the previous challenge, old codes fail, expired codes fail, and successful codes/proofs cannot be reused.
5. Compare public known/unknown patient/helper OTP-send responses for account-neutral behavior.
6. Exercise patient authenticated contact verification and helper registration/contact purposes; verify role and purpose isolation.
7. Repeat across a restart and all production instances to determine whether the shared-store requirement applies and ensure the configured HMAC secret keeps contact keys stable.
8. Inspect real forwarded headers at the ingress and verify an external client cannot supply a trusted spoofed IP. Confirm shared NAT behavior.
9. Run the original Finding #9 VAPT abuse scenario and capture actual results. Keep OTP Bypass and session replay checks separate.

## 12. Remediation status and security boundary

Per-IP and per-contact OTP send/verification limits are implemented and locally tested. OTP expiry messaging now matches actual challenge lifetime. All limiter and OTP state is currently process-local, and production proxy/instance topology is unverified. Staging integration and external VAPT retesting remain pending. Rate limiting reduces abuse; it does not prove identity, prevent all distributed abuse, replace OTP purpose/expiry/replay checks, or guarantee authorization. Finding #9 is **not closed**.
