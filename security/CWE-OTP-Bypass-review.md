# OTP Bypass review

## Scope and confirmed defect

Reviewed the backend patient OTP login and phone/email verification routes, helper registration and helper phone/email OTP verification routes, JWT middleware, and the available tests. No doctor or admin OTP routes were found.

The helper registration route (`POST /api/helper/register`) inserted a helper and issued a JWT using only contact/password fields. It did not require successful OTP verification, despite the helper registration OTP endpoints. A caller could bypass OTP by calling registration directly; changing a failed verification response was not necessary. Registration now requires unexpired server-issued proof for every supplied email/phone. Proofs are single-use and keyed by normalized contact and flow purpose. The `helper-registration` purpose is distinct from `patient-contact`, which remains used by `/add-patient`.

Patient OTP login (`POST /api/patient/verify-otp-login`) already checked the server-side OTP before signing a JWT and consumed the OTP. Its expiry boundary now rejects at `expiresAt`. Patient phone/email verification now binds each challenge to authenticated patient ID and the contact already stored for that patient, enforces expiry and single-use, and consumes the OTP before database work so concurrent replays cannot both pass. Database failures return errors without issuing JWTs or marking verification successful.

Patient password signup (`POST /api/patient/signup`) creates an account without OTP proof, but does not issue a JWT in that route; patient password login and OTP login are separate. The backend checkout does not establish whether product policy requires OTP before account creation, so this was not changed. Confirm the intended signup contract with the Angular flow as a separate verification requirement.

OTP values are generated with `crypto.randomInt`; OTP values and OTP-bearing provider payloads have been removed from application logs and send responses. OTP purpose and contact checks are performed server-side; client role, status, or verification flags do not establish proof.

## API contract note

Helper registration clients must pass `purpose: "helper-registration"` to `/api/helper/sendPhoneVerifyOTP`, `/api/helper/verifyPhoneOTP`, `/api/helper/sendEmailVerifyOTP`, and `/api/helper/verifyEmailOTP` as applicable. They must pass the returned `verificationToken` values as `phoneVerificationToken` and/or `emailVerificationToken` to `/api/helper/register`. Requests without `purpose` continue to use `patient-contact` for existing patient-contact verification. When both email and phone are supplied for helper registration, both must be verified.

## Separate session replay overlap

Patient OTP login returns a valid JWT after a correct OTP. Replaying a previously captured successful login response after a later invalid OTP can restore that already-issued bearer token in the client, and the token remains valid until its expiry/revocation. This is session/token replay (CWE-613), not acceptance of an invalid OTP. It is documented separately and was not changed as part of this OTP-only task. The same principle applies to a captured helper verification proof until its one-time use. Do not treat an HTTP response-replacement PoC as closed until staging confirms which credential is replayed and the protected API behavior.

## Remaining infrastructure and staging checks

OTP challenges and verification proofs are held in process memory, as before. They are not shared across Node.js processes or instances. A cross-instance verify/register request may fail closed because the receiving process lacks the challenge/proof. A shared store could address availability, but no architectural migration was made here.

Retest in staging with isolated accounts: (1) call helper registration without OTP proof and confirm no account/JWT; (2) request and verify the correct OTP, register and access the helper dashboard; (3) retry with wrong, expired, reused, wrong-contact, and wrong-purpose OTP/proofs; (4) try replacing an invalid response with the captured successful response and record whether it replays a genuine proof/JWT; (5) check protected API access without credentials and with any replayed credential; and (6) repeat through the actual Angular flow and across instances if production uses more than one process/host. Do not claim closure based only on backend tests.
