# CWE-613 Improper Session Management review

## Scope and conclusion

Reviewed patient, doctor, helper, and admin JWT login/logout flows; shared authentication middleware; cookie helpers; and the available backend authorization test. The VAPT response-replacement scenario does not by itself create authentication: protected APIs verify a server-signed HS256 JWT, and the frontend response fields are not used as server-side session state. A previously issued token remains a bearer credential, so logout revocation is what prevents replay.

Confirmed residual defect: `middleware/token-blacklist.js` previously removed every logout revocation after two hours. Helper login tokens use `JWT_EXPIRES_IN` and can outlive that fixed cleanup period (the helper login fallback is seven days), so the old token could become usable again before its JWT expiration. Cleanup now follows a valid numeric token `exp` claim. Missing or malformed expiry claims are retained for the process lifetime because there is no safe expiry time to schedule; an already-expired token needs no revocation entry because JWT verification rejects it.

## Relevant routes and behavior

- Login issuers: `routes/patients.js` (`/login`, `/verify-otp-login`), `routes/doctors.js` (`/login`), `routes/patient_helpers.js` (`/login`), and `routes/admin.js` (`/login`). Patient, doctor, and admin password login issue one-hour JWTs. Helper password login uses `JWT_EXPIRES_IN` (default seven days); helper registration also issues a token.
- Logout handlers in the four route files pass the authenticated request token to the shared blacklist and clear `auth_token` and `csrf_token`.
- `middleware/authenticate.js` verifies each bearer token or HttpOnly `auth_token` cookie with HS256 and the role-specific signing secret, then rejects blacklisted, malformed, expired, and invalid-role credentials.
- `utils/auth-cookies.js` sets the auth cookie at path `/` without a Domain attribute. Auth clearing targets the same path and host-only scope. The CSRF cookie uses the configured domain both when set and cleared.
- A successful login response includes a JWT for frontend compatibility. Modifying response fields cannot mint a signed token; replaying the actual token after logout is blocked by revocation on the same process.

## Limits and staging checks

The blacklist remains in-process memory; it is not shared between Node.js processes or application instances. The checked-in `deploy_scripts/run.sh` starts one named PM2 application without a cluster/instance option, but repository configuration cannot establish the live production process count, PM2 mode, or number of hosts. A minimal compatible multi-instance change is a shared revocation store (for example, Redis with a TTL derived from JWT `exp`) used by every instance. Confirm the live deployment topology and shared-store availability before implementing that architectural change.

Backend automated tests do not establish that the deployed Angular client clears all token copies or that production routing is single-instance. Verify the captured-token-after-logout sequence, helper token expiration behavior, cookie clearing, and cross-instance replay in staging before declaring the VAPT finding closed.

## OTP review overlap

The patient OTP login response contains a server-issued JWT after a correct OTP. Replaying that captured successful response after a later failed OTP can restore the still-valid bearer token in the client. This is session/token replay (CWE-613), not bypass of the server's OTP comparison; it was documented during the separate OTP Bypass review and was not modified in that OTP-only task. Staging must verify the exact credential replayed and protected API behavior.
