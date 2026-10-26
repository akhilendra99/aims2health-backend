# VAPT Finding #6: Backend input validation

## Initial inventory (before remediation)

The backend is Express 4 with direct route handlers in `routes/patient_helpers.js`, MySQL through `mysql2`, and no installed request-schema validation library or existing route validation middleware. Queries are generally parameterized. `utils/pagination.js` provides a pagination helper, but the helper report route did not use it.

| Helper router endpoint | Client-controlled inputs observed | Initial validation notes |
|---|---|---|
| `POST /register` | `email_id`, `phone_no`, `password`, OTP proof tokens; callers may also submit `role` | Partial email/phone checks; no schema/type/unknown-field checks or general length caps. |
| `POST /login` | `email_id` or `phone_no`, `password`; optional ignored `role` | Missing/type checks only; no length/format validation. |
| `POST /add-patient` | Names, address/PIN, DOB, medical history, gender, phone/email/WhatsApp, country codes, IDs, password, EHR ID, helper ID, OTP proof tokens | Some required checks and field-specific checks; weak date/type/length checks, blanket angle-bracket rejection, unbounded fields, and error responses expose internal error text. |
| `GET /get-patients` | No query/body/path inputs | Protected account identity is taken from verified session. |
| `POST /change-password` | `oldPassword`, `newPassword`, `confirmPassword` | New password has a pattern check; missing/mismatch return 500; no schema/unknown-field or old-password length checks. |
| `POST /sendPhoneVerifyOTP` | `phone`, `countryCode`, `purpose` | Partial normalization/format checks. OTP behavior is outside this remediation scope. |
| `POST /verifyPhoneOTP` | `phone`, `countryCode`, `otp`, `purpose` | Partial checks. OTP behavior is outside this remediation scope. |
| `POST /sendEmailVerifyOTP` | `email`, `purpose` | Email format check. OTP behavior is outside this remediation scope. |
| `POST /verifyEmailOTP` | `email`, `otp`, `purpose` | Sparse checks. OTP behavior is outside this remediation scope. |
| `POST /mis-info` | `doctor_id`, `from_date`, `to_date` | Admin-only endpoint mounted in this router; not a Helper Dashboard endpoint. |
| `POST /medreport` (multipart) | `patient_id`, `title`, `content`, `mediaType`, `recordDate`, file `image` and its name/type/size | Patient authorization exists; no body schema, strict date/length checks, or Multer size/field limits. |
| `GET /medreports/:patient_id` | `patient_id`, query `pagesize`, `page` | Authorization validates patient ID; pagination uses permissive `parseInt` and has no explicit query bounds. |
| `POST /update-consent` | `patient_id` | Authorization checks patient relationship; no body schema or unknown-field rejection. |
| `POST /forgetpwd` | `email` | Required check only; no email type/format/length validation. |
| `GET /medreports/:patient_id/:id` | `patient_id`, `id` | Authorization validates access; route relies on it for identifier validation. |
| `PUT /medreport/:patient_id/:id` (multipart) | Path IDs; `title`, `content`, `mediaType`, `recordDate`, optional file `image` and metadata | Authorization exists; no body schema/date/length checks or Multer limits. |
| `DELETE /medrecords/:id` | `id` | Authorization validates the report identifier. |
| `POST /search` | `appmntDate`, `docType` | No required/type/format/length/unknown-field validation before SQL. |
| `POST /logout` | No body/query/path inputs | Session middleware protects the route. |

The helper router's response data includes medical-history and report content. No frontend checkout is present to establish whether these values are rendered as text or passed to an HTML sink. This remediation preserves text/rich content rather than stripping markup; frontend contextual output encoding remains a staging review item.

## Implemented backend validation

The concrete gap was that several Helper Dashboard handlers consumed request values with little or no server-side type, format, size, and unknown-field validation. Validation is now enforced in route middleware before handler/database work. A small local middleware was used because this backend has no request-schema validation dependency; no new package was added.

`POST /register` and `POST /login` validate optional email (email format, max 100 chars), optional phone (7–30 phone characters), required non-empty password (max 72 UTF-8 bytes, compatible with bcrypt), optional legacy `role` (max 20), and optional 48-hex-character verification proof fields. The existing email-or-phone requirement is enforced as a schema refinement. The role remains ignored for authorization. Existing verification workflows are not changed.

`POST /add-patient` validates required name, gender, medical-history, phone, address, and DOB fields; names max 50 chars, gender max 20, medical history max 65,535 UTF-8 bytes, six-digit address/PIN, phone format/length, and DOB as an ISO calendar date, four-digit year, or legacy numeric age (0–120). Optional email, secondary/WhatsApp phone, country codes, IDs, password, and legacy role/proof fields have type/format/length checks. Numeric phone/PIN JSON values remain compatible and are normalized to strings. Year and age DOB values retain the prior route's normalization into a database date. Markup in medical history remains valid data and is not stripped.

Report routes validate patient/report IDs as positive safe integers. `GET /medreports/:patient_id` accepts only positive integer pagination values (`pagesize` 1–100 and `page` 1–1,000,000), then passes normalized integers through the existing pagination helper. Create/update report bodies validate title (100 chars), content (65,535 UTF-8 bytes), media type (30 chars), and optional calendar date. Consent validates only `patient_id`; password change validates all three password fields and matching new/confirmation values; password reset validates email; appointment search validates ISO date and non-empty doctor type (50 chars); delete validates report ID. The report upload routes enforce Multer limits (one file, 25 MiB, bounded fields), safe filename length, and the existing PNG/JPEG/PDF MIME allowlist. Invalid uploaded files are discarded. SQL continues to use bound parameters; validated pagination values alone are interpolated through the existing helper.

Malformed JSON under `/api/helper` now receives a consistent JSON 400 response instead of Express's parser error page. Other API error handling is unchanged. `/get-patients` and `/logout` have no client-controlled business input; their existing authenticated identity behavior is retained. OTP endpoints and admin-only `/mis-info` share this router but are outside the requested Finding #6 remediation scope and were not changed.

### Changed files

- `middleware/validate-request.js`: reusable schema and uploaded-file validation with safe 400 responses.
- `middleware/helper-json-errors.js`: scoped malformed-JSON response handler.
- `app.js`: installs that handler after the body parsers and before routes.
- `routes/patient_helpers.js`: applies schemas to the in-scope helper dashboard endpoints, uses validated values, bounds uploads/pagination, and preserves legitimate rich-text/date/phone formats.
- `tests/helper-input-validation.test.cjs`: isolated HTTP/router regression tests using a fixture JWT and fake database.
- `VAPT-INPUT-VALIDATION-BACKEND-REPORT.md`: inventory and findings/results record.

## Automated verification

Focused command: `node --test tests/helper-input-validation.test.cjs` — **2 passed, 0 failed, 0 skipped**. This covers malformed JSON, missing/invalid fields, wrong types, oversize input, unknown fields, direct API requests, valid search reaching the existing no-results response, safe preservation of medical report markup, strict path/query formats, and multipart unknown fields. The router test uses a fake database and does not connect to production.

Full repository command: `npm.cmd test` — **14 passed, 0 failed, 1 skipped** (15 total). The skipped test is the opt-in MySQL authorization integration test, which was not run against any database. The full suite also exercised existing authentication/authorization, OTP, and CWE-613 tests; those findings were not modified as part of this task. No frontend tests were available or run.

## Remaining gaps and staging verification

Validation is not HTML output encoding. Medical history/report content intentionally retains markup for compatibility, so the Angular application must render these values using contextual text escaping or an explicitly reviewed rich-text sanitizer. The frontend checkout was not available in this backend repository. Upload validation checks the declared MIME type and size; it does not inspect file signatures, so content sniffing remains a separate hardening opportunity if required by the product's upload policy. OTP request validation and `/mis-info` remain outside this finding's scope.

Staging retest still required before closure: submit valid and malformed/missing/oversized/unexpected inputs directly to each listed Helper Dashboard endpoint; confirm invalid requests return safe 400 responses and do not invoke business queries; exercise valid registration/login, patient creation with supported date/age and phone formats, report create/update/list/delete, consent, password change/reset, and search using isolated staging accounts; test accepted and rejected multipart files at and beyond limits; then inspect rendered medical-history/report content in the Angular UI for contextual output encoding. Do not use production accounts or data. This report records implementation and automated results only; it does not claim VAPT closure.
