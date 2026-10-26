# CWE-639 authorization review and completion

Review date: 2026-10-24. Scope: this Express/MySQL backend and read-only inspection of the adjacent Angular checkout. No production deployment or production HTTP probing was performed.

## Evidence and initial audit

The supplied `D:\all_docs\LATESTVPATAIMS2HEALTH_unlocked.pdf` was read locally. Physical page 19 / printed page 16 identifies admin `/mnbvcxzadmin` and doctor `/dlogin` frontend workflows and describes request-method manipulation and missing server-side role/permission enforcement. The detail has inconsistent CWE/severity fields (CWE-601/Medium) but explicitly references CWE-639. This review follows the requested CWE-639 authorization scope. Document text was treated as evidence, not instructions.

`CWE-639-audit.md` was already present when this task began. Its historical route inventory and proposed fixes describe earlier vulnerabilities; many of those fixes were already in the working files. All project source files were untracked, and the branch had no commits, so a reliable Git before/after history was unavailable. Existing unrelated work was preserved. This report distinguishes verified current changes from that earlier draft.

Structure: `app.js` mounts `/api/patient`, `/api/doctor`, `/api/helper`, and `/api/admin`. The four route files contain the handlers, business logic, and SQL; there are no separate controller modules. `middleware/authenticate.js` verifies existing JWTs, cookies, signing domains, and the token blacklist. Existing `utils/authorization.js` supplies parameterized database identity and relationship policies. No standalone tenant or second-opinion case API exists: appointments, prescriptions, and EHR `casesheet` / `vs_logins` implement those workflows.

Initial inspection, before implementation, confirmed:

| File / operation | Observed cause | Targeted fix |
|---|---|---|
| `app.js`, GET/HEAD `/images/*` | Public static medical files bypassed every API ownership check. The static mount also referenced an undefined `path`. | Replace static mount with authenticated database-reference authorization before sending bytes. |
| `routes/patients.js`, `routes/doctors.js`, `routes/patient_helpers.js` | These routes referenced missing `utils/public-record.js`; application imports and integration tests failed. Existing broad SELECT responses needed the intended credential/bank-field filtering. | Supply that missing response serializer without changing response shapes. |
| `middleware/authenticate.js` | ID validation coerced arrays/objects into strings; ambiguous patient/helper claim shapes were not rejected. | Accept scalar positive safe-integer IDs only; reject tokens containing both identity keys. Preserve HS256, blacklist, cookie support, legacy tokens, and distinct signing-domain enforcement. |
| `utils/authorization.js`, doctor protected operations | Identity lookup verified account existence/email but did not recheck `validated`; a previously approved doctor could retain access after approval withdrawal. Unknown roles could fall through to the doctor patient scope. | Recheck current doctor approval in SQL and fail closed for unknown roles. |
| `routes/doctors.js`, POST `/updateAppointmentState` | A row disappearing between policy and status queries caused unchecked `result[0]` access. | Return 404 if the scoped query no longer finds the appointment. Existing scoped UPDATE remains in place. |
| Post-Multer authorization failures | A denied consultation/helper/attachment policy could leave the newly uploaded file on disk. | Discard the Multer file when database authorization denies or fails. |
| `tests/authorization.test.cjs` | Assertions expected shared signing secrets to work despite existing fail-closed enforcement; failed tests leaked environment changes. | Preserve the security control, isolate/restore test secrets, exercise real routes with temporary MySQL tables, and extend negative/positive coverage. |

## Reviewed vulnerable route families and effective policies

The earlier draft identifies the original broad IDOR surface. These protections were already substantially present at task entry and were retained and tested:

| Mount / routes | Required authorization |
|---|---|
| Patient: GET `/appointment/:id`, `/getappointmentreceipt/:patientId`, `/medreportlist/:id`; POST `/:id`, `/listprescriptions`, `/getorderid`, `/setappointment` | Verified patient, assigned helper, or admin; patient/family/helper relationship checked in the database before access or side effects. |
| Patient: GET `/get-patients`; POST `/add-patients`, `/getvdetails` | Parent/current patient comes from the authenticated identity, not body/query IDs. A family member must match `parent_id` and the existing helper relationship rule. |
| Patient: GET `/medreports/:id`; PUT `/medreport/:id`, `/medreportwoimage/:id`; DELETE `/medrecords/:id` | Report ID and authenticated patient owner. Conflicting path/body IDs and unauthorized attachment references are rejected. UPDATE/DELETE SQL includes patient ownership. |
| Patient: POST `/medreport`, `/medreportwoimage` | New records belong to the authenticated patient; body patient/role fields cannot change ownership. Existing file references require access. |
| Helper: POST `/add-patient`; GET `/get-patients` | Verified helper identity supplies helper ownership; frontend helper IDs cannot reassign ownership. Existing OTP-verification requirements remain. |
| Helper: POST `/medreport`, `/update-consent`; GET `/medreports/:patient_id`, `/medreports/:patient_id/:id`; PUT `/medreport/:patient_id/:id`; DELETE `/medrecords/:id` | Database patient/helper assignment; report/patient match for individual reports. Mutations also scope SQL by helper ownership. |
| Helper: POST `/mis-info` | Admin-only reporting operation; helper token alone is insufficient. |
| Doctor: GET `/appointment/:id`, `/upcomingAppointment/:id`, `/pastAppointment/:id`, `/:id`; GET `/patientDetails/:id` | Own doctor profile/calendar; established admin read workflows remain allowed. |
| Doctor: POST `/deleteAppointment`, `/updateAppointmentState`, `/sendSmsLink` | Own calendar/appointment relationship; notification recipient contact information is loaded from the authorized patient. |
| Doctor: GET `/medreportlist/:id`; POST `/sendVSData` | Doctor has an appointment with this patient. EHR doctor identity comes from authenticated doctor, not body `docId`. |
| Doctor: POST `/uploadprescription`, `/listprescriptions` | Patient/calendar pair belongs to that doctor's consultation; INSERT SELECT repeats the relationship restriction. |
| Doctor: GET `/listdoctorspayments/:doctorId`; POST `/schedule` | Doctor identity is taken from the verified session regardless of frontend doctor IDs. |
| Admin: patient/helper/doctor/payment lists, validation, payment/bank/profile updates, doctor-type changes, helper reassignment | Admin token and current database account are required. Patient, doctor, and helper tokens are denied for every protected admin route registration. |
| GET/HEAD `/images/:filename` | Current account plus stored report/prescription/biodata reference and matching patient/consultation/doctor ownership; admin may access mapped files. Patient/helper booking users may view approved doctors' published biodata, matching the Angular booking screen. Unknown files remain inaccessible, including for admin. |

Authentication failures use 401; a verified wrong role uses 403; missing or inaccessible resources use 404. Database authorization failures use 500 and never continue to handlers. Missing/reused signing-domain configuration fails closed with 500. Public registration/login/OTP/reset flows remain public where required, but protected data/mutations cannot be reached merely by changing the method. Reset routes verify a password/email-derived reset token. Public doctor-type routes return scheduling catalogs/counts, not patient records. The generated complete inventory below lists all route registrations and their policies.

## Files changed in this completion

- `app.js`: mount protected file delivery.
- `middleware/protected-files.js` (new): authorize GET/HEAD/ranges using parameterized stored-reference lookups; prevent nested paths; private/no-store responses; deny other methods.
- `middleware/authenticate.js`: scalar ID validation and ambiguous-identity rejection.
- `utils/authorization.js`: unknown-role denial, current doctor approval, denied-upload cleanup, and approved doctor biodata access for the existing booking screen.
- `utils/public-record.js` (new): complete existing imports and strip passwords/hashes and bank fields from shared response serialization.
- `routes/doctors.js`: handle the missing scoped appointment before dereferencing it.
- `.env.example`: demonstrate distinct signing domains explicitly; no real secrets changed.
- `tests/authorization.test.cjs`: repair test isolation and add authorization regression coverage.
- `security/CWE-639-review.md`: current audit, route inventory, results, and remaining verification requirements. Earlier audit draft retained.

## Validation

`npm.cmd test`: two unit tests pass; MySQL test deliberately skipped by default. `npm.cmd run test:authorization:mysql`: all three tests pass, zero skips. Integration tests use real MySQL SQL execution and real Express routers with connection-local temporary tables shadowing application tables. External EHR/payment/email/SMS/Zoom calls are blocked, and test files are removed. No imported application rows are inserted, updated, or deleted.

Coverage: 74 protected route registrations checked for unauthenticated rejection and inappropriate roles; four real login issuers checked against frontend role escalation; 81 positive/negative route cases plus 56 unauthenticated method/path cases; mutation-result assertions; patient/family/helper/doctor/admin access; invalid and conflicting IDs; wrong-email sessions; doctor approval withdrawal; GET/HEAD/range/cookie download checks; multipart cross-user denial, cleanup, and authorized upload/download; approved doctor biodata access for booking users; request-method changes on admin/doctor workflows; existing CSRF and trusted-origin controls. JWT tests cover expiry, malformed/revoked tokens, algorithm restriction, forged roles, ambiguous IDs, legacy token compatibility, and rejection of reused signing secrets. Authorization database failure/account removal fail closed.

All 20 source/test JavaScript files pass `node --check`. An actual `app.js` startup smoke check on an ephemeral loopback port passed: `/health` returned 200, unauthenticated admin listing and `/images` download returned 401. That smoke process was stopped afterward. There is no configured lint command. The `build` script launches `node server.js` rather than compiling; a persistent application server was not started as a build check. Angular is outside the writable backend scope and was inspected without modifications or a frontend build.

## Remaining deployment and manual verification

- **Deployment blocker:** the current local environment's JWT secrets are not three distinct configured values. Existing middleware correctly rejects this. Configure independent strong patient/doctor/admin secrets before deployment; coordinate session invalidation. Real `.env` secrets were neither printed nor changed. Tests use isolated distinct fixture keys and do not certify this environment's authentication readiness.
- Retest the original VAPT method-manipulation proof of concept on staging with patient, helper, doctor, and admin sessions. Passing backend regression tests supports code remediation, not a production VAPT closure certificate.
- Verify reverse-proxy/CDN configuration: `/images` must reach this middleware, not an Nginx alias/public bucket. Purge previously cached medical files. This checkout cannot establish infrastructure behavior.
- Verify Angular image/PDF previews and downloads using the existing backend auth cookie. Cross-site deployments and embedded PDF viewers must send it; same-site subdomain configurations should preserve the existing cookie workflow. Anonymous external file sharing is intentionally denied. Unmapped historical attachments/biodata need manual reference repair; do not restore public static serving.
- Full EHR case creation, family/helper registration with OTP proofs, paid booking/signature flow, Zoom, messaging, and refund/cancellation workflows require staging smoke tests. External calls were deliberately blocked in these local regression tests. Payment replay/amount integrity and general business logic are outside this narrowly scoped authorization change.
- Existing policy grants doctors patient medical-record access if any appointment relationship exists; whether historical/cancelled appointments should expire that access needs a business policy decision. Existing helper/family relationship semantics are preserved and must be confirmed with clinical operations.
- Logout revocation remains an in-process blacklist (including its existing two-hour cleanup versus longer helper JWT lifetime). Multi-instance revocation and immediate password-reset session invalidation require a separate session-lifecycle change. Existing verbose route logging should be reviewed for health data/secrets separately.

No claim of production closure is made while these deployment and staging checks remain outstanding.

## Complete current API registration inventory

Line numbers refer to the completed source. Each row is a registered method; Express GET also handles HEAD. Public reset/verification routes retain their inline proof checks.

| File:line | Method | Mounted route | Policy |
|---|---|---|---|
| `routes/patients.js:203` | POST | `/api/patient/contact` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:235` | GET | `/api/patient/currentMedReportTotal` | patient/current database identity |
| `routes/patients.js:276` | GET | `/api/patient/medreports` | patient/current database identity |
| `routes/patients.js:318` | POST | `/api/patient/search` | patient/current database identity |
| `routes/patients.js:356` | POST | `/api/patient/requestEmergency` | patient/current database identity |
| `routes/patients.js:398` | GET | `/api/patient/medreportlist/:id` | patient/helper/admin + patient relationship |
| `routes/patients.js:439` | GET | `/api/patient/appointment/:id` | patient/helper/admin + patient relationship |
| `routes/patients.js:480` | GET | `/api/patient/medreports/:id` | patient/current database identity |
| `routes/patients.js:505` | PUT | `/api/patient/medreport/:id` | patient + own report |
| `routes/patients.js:552` | PUT | `/api/patient/medreportwoimage/:id` | patient + own report |
| `routes/patients.js:616` | POST | `/api/patient/patientExists` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:640` | POST | `/api/patient/getvdetails` | patient/current database identity |
| `routes/patients.js:702` | GET | `/api/patient/getappointmentreceipt/:patientId` | patient/helper/admin + patient relationship |
| `routes/patients.js:747` | POST | `/api/patient/sendPhoneVerifyOTP` | patient/current database identity |
| `routes/patients.js:832` | POST | `/api/patient/verifyPhone` | patient/current database identity |
| `routes/patients.js:904` | POST | `/api/patient/sendEmailVerifyOTP` | patient/current database identity |
| `routes/patients.js:956` | POST | `/api/patient/verifyEmail` | patient/current database identity |
| `routes/patients.js:999` | POST | `/api/patient/sendConsent` | patient/current database identity |
| `routes/patients.js:1064` | POST | `/api/patient/send-otp-login` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:1095` | POST | `/api/patient/verify-otp-login` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:1132` | PUT | `/api/patient/chpwd` | patient/current database identity |
| `routes/patients.js:1204` | POST | `/api/patient/signup` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:1598` | POST | `/api/patient/add-patients` | patient/current database identity |
| `routes/patients.js:1796` | GET | `/api/patient/get-patients` | patient/current database identity |
| `routes/patients.js:1817` | POST | `/api/patient/medreport` | patient/current database identity |
| `routes/patients.js:1966` | POST | `/api/patient/medreportwoimage` | patient/current database identity |
| `routes/patients.js:2015` | POST | `/api/patient/getorderid` | patient/helper/admin + patient relationship |
| `routes/patients.js:2113` | POST | `/api/patient/setappointment` | patient/helper/admin + patient relationship |
| `routes/patients.js:2505` | POST | `/api/patient/login` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:2562` | POST | `/api/patient/forgetpwd` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:2628` | POST | `/api/patient/forgetpwd` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:2647` | POST | `/api/patient/forgetpwdresetpwd` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patients.js:2776` | POST | `/api/patient/listprescriptions` | patient/helper/admin + patient relationship |
| `routes/patients.js:2804` | DELETE | `/api/patient/medrecords/:id` | patient + own report |
| `routes/patients.js:2819` | POST | `/api/patient/logout` | patient/current database identity |
| `routes/patients.js:2826` | POST | `/api/patient/:id` | patient/helper/admin + patient relationship |
| `routes/doctors.js:165` | POST | `/api/doctor/doctorExists` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/doctors.js:188` | GET | `/api/doctor/appointment/:id` | own doctor profile or admin |
| `routes/doctors.js:236` | GET | `/api/doctor/upcomingAppointment/:id` | own doctor profile or admin |
| `routes/doctors.js:296` | GET | `/api/doctor/pastAppointment/:id` | own doctor profile or admin |
| `routes/doctors.js:358` | GET | `/api/doctor/:id` | own doctor profile or admin |
| `routes/doctors.js:407` | GET | `/api/doctor/patientDetails/:id` | own doctor calendar (admin reads permitted) |
| `routes/doctors.js:449` | PUT | `/api/doctor/chpwd` | approved doctor/current database identity |
| `routes/doctors.js:523` | POST | `/api/doctor/deleteAppointment` | doctor + own empty calendar |
| `routes/doctors.js:571` | GET | `/api/doctor/medreportlist/:id` | doctor + appointment/patient relationship |
| `routes/doctors.js:612` | POST | `/api/doctor/schedule` | approved doctor/current database identity |
| `routes/doctors.js:720` | POST | `/api/doctor/signup` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/doctors.js:802` | POST | `/api/doctor/login` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/doctors.js:864` | POST | `/api/doctor/createMeeting` | approved doctor/current database identity |
| `routes/doctors.js:993` | POST | `/api/doctor/sendSmsLink` | doctor + own appointment |
| `routes/doctors.js:1072` | GET | `/api/doctor/listdoctorspayments/:doctorId` | approved doctor/current database identity |
| `routes/doctors.js:1101` | POST | `/api/doctor/updateAppointmentState` | doctor + own appointment |
| `routes/doctors.js:1143` | POST | `/api/doctor/sendVSData` | doctor + appointment/patient relationship |
| `routes/doctors.js:1212` | POST | `/api/doctor/uploadprescription` | approved doctor/current database identity |
| `routes/doctors.js:1273` | POST | `/api/doctor/listprescriptions` | doctor + patient/calendar consultation |
| `routes/doctors.js:1301` | POST | `/api/doctor/forgetpwd` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/doctors.js:1368` | POST | `/api/doctor/forgetpwdresetpwd` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/doctors.js:1454` | POST | `/api/doctor/logout` | approved doctor/current database identity |
| `routes/patient_helpers.js:201` | POST | `/api/helper/register` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patient_helpers.js:294` | POST | `/api/helper/login` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patient_helpers.js:365` | POST | `/api/helper/add-patient` | helper/current database identity |
| `routes/patient_helpers.js:681` | GET | `/api/helper/get-patients` | helper/current database identity |
| `routes/patient_helpers.js:784` | POST | `/api/helper/change-password` | helper/current database identity |
| `routes/patient_helpers.js:898` | POST | `/api/helper/sendPhoneVerifyOTP` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patient_helpers.js:1058` | POST | `/api/helper/verifyPhoneOTP` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patient_helpers.js:1115` | POST | `/api/helper/sendEmailVerifyOTP` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patient_helpers.js:1201` | POST | `/api/helper/mis-info` | admin/current database identity |
| `routes/patient_helpers.js:1265` | POST | `/api/helper/verifyEmailOTP` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patient_helpers.js:1284` | POST | `/api/helper/medreport` | helper/current database identity |
| `routes/patient_helpers.js:1384` | GET | `/api/helper/medreports/:patient_id` | helper + assigned patient |
| `routes/patient_helpers.js:1427` | POST | `/api/helper/update-consent` | helper + assigned patient |
| `routes/patient_helpers.js:1497` | POST | `/api/helper/forgetpwd` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/patient_helpers.js:1562` | GET | `/api/helper/medreports/:patient_id/:id` | helper + assigned patient |
| `routes/patient_helpers.js:1571` | PUT | `/api/helper/medreport/:patient_id/:id` | helper + assigned patient/report |
| `routes/patient_helpers.js:1691` | DELETE | `/api/helper/medrecords/:id` | helper + assigned patient/report |
| `routes/patient_helpers.js:1708` | POST | `/api/helper/search` | helper/current database identity |
| `routes/patient_helpers.js:1740` | POST | `/api/helper/logout` | helper/current database identity |
| `routes/admin.js:87` | POST | `/api/admin/login` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/admin.js:143` | GET | `/api/admin/listdoctorstovalidate` | admin/current database identity |
| `routes/admin.js:167` | GET | `/api/admin/listhelpers` | admin/current database identity |
| `routes/admin.js:191` | GET | `/api/admin/listdoctors` | admin/current database identity |
| `routes/admin.js:215` | GET | `/api/admin/listdoctorspayments/:doctorId` | admin/current database identity |
| `routes/admin.js:245` | GET | `/api/admin/listdoctorsextras` | admin/current database identity |
| `routes/admin.js:270` | POST | `/api/admin/updateAmountPaidToDoc` | admin/current database identity |
| `routes/admin.js:290` | POST | `/api/admin/updateIfsc` | admin/current database identity |
| `routes/admin.js:310` | POST | `/api/admin/updateAcNo` | admin/current database identity |
| `routes/admin.js:330` | POST | `/api/admin/updateAcName` | admin/current database identity |
| `routes/admin.js:350` | POST | `/api/admin/updateBioDataUrl` | admin/current database identity |
| `routes/admin.js:370` | GET | `/api/admin/listpatients` | admin/current database identity |
| `routes/admin.js:394` | GET | `/api/admin/listpatientswithbookings` | admin/current database identity |
| `routes/admin.js:460` | POST | `/api/admin/validatedoc` | admin/current database identity |
| `routes/admin.js:506` | POST | `/api/admin/createNewDocType` | admin/current database identity |
| `routes/admin.js:553` | POST | `/api/admin/updateDocType` | admin/current database identity |
| `routes/admin.js:622` | POST | `/api/admin/deleteDocType` | admin/current database identity |
| `routes/admin.js:678` | GET | `/api/admin/getdoctorTypes` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/admin.js:704` | GET | `/api/admin/listdoctorTypes` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/admin.js:741` | GET | `/api/admin/listdoctorTypes/:date` | public / inline login, registration, verification, reset, contact or catalog |
| `routes/admin.js:782` | POST | `/api/admin/updatehelperforpatient` | admin/current database identity |
| `routes/admin.js:803` | POST | `/api/admin/logout` | admin/current database identity |

Total: 99 registered API routes, plus protected file delivery and public GET `/health`. The duplicate patient POST `/forgetpwd` registration is pre-existing; the first handler responds without calling next, so the second registration is unreachable. Its intended reset-flow cleanup is outside this change.
