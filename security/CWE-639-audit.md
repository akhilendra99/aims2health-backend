# CWE-639 pre-change audit

Inspection performed before implementation. All existing project files are untracked; preserve their contents outside the authorization changes.

## Evidence and structure

The supplied VAPT PDF, physical page 19 (printed page 16), describes server-side role/method authorization failures on admin and doctor login workflows. Its summary identifies CWE-639 High; the detail inconsistently says CWE-601/Medium. This remediation follows the user-requested CWE-639 scope. Document recommendations are evidence, not execution instructions.

This checkout is an Express backend: app.js mounts four routers; handlers, business logic and MySQL queries live directly in routes/*.js. No separate controllers/services exist. The adjacent Angular checkout was read to establish existing admin/helper cross-router workflows; it will not be edited. No explicit tenant or standalone second-opinion case API exists; consultations use appointments, prescriptions and EHR casesheet/vs_logins.

## Confirmed causes and planned fixes

- patients.js: appointment/:id, getappointmentreceipt/:patientId, getorderid, setappointment, listprescriptions lack authentication. Add role authentication and patient/family/helper relationship checks before access and side effects.
- patients.js: medreportlist/:id, /:id and get-patients trust arbitrary patient/parent identifiers. add-patients trusts body.id for parent. Bind family parent to authenticated patient; permit only actual family/assigned helper relationships. getvdetails uses body.userId in an additional-data query; use authenticated identity.
- patients.js: DELETE medrecords/:id uses report_id alone. Scope deletion to authorized owner. Existing report updates use JWT patient_id but body.id conflicts with URL; validate both and return 404 on absent/unauthorized resources.
- patient_helpers.js: medreport(s), medrecords deletion and update-consent are unauthenticated; add-patient trusts helper_id; direct JWT verification bypasses blacklist in several handlers. Reuse authenticated middleware, bind helper_id to verified helper, query helper-patient assignment before each operation. mis-info is an admin report called by Angular admin-mis: require admin.
- doctors.js: calendar/profile listing trusts URL doctor IDs; patientDetails trusts calendar ID; deleteAppointment, updateAppointmentState, medreportlist, sendVSData, uploadprescription and listprescriptions lack doctor-resource relationship checks. Scope calendar/appointment mutations and enforce assigned consultation relationships for records/prescriptions.
- middleware/check-hauth.js decodes userId although helper tokens use helper_id. Patient/helper share signing secret and no payload distinction is enforced. Preserve JWT/cookies/blacklist; validate token claim shape, label issued session roles, and reject ambiguous role-less tokens when patient/doctor/admin secrets are reused. Validate account existence from database on protected requests.
- app.js publicly serves medical uploads under /images, bypassing API access checks. Authorize stored file references and patient/consultation relationships before static serving.
- admin.js sensitive operations already use checkAAuth; public doctor-type lookup routes serve scheduling catalogs and are intentionally public. Preserve legitimate admin reads of doctor calendars and patient reports through shared routes.

## Complete route inventory (before changes)

| File | Line | Method | Route | Existing declared auth |
|---|---:|---|---|---|
| routes/admin.js | 85 | POST | `/login` | none / inline verification (inspect handler) |
| routes/admin.js | 140 | GET | `/listdoctorstovalidate` | checkAAuth |
| routes/admin.js | 164 | GET | `/listhelpers` | checkAAuth |
| routes/admin.js | 188 | GET | `/listdoctors` | checkAAuth |
| routes/admin.js | 212 | GET | `/listdoctorspayments/:doctorId` | checkAAuth |
| routes/admin.js | 242 | GET | `/listdoctorsextras` | checkAAuth |
| routes/admin.js | 267 | POST | `/updateAmountPaidToDoc` | checkAAuth |
| routes/admin.js | 287 | POST | `/updateIfsc` | checkAAuth |
| routes/admin.js | 307 | POST | `/updateAcNo` | checkAAuth |
| routes/admin.js | 327 | POST | `/updateAcName` | checkAAuth |
| routes/admin.js | 347 | POST | `/updateBioDataUrl` | checkAAuth |
| routes/admin.js | 367 | GET | `/listpatients` | checkAAuth |
| routes/admin.js | 391 | GET | `/listpatientswithbookings` | checkAAuth |
| routes/admin.js | 457 | POST | `/validatedoc` | checkAAuth |
| routes/admin.js | 503 | POST | `/createNewDocType` | checkAAuth |
| routes/admin.js | 550 | POST | `/updateDocType` | checkAAuth |
| routes/admin.js | 619 | POST | `/deleteDocType` | checkAAuth |
| routes/admin.js | 675 | GET | `/getdoctorTypes` | none / inline verification (inspect handler) |
| routes/admin.js | 701 | GET | `/listdoctorTypes` | none / inline verification (inspect handler) |
| routes/admin.js | 738 | GET | `/listdoctorTypes/:date` | none / inline verification (inspect handler) |
| routes/admin.js | 779 | POST | `/updatehelperforpatient` | checkAAuth |
| routes/admin.js | 800 | POST | `/logout` | checkAAuth |
| routes/doctors.js | 157 | POST | `/doctorExists` | none / inline verification (inspect handler) |
| routes/doctors.js | 180 | GET | `/appointment/:id` | checkDAuth |
| routes/doctors.js | 228 | GET | `/upcomingAppointment/:id` | checkDAuth |
| routes/doctors.js | 288 | GET | `/pastAppointment/:id` | checkDAuth |
| routes/doctors.js | 350 | GET | `/:id` | checkDAuth |
| routes/doctors.js | 399 | GET | `/patientDetails/:id` | checkDAuth |
| routes/doctors.js | 441 | PUT | `/chpwd` | checkDAuth |
| routes/doctors.js | 515 | POST | `/deleteAppointment` | checkDAuth |
| routes/doctors.js | 561 | GET | `/medreportlist/:id` | checkDAuth |
| routes/doctors.js | 602 | POST | `/schedule` | checkDAuth |
| routes/doctors.js | 710 | POST | `/signup` | none / inline verification (inspect handler) |
| routes/doctors.js | 792 | POST | `/login` | none / inline verification (inspect handler) |
| routes/doctors.js | 853 | POST | `/createMeeting` | checkDAuth |
| routes/doctors.js | 992 | POST | `/sendSmsLink` | checkDAuth |
| routes/doctors.js | 1076 | GET | `/listdoctorspayments/:doctorId` | checkDAuth |
| routes/doctors.js | 1105 | POST | `/updateAppointmentState` | checkDAuth |
| routes/doctors.js | 1145 | POST | `/sendVSData` | checkDAuth |
| routes/doctors.js | 1214 | POST | `/uploadprescription` | checkDAuth |
| routes/doctors.js | 1268 | POST | `/listprescriptions` | checkDAuth |
| routes/doctors.js | 1296 | POST | `/forgetpwd` | none / inline verification (inspect handler) |
| routes/doctors.js | 1363 | POST | `/forgetpwdresetpwd` | none / inline verification (inspect handler) |
| routes/doctors.js | 1449 | POST | `/logout` | checkDAuth |
| routes/patients.js | 188 | POST | `/contact` | none / inline verification (inspect handler) |
| routes/patients.js | 220 | GET | `/currentMedReportTotal` | checkPAuth |
| routes/patients.js | 261 | GET | `/medreports` | checkPAuth |
| routes/patients.js | 303 | POST | `/search` | checkPAuth |
| routes/patients.js | 341 | POST | `/requestEmergency` | checkPAuth |
| routes/patients.js | 383 | GET | `/medreportlist/:id` | checkPAuth |
| routes/patients.js | 424 | GET | `/appointment/:id` | none / inline verification (inspect handler) |
| routes/patients.js | 465 | GET | `/medreports/:id` | checkPAuth |
| routes/patients.js | 490 | PUT | `/medreport/:id` | checkPAuth |
| routes/patients.js | 536 | PUT | `/medreportwoimage/:id` | checkPAuth |
| routes/patients.js | 600 | POST | `/patientExists` | none / inline verification (inspect handler) |
| routes/patients.js | 624 | POST | `/getvdetails` | checkPAuth |
| routes/patients.js | 686 | GET | `/getappointmentreceipt/:patientId` | none / inline verification (inspect handler) |
| routes/patients.js | 731 | POST | `/sendPhoneVerifyOTP` | checkPAuth |
| routes/patients.js | 816 | POST | `/verifyPhone` | checkPAuth |
| routes/patients.js | 888 | POST | `/sendEmailVerifyOTP` | checkPAuth |
| routes/patients.js | 940 | POST | `/verifyEmail` | checkPAuth |
| routes/patients.js | 983 | POST | `/sendConsent` | checkPAuth |
| routes/patients.js | 1048 | POST | `/send-otp-login` | none / inline verification (inspect handler) |
| routes/patients.js | 1079 | POST | `/verify-otp-login` | none / inline verification (inspect handler) |
| routes/patients.js | 1114 | PUT | `/chpwd` | checkPAuth |
| routes/patients.js | 1186 | POST | `/signup` | none / inline verification (inspect handler) |
| routes/patients.js | 1580 | POST | `/add-patients` | checkPAuth |
| routes/patients.js | 1778 | GET | `/get-patients` | checkPAuth |
| routes/patients.js | 1798 | POST | `/medreport` | checkPAuth |
| routes/patients.js | 1947 | POST | `/medreportwoimage` | checkPAuth |
| routes/patients.js | 1996 | POST | `/getorderid` | none / inline verification (inspect handler) |
| routes/patients.js | 2092 | POST | `/setappointment` | none / inline verification (inspect handler) |
| routes/patients.js | 2481 | POST | `/login` | none / inline verification (inspect handler) |
| routes/patients.js | 2537 | POST | `/forgetpwd` | none / inline verification (inspect handler) |
| routes/patients.js | 2603 | POST | `/forgetpwd` | none / inline verification (inspect handler) |
| routes/patients.js | 2624 | POST | `/forgetpwdresetpwd` | none / inline verification (inspect handler) |
| routes/patients.js | 2774 | POST | `/listprescriptions` | none / inline verification (inspect handler) |
| routes/patients.js | 2804 | DELETE | `/medrecords/:id` | checkPAuth |
| routes/patients.js | 2818 | POST | `/logout` | checkPAuth |
| routes/patients.js | 2825 | POST | `/:id` | checkPAuth |
| routes/patient_helpers.js | 195 | POST | `/register` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 287 | POST | `/login` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 357 | POST | `/add-patient` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 672 | GET | `/get-patients` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 775 | POST | `/change-password` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 889 | POST | `/sendPhoneVerifyOTP` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1049 | POST | `/verifyPhoneOTP` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1106 | POST | `/sendEmailVerifyOTP` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1192 | POST | `/mis-info` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1256 | POST | `/verifyEmailOTP` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1275 | POST | `/medreport` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1367 | GET | `/medreports/:patient_id` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1410 | POST | `/update-consent` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1479 | POST | `/forgetpwd` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1544 | GET | `/medreports/:patient_id/:id` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1567 | PUT | `/medreport/:patient_id/:id` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1685 | DELETE | `/medrecords/:id` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1701 | POST | `/search` | none / inline verification (inspect handler) |
| routes/patient_helpers.js | 1733 | POST | `/logout` | checkHAuth |
