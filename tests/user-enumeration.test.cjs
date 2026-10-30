const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const root = path.resolve(__dirname, "..");
const knownEmail = "existing-user@test.invalid";
const knownPhone = "5551234567";

function makeDatabase(users) {
  const calls = [];
  const loginLockoutRows = new Map();
  let databaseNow = Date.now();
  let failLoginLockoutStore = false;
  users.createdPatients = [];
  async function rowsFor(sql, values = []) {
    calls.push({ sql, values });
    const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
    const value = values[0];
    if (normalized.includes("login_lockout_state") && failLoginLockoutStore) {
      throw new Error("fixture lockout store failure");
    }
    if (normalized.startsWith("insert into patient_details")) {
      const created = { patient_id: 2, helper_id: values[0], email_id: values[13], hashed_pwd: values[14] };
      users.createdPatients.push(created);
      return { insertId: created.patient_id, affectedRows: 1 };
    }
    if (normalized.startsWith("insert into patient_additional")) return { affectedRows: 1 };
    if (normalized.startsWith("select lock_key from login_lockout_state")) {
      return values.filter(key => (loginLockoutRows.get(key)?.lockedUntil || 0) > databaseNow).map(lock_key => ({ lock_key }));
    }
    if (normalized.startsWith("insert into login_lockout_state")) {
      const [key, retentionSeconds, windowSeconds, threshold, lockSeconds] = values;
      const previous = loginLockoutRows.get(key);
      if (!previous) {
        loginLockoutRows.set(key, {
          windowStartedAt: databaseNow,
          failedAttempts: 1,
          lockedUntil: 0,
          expiresAt: databaseNow + retentionSeconds * 1000,
        });
      } else if (previous.lockedUntil <= databaseNow) {
        if (previous.windowStartedAt <= databaseNow - windowSeconds * 1000) {
          previous.windowStartedAt = databaseNow;
          previous.failedAttempts = 1;
          previous.lockedUntil = 0;
        } else {
          previous.failedAttempts += 1;
          if (previous.failedAttempts >= threshold) previous.lockedUntil = databaseNow + lockSeconds * 1000;
        }
        previous.expiresAt = databaseNow + retentionSeconds * 1000;
      }
      return { affectedRows: 1 };
    }
    if (normalized.startsWith("delete from login_lockout_state where lock_key in")) {
      let affectedRows = 0;
      for (const key of values) affectedRows += loginLockoutRows.delete(key) ? 1 : 0;
      return { affectedRows };
    }
    if (normalized.startsWith("delete from login_lockout_state where expires_at")) {
      for (const [key, row] of loginLockoutRows) if (row.expiresAt <= databaseNow) loginLockoutRows.delete(key);
      return { affectedRows: 0 };
    }
    if (normalized.startsWith("select crno from pt_key")) return [{ crno: 100 }];
    if (normalized === "select 1") return [{ ok: 1 }];
    if (normalized.includes("from helper_details") && normalized.includes("where mobile = ?")) {
      return value === knownPhone ? [users.helper] : [];
    }
    if (normalized.includes("from helper_details") && normalized.includes("where lower(email_id) = ?")) {
      return String(value).toLowerCase() === knownEmail ? [users.helper] : [];
    }
    if (normalized.includes("from helper_details") && normalized.includes("where email_id = ?")) {
      return value === knownEmail ? [users.helper] : [];
    }
    if (normalized.includes("from helper_details") && normalized.includes("where helper_id = ?")) {
      return String(value) === "1" ? [users.helper] : [];
    }
    if (normalized.includes("from patient_details") && normalized.includes("where patient_id")) {
      return String(value) === String(users.patient.patient_id) ? [users.patient] : [];
    }
    if (normalized.includes("from patient_details") && normalized.includes("where email_id")) {
      return value === knownEmail ? [users.patient] : [];
    }
    if (normalized.includes("from doctor_details") && normalized.includes("where email_id")) {
      if (value === "pending-user@test.invalid") return [users.pendingDoctor];
      return value === knownEmail ? [users.doctor] : [];
    }
    if (normalized.includes("from admin_details") && normalized.includes("where email_id")) {
      return value === knownEmail ? [users.admin] : [];
    }
    if (normalized.includes("from doctor_details") && normalized.includes("where doctor_id")) {
      return String(value) === "1" ? [users.doctor] : [];
    }
    if (normalized.startsWith("insert into doctor_details")) return { insertId: 8, affectedRows: 1 };
    if (normalized.startsWith("update patient_details set hashed_pwd = ? where patient_id = ?")) {
      users.patient.hashed_pwd = values[0];
      return { affectedRows: 1 };
    }
    if (normalized.startsWith("update helper_details set hashed_pwd = ? where helper_id = ?")) {
      users.helper.hashed_pwd = values[0];
      return { affectedRows: 1 };
    }
    if (normalized.startsWith("update doctor_details set adhaar")) {
      users.doctor.createdHash = values[2];
      return { affectedRows: 1 };
    }
    if (normalized.startsWith("update doctor_details set hashed_pwd = ?")) {
      users.doctor.hashed_pwd = values[0];
      return { affectedRows: 1 };
    }
    if (normalized.startsWith("update doctor_details")) return { affectedRows: 1 };
    return [];
  }
  const callbackConnection = {
    connect(callback) { callback(null); },
    query(sql, values, callback) {
      if (typeof values === "function") { callback = values; values = []; }
      rowsFor(sql, values).then(result => callback(null, result, []), callback);
    },
  };
  const promiseConnection = {
    async query(sql, values = []) { return [await rowsFor(sql, values), []]; },
    async getConnection() { return { query: async () => [[], []], release() {}, beginTransaction: async () => {}, commit: async () => {}, rollback: async () => {} }; },
  };
  return {
    calls,
    advanceTime: milliseconds => { databaseNow += milliseconds; },
    setLoginLockoutFailure: value => { failLoginLockoutStore = value; },
    mysql: {
      createConnection: () => callbackConnection,
      createPool: () => ({ promise: () => promiseConnection }),
    },
  };
}

function loadRouter(relative, overrides) {
  const filename = path.join(root, relative);
  const localRequire = createRequire(filename);
  const module = { exports: {} };
  const context = {
    module,
    exports: module.exports,
    require: id => Object.hasOwn(overrides, id) ? overrides[id] : localRequire(id),
    __dirname: path.dirname(filename),
    __filename: filename,
    process,
    Buffer,
    console: { log() {}, error() {}, warn() {} },
    setTimeout,
    clearTimeout,
    URL,
  };
  vm.runInNewContext(`(function(exports,require,module,__filename,__dirname){${fs.readFileSync(filename, "utf8")}\n})`, context, { filename })(module.exports, context.require, module, filename, path.dirname(filename));
  return module.exports;
}

async function serve(app, run) {
  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const request = async (method, route, body, options = {}) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`, {
      method,
      headers: { ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...(options.headers || {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
    const text = await response.text();
    const result = { status: response.status, body: text ? JSON.parse(text) : null };
    if (options.includeHeaders) result.headers = response.headers;
    return result;
  };
  try { await run(request); }
  finally {
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(resolve));
  }
}

test("login, recovery, existence checks, and registration responses do not disclose account state", async t => {
  const envKeys = ["JWT_SECRET_PATIENT", "JWT_SECRET_DOC", "JWT_SECRET_ADMIN", "LOGIN_LOCKOUT_SECRET", "FRONTEND_URL", "EHR_CONNECT", "COOKIE_SECURE", "COOKIE_DOMAIN"];
  const previous = envKeys.map(key => process.env[key]);
  process.env.JWT_SECRET_PATIENT = "enum-test-patient-secret";
  process.env.JWT_SECRET_DOC = "enum-test-doctor-secret";
  process.env.JWT_SECRET_ADMIN = "enum-test-admin-secret";
  process.env.LOGIN_LOCKOUT_SECRET = "user-enumeration-lockout-secret-fixture-2026";
  process.env.FRONTEND_URL = "https://frontend.test.invalid";
  process.env.EHR_CONNECT = "false";
  process.env.COOKIE_SECURE = "true";
  delete process.env.COOKIE_DOMAIN;
  t.after(() => envKeys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));

  const helperHash = await bcrypt.hash("ValidPass1!", 12);
  const standardHash = await bcrypt.hash("ValidPass1!", 11);
  const users = {
    helper: { helper_id: 1, email_id: knownEmail, mobile: knownPhone, hashed_pwd: helperHash },
    patient: { patient_id: 1, email_id: knownEmail, fname: "Test", lname: "Patient", hashed_pwd: standardHash },
    doctor: { doctor_id: 1, email_id: knownEmail, fname: "Test", lname: "Doctor", validated: 1, hashed_pwd: standardHash },
    pendingDoctor: { doctor_id: 2, email_id: "pending-user@test.invalid", validated: 0, hashed_pwd: standardHash },
    admin: { admin_id: 1, email_id: knownEmail, hashed_pwd: standardHash },
  };
  const database = makeDatabase(users);
  const mails = [];
  const sms = [];
  const axios = { post: async (url, payload) => {
    if (url.includes("/sms-api/")) sms.push(payload);
    return { data: { status: "Accepted" } };
  } };
  const sendgrid = { setApiKey() {}, send: async message => { mails.push({ channel: "sendgrid", ...message }); } };
  const common = {
    mysql2: database.mysql,
    axios,
    twilio: () => ({ messages: { create: async () => ({}) } }),
    Razorpay: function Razorpay() { this.orders = {}; },
    "@sendgrid/mail": sendgrid,
    "../utils/zeptomail": { sendMail: async message => { mails.push({ channel: "zeptomail", ...message }); } },
    needle: { post: async () => ({ body: {} }) },
    "fix-esm": { require: () => async () => ({}) },
  };
  const routers = {
    helper: loadRouter("routes/patient_helpers.js", common),
    patient: loadRouter("routes/patients.js", common),
    doctor: loadRouter("routes/doctors.js", common),
    admin: loadRouter("routes/admin.js", common),
  };
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(require("cookie-parser")());
  const csrf = require("../middleware/csrf-protection");
  app.use(csrf.requireTrustedOrigin(["http://localhost:4200"]));
  app.use(csrf.requireCsrfToken);
  for (const [prefix, router] of Object.entries(routers)) app.use(`/api/${prefix}`, router);

  await serve(app, async request => {
    const loginCases = [
      ["helper", { email_id: knownEmail, password: "WrongPass1!" }, { email_id: "missing@test.invalid", password: "WrongPass1!" }],
      ["patient", { email: knownEmail, password: "WrongPass1!" }, { email: "missing@test.invalid", password: "WrongPass1!" }],
      ["doctor", { email: knownEmail, password: "WrongPass1!" }, { email: "missing@test.invalid", password: "WrongPass1!" }],
      ["admin", { email: knownEmail, password: "WrongPass1!" }, { email: "missing@test.invalid", password: "WrongPass1!" }],
    ];
    for (const [role, wrongPassword, missingAccount] of loginCases) {
      const base = `/api/${role}/login`;
      const wrong = await request("POST", base, wrongPassword);
      const absent = await request("POST", base, missingAccount);
      assert.equal(wrong.status, 401, `${role} wrong password status`);
      assert.deepEqual(absent, wrong, `${role} missing and wrong password responses match`);
      assert.deepEqual(wrong.body, { message: "Invalid Authentication Credentials!" });

      const goodBody = role === "helper"
        ? { email_id: knownEmail, password: "ValidPass1!" }
        : { email: knownEmail, password: "ValidPass1!" };
      const success = await request("POST", base, goodBody, { includeHeaders: ["patient", "doctor", "helper", "admin"].includes(role) });
      assert.equal(success.status, 200, `${role} successful login remains intact`);
      if (role === "patient") {
        assert.deepEqual(success.body, {
          expiresIn: 3600, userId: 1, userEmail: knownEmail, userName: "Test Patient",
        });
        assert.equal(success.body.token, undefined, "patient password login does not return its JWT in JSON");
        const cookies = success.headers.getSetCookie();
        const authCookie = cookies.find(cookie => cookie.startsWith("auth_token="));
        const csrfCookie = cookies.find(cookie => cookie.startsWith("csrf_token="));
        assert.ok(authCookie, "patient login sets the auth cookie");
        assert.ok(csrfCookie, "patient login sets the CSRF cookie");
        assert.match(authCookie, /; HttpOnly/i);
        assert.match(authCookie, /; Secure/i);
        assert.match(authCookie, /; SameSite=Lax/i);
        assert.doesNotMatch(csrfCookie, /; HttpOnly/i);
        assert.match(csrfCookie, /; Secure/i);
        assert.match(csrfCookie, /; SameSite=Lax/i);
        const cookieToken = authCookie.match(/^auth_token=([^;]+)/)?.[1];
        const patientClaims = jwt.verify(cookieToken, process.env.JWT_SECRET_PATIENT);
        assert.equal(patientClaims.role, "patient");
        assert.equal(patientClaims.userId, 1);
        const csrfTokenValue = csrfCookie.match(/^csrf_token=([^;]+)/)[1];
        const cookieHeader = "auth_token=" + cookieToken + "; csrf_token=" + csrfTokenValue;
        const blockedLogout = await request("POST", "/api/patient/logout", {}, { headers: { Cookie: cookieHeader } });
        assert.equal(blockedLogout.status, 403, "cookie-authenticated logout requires a CSRF header");
        const logout = await request("POST", "/api/patient/logout", {}, {
          includeHeaders: true,
          headers: { Cookie: cookieHeader, "x-csrf-token": csrfTokenValue },
        });
        assert.equal(logout.status, 200);
        assert.match(logout.headers.get("set-cookie") || "", /auth_token=;/);
        assert.match(logout.headers.get("set-cookie") || "", /csrf_token=;/);
        const afterLogout = await request("GET", "/api/patient/get-patients?id=1", undefined, {
          headers: { Cookie: "auth_token=" + cookieToken },
        });
        assert.equal(afterLogout.status, 401, "logout revokes the cookie-issued patient token");
      } else if (role === "admin") {
        assert.equal(success.body.token, undefined, "admin JWT is not exposed in JavaScript-readable JSON");
        assert.equal(success.body.userId, 1, "admin UI identity contract remains intact");
        const authCookie = success.headers.getSetCookie().find(value => value.startsWith("auth_token="));
        assert.ok(authCookie, "admin login still issues an HttpOnly authentication cookie");
        assert.match(authCookie, /; HttpOnly/i);
      } else if (role === "doctor") {
        assert.equal(success.body.token, undefined, "doctor JWT is not exposed in JavaScript-readable JSON");
        assert.equal(success.body.userId, 1);
        assert.equal(success.body.userEmail, knownEmail);
        assert.equal(success.body.userName, "Test Doctor");
        const authCookie = success.headers.getSetCookie().find(value => value.startsWith("auth_token="));
        assert.ok(authCookie, "doctor login still sets its HttpOnly authentication cookie");
        assert.match(authCookie, /; HttpOnly/i);
      } else if (role === "helper") {
        assert.equal(success.body.token, undefined, "helper JWT is not exposed in JavaScript-readable JSON");
        assert.deepEqual(success.body.user, {
          helper_id: 1, email_id: knownEmail, mobile: knownPhone,
        }, "helper profile response remains compatible with current Angular login");
        const authCookie = success.headers.getSetCookie().find(value => value.startsWith("auth_token="));
        assert.ok(authCookie, "helper login still sets its HttpOnly authentication cookie");
        assert.match(authCookie, /; HttpOnly/i);
      } else {
        assert.ok(success.body.token, `${role} successful login still issues a token`);
      }
    }

    for (let attempt = 0; attempt < 4; attempt++) {
      const failed = await request("POST", "/api/patient/login", { email: knownEmail, password: "WrongPass1!" });
      assert.equal(failed.status, 401);
    }
    const resetBySuccess = await request("POST", "/api/patient/login", { email: knownEmail, password: "ValidPass1!" });
    assert.equal(resetBySuccess.status, 200, "successful login clears identifier/account failures");
    for (let attempt = 0; attempt < 5; attempt++) {
      const failed = await request("POST", "/api/patient/login", { email: knownEmail, password: "WrongPass1!" }, {
        headers: { "X-Forwarded-For": `192.0.2.${attempt + 1}` },
      });
      assert.deepEqual(failed, { status: 401, body: { message: "Invalid Authentication Credentials!" } });
    }
    const crossRoleLock = await request("POST", "/api/doctor/login", { email: knownEmail, password: "ValidPass1!" }, {
      headers: { "X-Forwarded-For": "198.51.100.44" },
    });
    assert.deepEqual(crossRoleLock, { status: 401, body: { message: "Invalid Authentication Credentials!" } },
      "identifier lockout applies through alternate role login endpoints");
    database.advanceTime(15 * 60 * 1000 + 1);
    const afterExpiry = await request("POST", "/api/patient/login", { email: knownEmail, password: "ValidPass1!" });
    assert.equal(afterExpiry.status, 200, "temporary lockout expires and successful login works again");

    for (let attempt = 0; attempt < 5; attempt++) {
      const failed = await request("POST", "/api/helper/login", { phone_no: knownPhone, password: "WrongPass1!" });
      assert.equal(failed.status, 401);
    }
    const helperAliasLock = await request("POST", "/api/helper/login", { email_id: knownEmail, password: "ValidPass1!" });
    assert.deepEqual(helperAliasLock, { status: 401, body: { message: "Invalid Authentication Credentials!" } },
      "helper email and phone aliases share server-resolved account state");
    database.advanceTime(15 * 60 * 1000 + 1);
    const helperAfterExpiry = await request("POST", "/api/helper/login", { email_id: knownEmail, password: "ValidPass1!" });
    assert.equal(helperAfterExpiry.status, 200);

    const weakSignupCases = [
      ["/api/helper/register", { email_id: "new-user@test.invalid", password: "Weak123" }],
      ["/api/patient/signup", { password: "Weak123" }],
      ["/api/doctor/signup", { password: "Weak123" }],
    ];
    const beforeWeakSignups = database.calls.length;
    for (const [route, body] of weakSignupCases) {
      const result = await request("POST", route, body);
      assert.equal(result.status, 400, `${route} rejects a weak password`);
      assert.match(result.body.message, /8-12 ASCII characters/);
    }
    assert.equal(database.calls.length, beforeWeakSignups, "weak signup input is rejected before database work");

    const patientSession = jwt.sign({ userId: 1, role: "patient", email: knownEmail }, process.env.JWT_SECRET_PATIENT, { expiresIn: "1h" });
    const doctorSession = jwt.sign({ userId: 1, role: "doctor", email: knownEmail }, process.env.JWT_SECRET_DOC, { expiresIn: "1h" });
    const helperSession = jwt.sign({ helper_id: 1, role: "helper", email_id: knownEmail }, process.env.JWT_SECRET_PATIENT, { expiresIn: "1h" });
    const weakChangeCases = [
      ["PUT", "/api/patient/chpwd", patientSession, { oldpwd: "ValidPass1!", newpwd: "Weak123" }],
      ["PUT", "/api/doctor/chpwd", doctorSession, { oldpwd: "ValidPass1!", newpwd: "Weak123" }],
      ["POST", "/api/helper/change-password", helperSession, { oldPassword: "ValidPass1!", newPassword: "Weak123", confirmPassword: "Weak123" }],
    ];
    for (const [method, route, token, body] of weakChangeCases) {
      const result = await request(method, route, body, { headers: { Authorization: `Bearer ${token}` } });
      assert.equal(result.status, 400, `${route} rejects a weak new password`);
    }
    const currentPasswordCases = [
      ["PUT", "/api/patient/chpwd", patientSession, { oldpwd: "WrongOld1!", newpwd: "Change1!" }],
      ["PUT", "/api/doctor/chpwd", doctorSession, { oldpwd: "WrongOld1!", newpwd: "Change1!" }],
      ["POST", "/api/helper/change-password", helperSession, { oldPassword: "WrongOld1!", newPassword: "Change1!", confirmPassword: "Change1!" }],
    ];
    for (const [method, route, token, body] of currentPasswordCases) {
      const result = await request(method, route, body, { headers: { Authorization: `Bearer ${token}` } });
      assert.ok(result.status === 401 || result.status === 500, `${route} requires the current password`);
    }
    const validPasswordChanges = [
      ["PUT", "/api/patient/chpwd", patientSession, { oldpwd: "ValidPass1!", newpwd: "Change1!" }],
      ["PUT", "/api/doctor/chpwd", doctorSession, { oldpwd: "ValidPass1!", newpwd: "Change1!" }],
      ["POST", "/api/helper/change-password", helperSession, { oldPassword: "ValidPass1!", newPassword: "Change1!", confirmPassword: "Change1!" }],
    ];
    for (const [method, route, token, body] of validPasswordChanges) {
      const result = await request(method, route, body, { headers: { Authorization: `Bearer ${token}` } });
      assert.ok(result.status === 200 || result.status === 201, `${route} accepts a valid change with the current password`);
    }
    const wrongRolePasswordChange = await request("PUT", "/api/patient/chpwd", {
      oldpwd: "Change1!", newpwd: "Change2!",
    }, { headers: { Authorization: `Bearer ${helperSession}` } });
    assert.ok(wrongRolePasswordChange.status === 401 || wrongRolePasswordChange.status === 403,
      "a helper token cannot change a patient password");
    for (const account of [users.patient, users.doctor, users.helper]) {
      assert.equal(await bcrypt.compare("Change1!", account.hashed_pwd), true, "password changes store bcrypt hashes");
    }
    const weakHelperPatientPassword = await request("POST", "/api/helper/add-patient", {
      fname: "Fixture", lname: "Patient", gender: "Other", medical_history: "Fixture",
      mobile_no: "5551234567", address: "123456", dob: "1990-01-01", password: "Weak123",
    }, { headers: { Authorization: `Bearer ${helperSession}` } });
    assert.equal(weakHelperPatientPassword.status, 400, "helper-created patient weak password is rejected");
    const weakPatientCreatedPassword = await request("POST", "/api/patient/add-patients", {
      password: "Weak123",
    }, { headers: { Authorization: `Bearer ${patientSession}` } });
    assert.equal(weakPatientCreatedPassword.status, 400, "patient-created family weak password is rejected");
    const pendingDoctor = await request("POST", "/api/doctor/login", {
      email: "pending-user@test.invalid", password: "ValidPass1!",
    });
    assert.deepEqual(pendingDoctor, {
      status: 401,
      body: { message: "Invalid Authentication Credentials!" },
    }, "doctor approval state is not disclosed");

    for (const route of ["/api/helper/forgetpwd", "/api/patient/forgetpwd", "/api/doctor/forgetpwd"]) {
      const body = route.includes("helper") ? { email: knownEmail } : { email: knownEmail };
      const existing = await request("POST", route, body);
      const absent = await request("POST", route, { email: "missing@test.invalid" });
      assert.deepEqual(existing, absent, `${route} known and unknown account response matches`);
      assert.equal(existing.status, 200);
      assert.match(existing.body.message, /If the account is eligible/);
      assert.equal(existing.body.token, undefined, "recovery token is never returned publicly");
    }

    const doctorMail = mails.find(message => message.channel === "sendgrid" && message.subject === "Virtual Sathi Login Password Reset");
    const doctorToken = doctorMail?.text.match(/dresetpwd\/1\/([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/)?.[1];
    assert.ok(doctorToken, "doctor reset token is sent only in the recovery email");
    const beforeWeakResetRequests = database.calls.length;
    const weakDoctorReset = await request("POST", "/api/doctor/forgetpwdresetpwd", {
      doc_id: 1, token: doctorToken, password: "Weak123",
    });
    const weakPatientReset = await request("POST", "/api/patient/forgetpwdresetpwd", {
      patient_id: 1, token: "malformed", password: "Weak123",
    });
    const weakHelperReset = await request("POST", "/api/patient/forgetpwdresetpwd", {
      patient_id: 1, token: "malformed", password: "Weak123",
    });
    for (const result of [weakDoctorReset, weakPatientReset, weakHelperReset]) {
      assert.equal(result.status, 400);
      assert.match(result.body.message, /8-12 ASCII characters/);
    }
    assert.equal(database.calls.length, beforeWeakResetRequests, "weak reset passwords are rejected before account lookup");
    const doctorReset = await request("POST", "/api/doctor/forgetpwdresetpwd", {
      doc_id: 1, token: doctorToken, password: "Doctor1!",
    });
    assert.equal(doctorReset.status, 201);
    assert.notEqual(users.doctor.hashed_pwd, "Doctor1!");
    assert.equal(await bcrypt.compare("Doctor1!", users.doctor.hashed_pwd), true);

    // Exercise actual email-issued patient and helper links against the shared
    // reset endpoint, ensuring each updates only its own account table.
    const patientMail = mails.find(message => message.channel === "sendgrid" && message.to === knownEmail);
    assert.ok(patientMail, "patient recovery email is generated by the patient route");
    const patientToken = patientMail.text.match(/presetpwd\/1\/([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/)?.[1];
    assert.ok(patientToken, "patient reset token is present only in the email link");
    const helperMail = mails.find(message => message.channel === "zeptomail" && message.toName === "Helper");
    assert.ok(helperMail, "helper recovery email is generated by the helper route");
    const helperToken = helperMail.text.match(/presetpwd\/1\/([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/)?.[1];
    assert.ok(helperToken, "helper reset token is present only in the email link");
    const initialPatientHash = users.patient.hashed_pwd;
    const initialHelperHash = users.helper.hashed_pwd;
    const resetSecret = process.env.JWT_SECRET_PATIENT;
    const patientTokenClaimingHelperRole = jwt.sign(
      { email: knownEmail, userId: 1, role: "helper" },
      resetSecret + users.patient.email_id + initialPatientHash,
      { expiresIn: "10m" },
    );
    const helperTokenClaimingPatientRole = jwt.sign(
      { email: knownEmail, userId: 1, role: "patient" },
      resetSecret + users.helper.email_id + initialHelperHash,
      { expiresIn: "10m" },
    );
    const expiredToken = jwt.sign(
      { email: knownEmail, userId: 1, role: "patient" },
      resetSecret + users.patient.email_id + initialPatientHash,
      { expiresIn: -1 },
    );
    const [header, payload] = patientToken.split(".");
    const modifiedClaims = { ...JSON.parse(Buffer.from(payload, "base64url").toString("utf8")), email: "changed@test.invalid" };
    const tamperedToken = [header, Buffer.from(JSON.stringify(modifiedClaims)).toString("base64url"), patientToken.split(".")[2]].join(".");
    const failedTokens = [
      { patient_id: 1, token: patientTokenClaimingHelperRole },
      { patient_id: 1, token: helperTokenClaimingPatientRole },
      { patient_id: 2, token: patientToken },
      { patient_id: 1, token: "malformed" },
      { patient_id: 1, token: expiredToken },
      { patient_id: 1, token: tamperedToken },
    ];
    for (const failed of failedTokens) {
      const rejected = await request("POST", "/api/patient/forgetpwdresetpwd", {
        ...failed, password: "NoApply1!",
      });
      assert.deepEqual(rejected, { status: 401, body: { message: "Invalid or expired reset link." } });
      assert.equal(rejected.body.token, undefined);
      assert.equal(rejected.body.password, undefined);
    }
    assert.equal(users.patient.hashed_pwd, initialPatientHash, "all invalid/cross-role tokens leave the patient unchanged");
    assert.equal(users.helper.hashed_pwd, initialHelperHash, "all invalid/cross-role tokens leave the helper unchanged");

    const patientReset = await request("POST", "/api/patient/forgetpwdresetpwd", {
      patient_id: 1, token: patientToken, password: "Patient1!",
    });
    assert.equal(patientReset.status, 201);
    assert.deepEqual(patientReset.body, { message: "Password updated successfully." });
    assert.notEqual(users.patient.hashed_pwd, "PatientNewPass1!", "patient password is stored as a hash");
    assert.equal(await bcrypt.compare("Patient1!", users.patient.hashed_pwd), true);
    assert.equal(users.helper.hashed_pwd, initialHelperHash, "patient reset never updates helper credentials");

    const patientHashAfterReset = users.patient.hashed_pwd;
    const patientTokenReuse = await request("POST", "/api/patient/forgetpwdresetpwd", {
      patient_id: 1, token: patientToken, password: "Patient2!",
    });
    assert.deepEqual(patientTokenReuse, { status: 401, body: { message: "Invalid or expired reset link." } });
    assert.equal(users.patient.hashed_pwd, patientHashAfterReset, "patient reset tokens are single-use after the hash changes");

    const helperReset = await request("POST", "/api/patient/forgetpwdresetpwd", {
      patient_id: 1, token: helperToken, password: "Helper1!",
    });
    assert.equal(helperReset.status, 201, "shared UI and endpoint preserve helper reset compatibility");
    assert.deepEqual(helperReset.body, { message: "Password updated successfully." });
    assert.notEqual(users.helper.hashed_pwd, "HelperNewPass1!", "helper password is stored as a hash");
    assert.equal(await bcrypt.compare("Helper1!", users.helper.hashed_pwd), true);
    assert.equal(users.patient.hashed_pwd, patientHashAfterReset, "helper reset never updates patient credentials");

    const helperHashAfterReset = users.helper.hashed_pwd;
    const helperTokenReuse = await request("POST", "/api/patient/forgetpwdresetpwd", {
      patient_id: 1, token: helperToken, password: "Helper2!",
    });
    assert.deepEqual(helperTokenReuse, { status: 401, body: { message: "Invalid or expired reset link." } });
    assert.equal(users.helper.hashed_pwd, helperHashAfterReset, "helper reset tokens are single-use after the hash changes");

    for (const route of ["/api/patient/patientExists", "/api/doctor/doctorExists"]) {
      const existing = await request("POST", route, { email: knownEmail });
      const absent = await request("POST", route, { email: "missing@test.invalid" });
      assert.deepEqual(existing, absent, `${route} returns no account-specific boolean`);
      assert.equal(existing.body.message, "Continue registration if eligible.");
    }

    const doctorBadReset = await request("POST", "/api/doctor/forgetpwdresetpwd", {
      doc_id: 1, token: "malformed", password: "NewPass1!",
    });
    const doctorMissingReset = await request("POST", "/api/doctor/forgetpwdresetpwd", {
      doc_id: 999, token: "malformed", password: "NewPass1!",
    });
    assert.deepEqual(doctorBadReset, doctorMissingReset);
    const helperBadReset = await request("POST", "/api/patient/forgetpwdresetpwd", {
      patient_id: 1, token: "malformed", password: "NewPass1!",
    });
    const helperMissingReset = await request("POST", "/api/patient/forgetpwdresetpwd", {
      patient_id: 999, token: "malformed", password: "NewPass1!",
    });
    assert.deepEqual(helperBadReset, helperMissingReset);

    const duplicateDoctor = await request("POST", "/api/doctor/signup", {
      email: knownEmail, mobile_no: knownPhone, password: "ValidPass1!",
    });
    assert.equal(duplicateDoctor.status, 401);
    assert.doesNotMatch(duplicateDoctor.body.message, /exist|registered|already/i);

    const validDoctorSignup = await request("POST", "/api/doctor/signup", {
      email: "new-doctor@test.invalid", password: "Doctor1!", mobile_no: "5557654329",
    });
    assert.equal(validDoctorSignup.status, 201);
    assert.notEqual(users.doctor.createdHash, "Doctor1!");
    assert.equal(await bcrypt.compare("Doctor1!", users.doctor.createdHash), true);

    const duplicatePatient = await request("POST", "/api/patient/signup", {
      fname: "Test", lname: "Patient", email: knownEmail, password: "ValidPass1!",
      mobile_no: knownPhone, mobile_secondary: "5551112222", gender: "other",
      address: "City 123456", dob: "1990-01-01", countrycode: "1", medical_history: "Fixture",
    });
    assert.equal(duplicatePatient.status, 401);
    assert.doesNotMatch(duplicatePatient.body.message, /exist|registered|already/i);

    const validPatientSignup = await request("POST", "/api/patient/signup", {
      fname: "New", lname: "Patient", email: "new-patient@test.invalid", password: "ValidPass1!",
      mobile_no: "5557654321", mobile_secondary: "5557654322", gender: "other",
      address: "City 123456", dob: "1990-01-01", countrycode: "1",
      medical_history: "Fixture", idType: "Other", idNumber: "ID-123", abhaId: "",
    });
    assert.equal(validPatientSignup.status, 201);
    assert.deepEqual(validPatientSignup.body, { message: "Patient added successfully" });
    assert.equal(users.createdPatients.length, 1);
    assert.equal(users.createdPatients[0].helper_id, -1, "patient self-signup creates an unassigned patient record");
    assert.equal(users.createdPatients[0].email_id, "new-patient@test.invalid");
    assert.notEqual(users.createdPatients[0].hashed_pwd, "ValidPass1!", "patient password is not stored in plaintext");
    assert.equal(await bcrypt.compare("ValidPass1!", users.createdPatients[0].hashed_pwd), true);
    assert.equal(database.calls.some(call => call.sql.toLowerCase().startsWith("insert into helper_details")), false, "patient signup does not create a helper account");

    const patientOtpKnown = await request("POST", "/api/patient/send-otp-login", { email: knownEmail });
    const patientOtpAbsent = await request("POST", "/api/patient/send-otp-login", { email: "missing@test.invalid" });
    assert.deepEqual(patientOtpKnown, patientOtpAbsent);
    assert.equal(patientOtpKnown.body.message, "If the account is eligible, an OTP has been sent.");

    const helperPhoneKnown = await request("POST", "/api/helper/sendPhoneVerifyOTP", {
      phone: knownPhone, countryCode: "1", purpose: "helper-registration",
    });
    const sentBefore = sms.length;
    const helperPhoneAbsent = await request("POST", "/api/helper/sendPhoneVerifyOTP", {
      phone: "5557654321", countryCode: "1", purpose: "helper-registration",
    });
    assert.deepEqual(helperPhoneKnown, helperPhoneAbsent);
    assert.equal(helperPhoneKnown.status, 201);
    assert.equal(sms.length, sentBefore + 1, "OTP delivery remains conditional on an eligible contact");
    assert.equal(helperPhoneKnown.body.otp, undefined);

    const helperEmailKnown = await request("POST", "/api/helper/sendEmailVerifyOTP", {
      email: knownEmail, purpose: "helper-registration",
    });
    const sentMailsBefore = mails.length;
    const helperEmailAbsent = await request("POST", "/api/helper/sendEmailVerifyOTP", {
      email: "new-user@test.invalid", purpose: "helper-registration",
    });
    assert.deepEqual(helperEmailKnown, helperEmailAbsent);
    assert.equal(mails.length, sentMailsBefore + 1, "verification email is sent only to the eligible submitted contact");

    const invalidOtpWithNoChallenge = await request("POST", "/api/helper/verifyEmailOTP", {
      email: "missing@test.invalid", otp: "0000", purpose: "helper-registration",
    });
    const invalidOtpWithChallenge = await request("POST", "/api/helper/verifyEmailOTP", {
      email: "new-user@test.invalid", otp: "0000", purpose: "helper-registration",
    });
    assert.deepEqual(invalidOtpWithChallenge, invalidOtpWithNoChallenge);
    assert.deepEqual(invalidOtpWithNoChallenge, { status: 400, body: { message: "Invalid or expired OTP" } });

    const noPhoneChallenge = await request("POST", "/api/helper/verifyPhoneOTP", {
      phone: "5557654320", countryCode: "1", otp: "0000", purpose: "helper-registration",
    });
    const phoneChallenge = await request("POST", "/api/helper/verifyPhoneOTP", {
      phone: "5557654321", countryCode: "1", otp: "0000", purpose: "helper-registration",
    });
    assert.deepEqual(phoneChallenge, noPhoneChallenge);

    database.setLoginLockoutFailure(true);
    for (const [route, body] of [
      ["/api/patient/login", { email: knownEmail, password: "ValidPass1!" }],
      ["/api/helper/login", { email_id: knownEmail, password: "ValidPass1!" }],
      ["/api/doctor/login", { email: knownEmail, password: "ValidPass1!" }],
      ["/api/admin/login", { email: knownEmail, password: "ValidPass1!" }],
    ]) {
      const failedClosed = await request("POST", route, body, { includeHeaders: true });
      assert.equal(failedClosed.status, 503, `${route} fails closed when lockout storage is unavailable`);
      assert.deepEqual(failedClosed.body, { message: "Unable to authenticate right now." });
      assert.doesNotMatch(failedClosed.headers.get("set-cookie") || "", /auth_token=/i, `${route} issues no session`);
    }
    database.setLoginLockoutFailure(false);
  });
});

test("dummy password comparison uses the matching bcrypt work factor and never authenticates", async () => {
  const { comparePasswordOrDummy } = require("../utils/password-auth");
  const originalCompare = bcrypt.compare;
  const comparedHashes = [];
  bcrypt.compare = async (_password, hash) => { comparedHashes.push(hash); return false; };
  try {
    assert.equal(await comparePasswordOrDummy("incorrect", undefined, 11), false);
    assert.equal(await comparePasswordOrDummy("incorrect", undefined, 12), false);
  } finally {
    bcrypt.compare = originalCompare;
  }
  assert.deepEqual(comparedHashes.map(hash => hash.slice(0, 7)), ["$2a$11$", "$2a$12$"]);
});
