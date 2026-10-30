const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const root = path.resolve(__dirname, '..');

function loadPatientRouter({ failUpdate = false, failSecondPatientLookup = false } = {}) {
  const filename = path.join(root, 'routes/patients.js');
  const localRequire = createRequire(filename);
  const sent = { loginOtp: null, phoneOtp: null, emailOtp: null, emailText: null };
  const patient = { patient_id: 41, email_id: 'patient-otp@test.invalid', mobile_no: '5554443322', countryCode: '1', fname: 'OTP', lname: 'Fixture' };
  let patientLookupCount = 0;
  let clock = Date.now();
  class TestDate extends Date {
    constructor(...args) { super(...(args.length ? args : [clock])); }
    static now() { return clock; }
  }
  const db = {
    connect(callback) { callback(null); },
    query(sql, values, callback) {
      if (typeof values === 'function') { callback = values; values = []; }
      let result = [];
      if (/SELECT \* FROM patient_details WHERE email_id = \?/.test(sql)) {
        patientLookupCount++;
        if (failSecondPatientLookup && patientLookupCount > 1) return callback(new Error('fixture database failure'));
        result = [patient];
      } else if (/SELECT patient_id FROM patient_details WHERE patient_id = \? AND email_id <=> \?/.test(sql)) {
        result = Number(values[0]) === patient.patient_id && values[1] === patient.email_id ? [{ patient_id: patient.patient_id }] : [];
      } else if (/SELECT mobile_no FROM patient_details WHERE patient_id = \?/.test(sql)) {
        result = [patient];
      } else if (/SELECT email_id FROM patient_details WHERE patient_id = \?/.test(sql)) {
        result = [patient];
      } else if (/UPDATE patient_additional/.test(sql)) {
        if (failUpdate) return callback(new Error('fixture database failure'));
        result = { affectedRows: 1 };
      } else {
        throw new Error(`Unexpected fixture SQL: ${sql}`);
      }
      callback(null, result, []);
    },
    promise() {
      return { query: (sql, values) => new Promise((resolve, reject) => {
        this.query(sql, values, (error, rows) => error ? reject(error) : resolve([rows, []]));
      }) };
    },
  };
  const sgMail = {
    setApiKey() {},
    send: async message => {
      const match = String(message.text).match(/OTP is (\d{6})/);
      sent.loginOtp = match?.[1];
    },
  };
  const axios = { post: async (_url, payload) => {
    const match = String(payload.message).match(/No: (\d{4})/);
    sent.phoneOtp = match?.[1];
    return { data: { status: 'Accepted' }, status: 200, headers: {} };
  } };
  const zeptomail = { sendMail: async message => {
    sent.emailText = message.text;
    const match = String(message.text).match(/OTP for secure login is (\d{4})/);
    sent.emailOtp = match?.[1];
  } };
  const overrides = {
    mysql2: { createConnection: () => db },
    '@sendgrid/mail': sgMail,
    axios,
    '../utils/zeptomail': zeptomail,
    twilio: () => ({ messages: { create: async () => ({}) } }),
    razorpay: function Razorpay() { this.orders = {}; },
  };
  const module = { exports: {} };
  const context = {
    module, exports: module.exports,
    require: id => Object.hasOwn(overrides, id) ? overrides[id] : localRequire(id),
    __dirname: path.dirname(filename), __filename: filename,
    process, Buffer, Date: TestDate,
    console: { log() {}, error() {}, warn() {} },
    setTimeout, clearTimeout, URL,
  };
  vm.runInNewContext(`(function(exports,require,module,__filename,__dirname){${fs.readFileSync(filename, 'utf8')}\n})`, context, { filename })(module.exports, context.require, module, filename, path.dirname(filename));
  return { router: module.exports, sent, advance: ms => { clock += ms; }, getPatientLookupCount: () => patientLookupCount };
}

async function withServer(router, run) {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use(require('../middleware/csrf-protection').requireCsrfToken);
  app.use('/api/patient', router);
  app.get('/protected', require('../middleware/authenticate')(['patient']), (_req, res) => res.status(200).json({ ok: true }));
  const server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  try {
    const request = async (method, route, body, credential) => {
      const credentials = typeof credential === 'string'
        ? { Authorization: `Bearer ${credential}` }
        : credential || {};
      const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`, {
        method,
        headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...credentials },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(10000),
      });
      const text = await response.text();
      return { status: response.status, headers: response.headers, body: text ? JSON.parse(text) : null };
    };
    await run(request);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test('patient OTP login issues HttpOnly cookie only after current correct OTP; failed or replayed codes do not', async t => {
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = keys.map(key => process.env[key]);
  const previousEhrConnect = process.env.EHR_CONNECT;
  process.env.JWT_SECRET_PATIENT = 'otp-patient-login-fixture';
  process.env.JWT_SECRET_DOC = 'otp-doctor-login-fixture';
  process.env.JWT_SECRET_ADMIN = 'otp-admin-login-fixture';
  process.env.EHR_CONNECT = 'false';
  t.after(() => {
    keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]);
    previousEhrConnect === undefined ? delete process.env.EHR_CONNECT : process.env.EHR_CONNECT = previousEhrConnect;
  });

  const fixture = loadPatientRouter();
  await withServer(fixture.router, async request => {
    assert.equal((await request('POST', '/api/patient/send-otp-login', { email: 'patient-otp@test.invalid' })).status, 200);
    assert.match(fixture.sent.loginOtp, /^\d{6}$/);

    const bad = await request('POST', '/api/patient/verify-otp-login', { email: 'patient-otp@test.invalid', otp: '000000' });
    assert.equal(bad.status, 401);
    assert.equal(bad.body.token, undefined);
    assert.equal(bad.headers.get('set-cookie'), null, 'invalid OTP does not set auth cookies');
    assert.equal((await request('GET', '/protected', undefined, bad.body.token)).status, 401);

    const success = await request('POST', '/api/patient/verify-otp-login', { email: 'patient-otp@test.invalid', otp: fixture.sent.loginOtp });
    assert.equal(success.status, 200);
    assert.equal(success.body.token, undefined, 'patient JWT is absent from readable response JSON');
    assert.equal(success.body.expiresIn, 3600);
    assert.equal(success.body.userId, 41);
    assert.equal(success.body.userEmail, 'patient-otp@test.invalid');
    assert.equal(success.body.userName, 'OTP Fixture');
    const successCookies = success.headers.getSetCookie();
    const authCookie = successCookies.find(value => value.startsWith('auth_token='));
    const csrfCookie = successCookies.find(value => value.startsWith('csrf_token='));
    assert.ok(authCookie, 'success sets the HttpOnly auth cookie');
    assert.ok(csrfCookie, 'success sets the CSRF cookie');
    assert.match(authCookie, /; HttpOnly/i);
    assert.match(authCookie, /; Secure/i);
    assert.match(authCookie, /; SameSite=Lax/i);
    assert.doesNotMatch(csrfCookie, /; HttpOnly/i);
    const cookieHeader = `${authCookie.split(';', 1)[0]}; ${csrfCookie.split(';', 1)[0]}`;
    const csrfHeader = decodeURIComponent(csrfCookie.match(/^csrf_token=([^;]+)/)[1]);
    const cookieCredential = { Cookie: cookieHeader };
    assert.equal((await request('GET', '/protected', undefined, cookieCredential)).status, 200, 'protected API accepts the server-issued cookie');

    const replay = await request('POST', '/api/patient/verify-otp-login', { email: 'patient-otp@test.invalid', otp: fixture.sent.loginOtp });
    assert.equal(replay.status, 401);
    assert.equal(replay.body.token, undefined);
    assert.equal(replay.headers.get('set-cookie'), null, 'replayed OTP does not set auth cookies');
    assert.equal((await request('GET', '/protected', undefined, 'response-replacement')).status, 401);

    const logout = await request('POST', '/api/patient/logout', {}, { ...cookieCredential, 'x-csrf-token': csrfHeader });
    assert.equal(logout.status, 200);
    assert.match(logout.headers.get('set-cookie') || '', /auth_token=;/);
    assert.match(logout.headers.get('set-cookie') || '', /csrf_token=;/);
    assert.equal((await request('GET', '/protected', undefined, cookieCredential)).status, 401, 'logout revokes the OTP-issued cookie token');

    assert.equal((await request('POST', '/api/patient/send-otp-login', { email: 'patient-otp@test.invalid' })).status, 200);
    fixture.advance(5 * 60 * 1000 + 1);
    const expired = await request('POST', '/api/patient/verify-otp-login', { email: 'patient-otp@test.invalid', otp: fixture.sent.loginOtp });
    assert.equal(expired.status, 401);
    assert.equal(expired.body.token, undefined);
    assert.equal(expired.headers.get('set-cookie'), null, 'expired OTP does not set auth cookies');
  });
});

test('patient phone/email verification is bound to the signed-in account and consumes OTPs', async t => {
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = keys.map(key => process.env[key]);
  const previousEhrConnect = process.env.EHR_CONNECT;
  process.env.JWT_SECRET_PATIENT = 'otp-patient-contact-fixture';
  process.env.JWT_SECRET_DOC = 'otp-doctor-contact-fixture';
  process.env.JWT_SECRET_ADMIN = 'otp-admin-contact-fixture';
  process.env.EHR_CONNECT = 'false';
  t.after(() => {
    keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]);
    previousEhrConnect === undefined ? delete process.env.EHR_CONNECT : process.env.EHR_CONNECT = previousEhrConnect;
  });

  const fixture = loadPatientRouter();
  const patientToken = jwt.sign({ userId: 41, email: 'patient-otp@test.invalid', role: 'patient' }, process.env.JWT_SECRET_PATIENT, { expiresIn: '5m' });
  await withServer(fixture.router, async request => {
    assert.equal((await request('POST', '/api/patient/sendPhoneVerifyOTP', { phone: '5550000000' }, patientToken)).status, 400, 'cannot start OTP for a different contact');
    assert.equal((await request('POST', '/api/patient/sendPhoneVerifyOTP', { phone: '5554443322' }, patientToken)).status, 200);
    assert.match(fixture.sent.phoneOtp, /^\d{4}$/);
    assert.equal((await request('POST', '/api/patient/verifyPhone', { phone: '5554443322', otp: 'wrong' }, patientToken)).status, 400);
    assert.equal((await request('POST', '/api/patient/verifyPhone', { phone: '5554443322', otp: fixture.sent.phoneOtp }, patientToken)).status, 201);
    assert.equal((await request('POST', '/api/patient/verifyPhone', { phone: '5554443322', otp: fixture.sent.phoneOtp }, patientToken)).status, 400, 'phone OTP is single use');

    assert.equal((await request('POST', '/api/patient/sendEmailVerifyOTP', { email: 'other@test.invalid' }, patientToken)).status, 400);
    assert.equal((await request('POST', '/api/patient/sendEmailVerifyOTP', { email: 'PATIENT-OTP@test.invalid' }, patientToken)).status, 201);
    assert.match(fixture.sent.emailOtp, /^\d{4}$/);
    assert.match(fixture.sent.emailText, /valid for 8 minutes/i);
    assert.equal((await request('POST', '/api/patient/verifyEmail', { email: 'patient-otp@test.invalid', otp: fixture.sent.emailOtp }, patientToken)).status, 201);
    assert.equal((await request('POST', '/api/patient/verifyEmail', { email: 'patient-otp@test.invalid', otp: fixture.sent.emailOtp }, patientToken)).status, 400, 'email OTP is single use');
  });
});

test('patient OTP database failures do not report successful verification or issue a login token', async t => {
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = keys.map(key => process.env[key]);
  const previousEhrConnect = process.env.EHR_CONNECT;
  process.env.JWT_SECRET_PATIENT = 'otp-patient-db-failure-fixture';
  process.env.JWT_SECRET_DOC = 'otp-doctor-db-failure-fixture';
  process.env.JWT_SECRET_ADMIN = 'otp-admin-db-failure-fixture';
  process.env.EHR_CONNECT = 'false';
  t.after(() => {
    keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]);
    previousEhrConnect === undefined ? delete process.env.EHR_CONNECT : process.env.EHR_CONNECT = previousEhrConnect;
  });

  const fixture = loadPatientRouter({ failUpdate: true, failSecondPatientLookup: true });
  const patientToken = jwt.sign({ userId: 41, email: 'patient-otp@test.invalid', role: 'patient' }, process.env.JWT_SECRET_PATIENT, { expiresIn: '5m' });
  await withServer(fixture.router, async request => {
    await request('POST', '/api/patient/sendPhoneVerifyOTP', { phone: '5554443322' }, patientToken);
    const failedVerification = await request('POST', '/api/patient/verifyPhone', {
      phone: '5554443322', otp: fixture.sent.phoneOtp,
    }, patientToken);
    assert.equal(failedVerification.status, 500);
    assert.notEqual(failedVerification.body?.vstatus, 'approved');

    await request('POST', '/api/patient/send-otp-login', { email: 'patient-otp@test.invalid' });
    const failedLogin = await request('POST', '/api/patient/verify-otp-login', {
      email: 'patient-otp@test.invalid', otp: fixture.sent.loginOtp,
    });
    assert.equal(failedLogin.status, 401);
    assert.equal(failedLogin.body.message, 'Invalid or expired OTP');
    assert.equal(failedLogin.body.token, undefined);
    assert.equal(failedLogin.headers.get('set-cookie'), null);
  });
});



