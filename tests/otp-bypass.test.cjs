const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const express = require('express');
const jwt = require('jsonwebtoken');
const root = path.resolve(__dirname, '..');

function loadHelperRouter({ failInsert = false } = {}) {
  const filename = path.join(root, 'routes/patient_helpers.js');
  const localRequire = createRequire(filename);
  const sent = { phoneOtp: null, emailOtp: null };
  let clock = Date.now();
  class TestDate extends Date {
    constructor(...args) { super(...(args.length ? args : [clock])); }
    static now() { return clock; }
  }
  const db = {
    async query(sql) {
      if (sql === 'SELECT 1') return [[{ ok: 1 }], []];
      if (/SELECT helper_id FROM helper_details/.test(sql)) return [[], []];
      if (/INSERT INTO helper_details/.test(sql)) {
        if (failInsert) throw new Error('fixture database failure');
        return [{ insertId: 73 }, []];
      }
      throw new Error(`Unexpected fixture SQL: ${sql}`);
    },
  };
  const axios = { post: async (url, payload) => {
    if (url.includes('/sms-api/')) {
      const match = String(payload.message).match(/No: (\d{4})/);
      sent.phoneOtp = match?.[1];
      return { data: { status: 'Accepted' } };
    }
    return { data: { accepted: true } };
  } };
  const zeptomail = { sendMail: async message => {
    const match = String(message.text).match(/verification is: (\d{4})/);
    sent.emailOtp = match?.[1];
  } };
  const overrides = {
    mysql2: { createPool: () => ({ promise: () => db }) },
    axios,
    '../utils/zeptomail': zeptomail,
    twilio: () => ({ messages: { create: async () => ({}) } }),
    Razorpay: function Razorpay() { this.orders = {}; },
    '@sendgrid/mail': { setApiKey() {}, send: async () => ({}) },
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
  return { router: module.exports, sent, advance: ms => { clock += ms; } };
}

function createApp(router) {
  const app = express();
  app.use(express.json());
  app.use('/api/helper', router);
  app.get('/helper-dashboard', require('../middleware/authenticate')(['helper']), (req, res) => res.status(200).json({ ok: true }));
  return app;
}

async function withServer(app, run) {
  const server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  try {
    const request = async (method, route, body, token) => {
      const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`, {
        method,
        headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(10000),
      });
      return { status: response.status, headers: response.headers, body: await response.json() };
    };
    await run(request);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test('helper registration requires purpose-bound, single-use OTP proofs before issuing a JWT', async t => {
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = keys.map(key => process.env[key]);
  process.env.JWT_SECRET_PATIENT = 'otp-helper-patient-fixture';
  process.env.JWT_SECRET_DOC = 'otp-helper-doctor-fixture';
  process.env.JWT_SECRET_ADMIN = 'otp-helper-admin-fixture';
  t.after(() => keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));

  const { router, sent } = loadHelperRouter();
  await withServer(createApp(router), async request => {
    const base = { email_id: 'helper-otp@test.invalid', phone_no: '5551234567', password: 'FixturePass123!' };
    const skipped = await request('POST', '/api/helper/register', { ...base, isVerified: true, role: 'admin' });
    assert.equal(skipped.status, 400);
    assert.equal(skipped.body.token, undefined);
    assert.equal((await request('GET', '/helper-dashboard')).status, 401);

    assert.equal((await request('POST', '/api/helper/sendPhoneVerifyOTP', {
      phone: base.phone_no, countryCode: '1', purpose: 'helper-registration',
    })).status, 201);
    assert.equal((await request('POST', '/api/helper/sendEmailVerifyOTP', {
      email: base.email_id, purpose: 'helper-registration',
    })).status, 201);
    assert.match(sent.phoneOtp, /^\d{4}$/);
    assert.match(sent.emailOtp, /^\d{4}$/);

    const invalid = await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: base.phone_no, countryCode: '1', otp: '0000', purpose: 'helper-registration',
    });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.verificationToken, undefined);
    assert.equal((await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: base.phone_no, countryCode: '1', purpose: 'helper-registration',
    })).status, 400, 'missing OTP is rejected');
    assert.equal((await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: base.phone_no, countryCode: '1', otp: 'nope', purpose: 'helper-registration',
    })).status, 400, 'malformed OTP is rejected');

    // A challenge cannot be moved to the add-patient contact-verification flow.
    assert.equal((await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: base.phone_no, countryCode: '1', otp: sent.phoneOtp, purpose: 'patient-contact',
    })).status, 400);
    assert.equal((await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: '5550000000', countryCode: '1', otp: sent.phoneOtp, purpose: 'helper-registration',
    })).status, 400, 'OTP is bound to its phone contact');

    const phoneVerified = await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: base.phone_no, countryCode: '1', otp: sent.phoneOtp, purpose: 'helper-registration',
    });
    const emailVerified = await request('POST', '/api/helper/verifyEmailOTP', {
      email: base.email_id, otp: sent.emailOtp, purpose: 'helper-registration',
    });
    assert.equal(phoneVerified.status, 200);
    assert.equal(emailVerified.status, 200);
    assert.equal(phoneVerified.body.otp, undefined);
    assert.equal(emailVerified.body.otp, undefined);
    assert.equal((await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: base.phone_no, countryCode: '1', otp: sent.phoneOtp, purpose: 'helper-registration',
    })).status, 400, 'OTP cannot be consumed twice');

    const registered = await request('POST', '/api/helper/register', {
      ...base,
      phoneVerificationToken: phoneVerified.body.verificationToken,
      emailVerificationToken: emailVerified.body.verificationToken,
    });
    assert.equal(registered.status, 201);
    assert.equal(jwt.verify(registered.body.token, process.env.JWT_SECRET_PATIENT).role, 'helper');
    assert.equal((await request('GET', '/helper-dashboard', undefined, registered.body.token)).status, 200, 'server-issued registration token authenticates helper dashboard');
    assert.equal((await request('POST', '/api/helper/register', {
      ...base,
      phoneVerificationToken: phoneVerified.body.verificationToken,
      emailVerificationToken: emailVerified.body.verificationToken,
    })).status, 400, 'verification proof cannot be reused');
  });
});

test('expired helper OTP and registration database failure do not issue a session', async t => {
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = keys.map(key => process.env[key]);
  process.env.JWT_SECRET_PATIENT = 'otp-helper-patient-fixture-2';
  process.env.JWT_SECRET_DOC = 'otp-helper-doctor-fixture-2';
  process.env.JWT_SECRET_ADMIN = 'otp-helper-admin-fixture-2';
  t.after(() => keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));

  const fixture = loadHelperRouter({ failInsert: true });
  await withServer(createApp(fixture.router), async request => {
    const body = { phone_no: '5559876543', password: 'FixturePass123!' };
    await request('POST', '/api/helper/sendPhoneVerifyOTP', { phone: body.phone_no, countryCode: '1', purpose: 'helper-registration' });
    fixture.advance(8 * 60 * 1000 + 1);
    const expired = await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: body.phone_no, countryCode: '1', otp: fixture.sent.phoneOtp, purpose: 'helper-registration',
    });
    assert.equal(expired.status, 400);
    assert.equal(expired.body.token, undefined);

    await request('POST', '/api/helper/sendPhoneVerifyOTP', { phone: body.phone_no, countryCode: '1', purpose: 'helper-registration' });
    const verified = await request('POST', '/api/helper/verifyPhoneOTP', {
      phone: body.phone_no, countryCode: '1', otp: fixture.sent.phoneOtp, purpose: 'helper-registration',
    });
    const failed = await request('POST', '/api/helper/register', {
      ...body, phoneVerificationToken: verified.body.verificationToken,
    });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.token, undefined);
    assert.equal((await request('GET', '/helper-dashboard')).status, 401);
  });
});
