const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const root = path.resolve(__dirname, '..');
const secrets = {
  patient: 'session-bootstrap-patient-secret',
  helper: 'session-bootstrap-patient-secret',
  doctor: 'session-bootstrap-doctor-secret',
  admin: 'session-bootstrap-admin-secret',
};
const idFields = { patient: 'patient_id', doctor: 'doctor_id', helper: 'helper_id', admin: 'admin_id' };

function makeAccount(role, id) {
  if (role === 'patient') return { patient_id: id, email_id: `patient${id}@test.invalid`, fname: 'Test', lname: 'Patient' };
  if (role === 'doctor') return { doctor_id: id, email_id: `doctor${id}@test.invalid`, fname: 'Test', lname: 'Doctor', validated: 1 };
  if (role === 'helper') return { helper_id: id, email_id: `helper${id}@test.invalid`, mobile: '5551234567' };
  return { admin_id: id, email_id: `admin${id}@test.invalid` };
}

function sign(role, id, overrides = {}) {
  const claims = role === 'helper'
    ? { helper_id: id, email_id: `helper${id}@test.invalid`, role, jti: crypto.randomUUID() }
    : { userId: id, email: `${role}${id}@test.invalid`, role, jti: crypto.randomUUID() };
  return jwt.sign({ ...claims, ...overrides }, secrets[role], { expiresIn: '5m' });
}

function loadRouter(state) {
  const filename = path.join(root, 'routes/auth.js');
  const localRequire = createRequire(filename);
  const db = {
    async query(sql, values) {
      if (state.failDatabase) throw Object.assign(new Error('fixture database unavailable'), { code: 'FIXTURE_DB_DOWN' });
      const tableRole = Object.entries({ patient: 'patient_details', doctor: 'doctor_details', helper: 'helper_details', admin: 'admin_details' })
        .find(([, table]) => sql.includes(`FROM ${table}`))?.[0];
      if (!tableRole) throw new Error(`Unexpected fixture SQL: ${sql}`);
      const [id, email] = values;
      const account = state.accounts[tableRole];
      const matches = account && Number(account[idFields[tableRole]]) === Number(id) && (account.email_id ?? null) === email;
      if (!matches || (tableRole === 'doctor' && /validated\s*=\s*1/i.test(sql) && account.validated != 1)) return [[], []];
      return [[{ ...account }], []];
    },
  };
  const overrides = { mysql2: { createPool: () => ({ promise: () => db }) } };
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
  vm.runInNewContext(`(function(exports,require,module,__filename,__dirname){${fs.readFileSync(filename, 'utf8')}\n})`, context, { filename })(
    module.exports, context.require, module, filename, path.dirname(filename),
  );
  return module.exports;
}

async function withApp(router, run) {
  const app = express();
  app.set('trust proxy', 1);
  app.use(require('../middleware/security-headers'));
  app.use(cors({ origin: ['https://aims2health.co.in'], credentials: true }));
  app.use(cookieParser());
  app.use(require('../middleware/csrf-protection').requireTrustedOrigin(['https://aims2health.co.in']));
  app.use(require('../middleware/csrf-protection').requireCsrfToken);
  app.use('/api/auth', router);
  const server = await new Promise(resolve => { const instance = app.listen(0, '127.0.0.1', () => resolve(instance)); });
  try {
    const request = async ({ cookie, authorization, query = '', origin = 'https://aims2health.co.in' } = {}) => {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/api/auth/session${query}`, {
        headers: {
          ...(cookie ? { Cookie: `auth_token=${cookie}` } : {}),
          ...(authorization ? { Authorization: authorization } : {}),
          ...(origin ? { Origin: origin } : {}),
        },
        signal: AbortSignal.timeout(5000),
      });
      return { status: response.status, headers: response.headers, body: await response.json() };
    };
    await run(request);
  } finally {
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(resolve));
  }
}

test('session bootstrap returns authoritative minimal identity for patient, doctor, helper and admin cookies', async t => {
  const envNames = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = envNames.map(name => process.env[name]);
  process.env.JWT_SECRET_PATIENT = secrets.patient;
  process.env.JWT_SECRET_DOC = secrets.doctor;
  process.env.JWT_SECRET_ADMIN = secrets.admin;
  t.after(() => envNames.forEach((name, index) => previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index]));

  const state = { accounts: Object.fromEntries(['patient', 'doctor', 'helper', 'admin'].map(role => [role, makeAccount(role, 1)])), failDatabase: false };
  const router = loadRouter(state);
  await withApp(router, async request => {
    for (const role of ['patient', 'doctor', 'helper', 'admin']) {
      const token = sign(role, 1);
      const response = await request({ cookie: token, query: '?role=admin&userId=999&department=forged' });
      assert.equal(response.status, 200, role);
      assert.equal(response.body.role, role, 'role comes from verified credential');
      assert.equal(response.body.userId, 1, 'ID comes from the verified credential and matched database record');
      assert.equal(response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
      assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
      assert.equal(response.headers.get('access-control-allow-origin'), 'https://aims2health.co.in');
      assert.equal(JSON.stringify(response.body).includes(token), false);
      assert.doesNotMatch(JSON.stringify(response.body), /password|otp|secret|refresh.?token/i);
      if (role === 'patient') {
        assert.deepEqual(response.body, { role, expiresIn: response.body.expiresIn, userId: 1, userEmail: 'patient1@test.invalid', userName: 'Test Patient' });
      } else if (role === 'doctor') {
        assert.deepEqual(response.body, { role, expiresIn: response.body.expiresIn, userId: 1, userEmail: 'doctor1@test.invalid', userName: 'Test Doctor' });
      } else if (role === 'admin') {
        assert.deepEqual(response.body, { role, expiresIn: response.body.expiresIn, userId: 1, userEmail: 'admin1@test.invalid', userName: 'admin1@test.invalid' });
      } else {
        assert.deepEqual(response.body, {
          role, expiresIn: response.body.expiresIn, userId: 1,
          userEmail: 'helper1@test.invalid', userName: '',
          user: { helper_id: 1, email_id: 'helper1@test.invalid', mobile: '5551234567' },
        });
      }
      assert.equal(Number.isInteger(response.body.expiresIn) && response.body.expiresIn > 0, true);
    }
  });
});

test('session bootstrap rejects absent, malformed, expired, forged, revoked and bearer-only credentials', async t => {
  const envNames = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = envNames.map(name => process.env[name]);
  process.env.JWT_SECRET_PATIENT = secrets.patient;
  process.env.JWT_SECRET_DOC = secrets.doctor;
  process.env.JWT_SECRET_ADMIN = secrets.admin;
  t.after(() => envNames.forEach((name, index) => previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index]));
  const state = { accounts: { patient: makeAccount('patient', 1) }, failDatabase: false };
  const router = loadRouter(state);
  const blacklist = require('../middleware/token-blacklist');
  await withApp(router, async request => {
    const missing = await request();
    assert.equal(missing.status, 401);
    assert.deepEqual(missing.body, { message: 'You are not authenticated!' });
    assert.equal(missing.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');

    for (const cookie of [
      'not-a-jwt',
      jwt.sign({ userId: 1, email: 'patient1@test.invalid', role: 'patient' }, 'wrong-signature-key', { expiresIn: '5m' }),
      jwt.sign({ userId: 1, email: 'patient1@test.invalid', role: 'patient' }, secrets.patient, { expiresIn: -1 }),
      jwt.sign({ userId: 1, email: 'patient1@test.invalid', role: 'patient' }, secrets.patient),
    ]) {
      const response = await request({ cookie });
      assert.equal(response.status, 401);
      assert.deepEqual(response.body, { message: 'You are not authenticated!' });
      assert.equal(response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
    }

    const bearerOnlyToken = sign('patient', 1);
    const bearerOnly = await request({ authorization: `Bearer ${bearerOnlyToken}` });
    assert.equal(bearerOnly.status, 401, 'session bootstrap requires auth_token cookie');

    const revoked = sign('patient', 1);
    blacklist.blacklistToken(revoked);
    const revokedResponse = await request({ cookie: revoked });
    assert.equal(revokedResponse.status, 401);
    assert.deepEqual(revokedResponse.body, { message: 'You are not authenticated!' });
    assert.equal(revokedResponse.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');

    const cookieWinsOverHeader = await request({ cookie: sign('patient', 1), authorization: 'Bearer malformed' });
    assert.equal(cookieWinsOverHeader.status, 200, 'only the valid cookie determines bootstrap identity');
  });
});

test('session bootstrap rejects deleted and ineligible accounts and fails closed on database errors', async t => {
  const envNames = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = envNames.map(name => process.env[name]);
  process.env.JWT_SECRET_PATIENT = secrets.patient;
  process.env.JWT_SECRET_DOC = secrets.doctor;
  process.env.JWT_SECRET_ADMIN = secrets.admin;
  t.after(() => envNames.forEach((name, index) => previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index]));

  const state = { accounts: {}, failDatabase: false };
  const router = loadRouter(state);
  await withApp(router, async request => {
    for (const role of ['patient', 'doctor', 'helper', 'admin']) {
      const response = await request({ cookie: sign(role, 1) });
      assert.equal(response.status, 401, `${role} account missing/deleted`);
      assert.deepEqual(response.body, { message: 'You are not authenticated!' });
    }

    state.accounts.doctor = { ...makeAccount('doctor', 2), validated: 0 };
    const unapprovedDoctor = await request({ cookie: sign('doctor', 2) });
    assert.equal(unapprovedDoctor.status, 401, 'doctor approval status follows existing authorization policy');

    state.failDatabase = true;
    const databaseFailure = await request({ cookie: sign('patient', 1) });
    assert.equal(databaseFailure.status, 503);
    assert.deepEqual(databaseFailure.body, { message: 'Unable to validate session right now.' });
    assert.equal(databaseFailure.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
  });
});
