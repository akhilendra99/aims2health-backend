const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');

const root = path.resolve(__dirname, '..');
function load(relative, overrides = {}) {
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
  vm.runInNewContext('(function(exports,require,module,__filename,__dirname){' + fs.readFileSync(filename, 'utf8') + '\n})', context, { filename })(module.exports, context.require, module, filename, path.dirname(filename));
  return module.exports;
}

test('admin login keeps JWT HttpOnly and ignores client supplied identity for protected API auth', async t => {
  const envKeys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN', 'COOKIE_SECURE', 'COOKIE_DOMAIN'];
  const previous = envKeys.map(key => process.env[key]);
  process.env.JWT_SECRET_PATIENT = 'local-storage-boundary-patient-secret';
  process.env.JWT_SECRET_DOC = 'local-storage-boundary-doctor-secret';
  process.env.JWT_SECRET_ADMIN = 'local-storage-boundary-admin-secret';
  process.env.COOKIE_SECURE = 'true';
  delete process.env.COOKIE_DOMAIN;
  t.after(() => envKeys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));

  const passwordHash = await bcrypt.hash('FixtureAdminPassword1!', 4);
  const adminRow = { admin_id: 7, email_id: 'admin7@test.invalid', hashed_pwd: passwordHash };
  const db = {
    connect(callback) { callback(null); },
    query(sql, values, callback) {
      if (typeof values === 'function') { callback = values; values = []; }
      let rows = [];
      if (/SELECT \* FROM admin_details WHERE email_id = \?/.test(sql)) rows = [adminRow];
      else if (/SELECT admin_id FROM admin_details WHERE admin_id = \? AND email_id <=> \?/.test(sql)) {
        rows = Number(values[0]) === adminRow.admin_id && values[1] === adminRow.email_id ? [{ admin_id: adminRow.admin_id }] : [];
      }
      if (callback) callback(null, rows);
      return Promise.resolve([rows]);
    },
  };
  const lockout = {
    createLoginLockKeys: () => ['fixture-lock-key'],
    isLoginLocked: async () => false,
    recordLoginFailure: async () => {},
    clearLoginFailures: async () => {},
  };
  const mail = { setApiKey() {}, send: async () => {} };
  const router = load('routes/admin.js', {
    mysql2: { createConnection: () => db },
    '../utils/login-lockout': lockout,
    '@sendgrid/mail': mail,
    twilio: () => ({ messages: { create: async () => {} } }),
    axios: { post: async () => {} },
  });

  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use(require('../middleware/csrf-protection').requireCsrfToken);
  app.use('/api/admin', router);
  const access = require('../utils/authorization')(async (sql, values) => {
    const [rows] = await db.query(sql, values);
    return rows;
  });
  app.post('/identity', access.guard(['admin']), (req, res) => res.json(req.userData));
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const login = await fetch(origin + '/api/admin/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: adminRow.email_id, password: 'FixtureAdminPassword1!' }),
  });
  assert.equal(login.status, 200);
  const body = await login.json();
  assert.equal(body.token, undefined, 'admin login does not expose bearer credential in JavaScript-readable JSON');
  assert.equal(body.userId, adminRow.admin_id, 'existing UI metadata stays compatible');
  assert.equal(body.expiresIn, 3600);
  const authCookie = login.headers.getSetCookie().find(value => value.startsWith('auth_token='));
  const csrfCookie = login.headers.getSetCookie().find(value => value.startsWith('csrf_token='));
  assert.ok(authCookie);
  assert.ok(csrfCookie);
  assert.match(authCookie, /; HttpOnly/i);
  assert.match(authCookie, /; Secure/i);
  assert.match(authCookie, /; SameSite=Lax/i);
  const authValue = authCookie.split(';', 1)[0];
  const csrfValue = csrfCookie.split(';', 1)[0];
  const cookie = `${authValue}; ${csrfValue}`;
  const csrfHeader = decodeURIComponent(csrfValue.slice('csrf_token='.length));

  const missingCookie = await fetch(origin + '/identity', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: adminRow.admin_id, role: 'admin' }),
  });
  assert.equal(missingCookie.status, 401);

  const malformedCookie = await fetch(origin + '/identity', {
    method: 'POST',
    headers: { Cookie: `auth_token=malformed; ${csrfValue}`, 'x-csrf-token': csrfHeader, 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: adminRow.admin_id, role: 'admin' }),
  });
  assert.equal(malformedCookie.status, 401);

  const protectedResponse = await fetch(origin + '/identity', {
    method: 'POST',
    headers: { Cookie: cookie, 'x-csrf-token': csrfHeader, 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: 999, role: 'patient', department: 'forged' }),
  });
  assert.equal(protectedResponse.status, 200);
  const identity = await protectedResponse.json();
  assert.equal(identity.userId, adminRow.admin_id);
  assert.equal(identity.role, 'admin');
  assert.equal(identity.email, adminRow.email_id);

  const forgedOnly = await fetch(origin + '/identity', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: adminRow.admin_id, role: 'admin', department: 'admin' }),
  });
  assert.equal(forgedOnly.status, 401, 'client supplied local state cannot authenticate without server-issued credential');

  const logout = await fetch(origin + '/api/admin/logout', {
    method: 'POST',
    headers: { Cookie: cookie, 'x-csrf-token': csrfHeader, 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: 999, role: 'patient', department: 'forged' }),
  });
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get('set-cookie') || '', /auth_token=;/);
  assert.match(logout.headers.get('set-cookie') || '', /csrf_token=;/);

  const revokedCookie = await fetch(origin + '/identity', {
    method: 'POST',
    headers: { Cookie: cookie, 'x-csrf-token': csrfHeader, 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: adminRow.admin_id, role: 'admin' }),
  });
  assert.equal(revokedCookie.status, 401, 'old cookie cannot access protected API after logout');
});
