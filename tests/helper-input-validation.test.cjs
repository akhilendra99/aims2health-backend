const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const express = require('express');
const jwt = require('jsonwebtoken');
const root = path.resolve(__dirname, '..');

function loadHelperRouter() {
  const filename = path.join(root, 'routes/patient_helpers.js');
  const localRequire = createRequire(filename);
  const calls = [];
  const db = {
    async query(sql, values = []) {
      calls.push({ sql, values });
      if (sql === 'SELECT 1') return [[{ ok: 1 }], []];
      if (/SELECT helper_id FROM helper_details WHERE helper_id = \? AND email_id <=> \?/.test(sql)) return [[{ helper_id: 7 }], []];
      if (/SELECT doctor_calendar\.\*/.test(sql)) return [[], []];
      if (/SELECT pd\.patient_id/.test(sql)) return [[], []];
      if (/SELECT \*/.test(sql)) return [[], []];
      if (/SELECT helper_id FROM helper_details/.test(sql)) return [[], []];
      throw new Error(`Unexpected fixture SQL: ${sql}`);
    },
  };
  const overrides = {
    mysql2: { createPool: () => ({ promise: () => db }) },
    axios: { post: async () => ({ data: { status: 'Accepted' } }) },
    '../utils/zeptomail': { sendMail: async () => {} },
    twilio: () => ({ messages: { create: async () => ({}) } }),
    Razorpay: function Razorpay() { this.orders = {}; },
    '@sendgrid/mail': { setApiKey() {}, send: async () => {} },
  };
  const module = { exports: {} };
  const context = {
    module, exports: module.exports,
    require: id => Object.hasOwn(overrides, id) ? overrides[id] : localRequire(id),
    __dirname: path.dirname(filename), __filename: filename,
    process, Buffer,
    console: { log() {}, error() {}, warn() {} },
    setTimeout, clearTimeout, URL,
  };
  vm.runInNewContext(`(function(exports,require,module,__filename,__dirname){${fs.readFileSync(filename, 'utf8')}\n})`, context, { filename })(module.exports, context.require, module, filename, path.dirname(filename));
  return { router: module.exports, calls };
}

async function withServer(app, run) {
  const server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  try {
    const request = async (method, route, body, token, contentType = 'application/json') => {
      const isMultipart = contentType === 'multipart/form-data';
      const headers = { ...(body !== undefined && !isMultipart ? { 'Content-Type': contentType } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) };
      const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`, {
        method, headers,
        body: body === undefined ? undefined : contentType === 'application/json' ? JSON.stringify(body) : body,
        signal: AbortSignal.timeout(10000),
      });
      return { status: response.status, contentType: response.headers.get('content-type'), body: await response.text() };
    };
    await run(request);
  } finally {
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(resolve));
  }
}

test('helper dashboard rejects malformed, oversized, mistyped, and unexpected request fields', async t => {
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = keys.map(key => process.env[key]);
  process.env.JWT_SECRET_PATIENT = 'helper-input-patient-fixture';
  process.env.JWT_SECRET_DOC = 'helper-input-doctor-fixture';
  process.env.JWT_SECRET_ADMIN = 'helper-input-admin-fixture';
  t.after(() => keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));

  const { router, calls } = loadHelperRouter();
  const app = express();
  app.use(express.json());
  app.use(require('../middleware/helper-json-errors'));
  app.use('/api/helper', router);
  const token = jwt.sign({ helper_id: 7, email_id: 'helper@test.invalid', role: 'helper' }, process.env.JWT_SECRET_PATIENT, { expiresIn: '5m' });

  await withServer(app, async request => {
    let before = calls.length;
    let response = await request('POST', '/api/helper/register', {
      email_id: 'bad-email', password: 'ok', extra: '<script>alert(1)</script>',
    });
    assert.equal(response.status, 400);
    assert.deepEqual(JSON.parse(response.body).errors.map(error => error.field).sort(), ['body', 'body.email_id', 'body.extra']);
    assert.equal(calls.length, before, 'invalid request rejected before database work');

    response = await request('POST', '/api/helper/login', { email_id: ['helper@test.invalid'], password: 'pw' });
    assert.equal(response.status, 400);

    response = await request('POST', '/api/helper/register', { email_id: 'helper@test.invalid', password: 'x'.repeat(73) });
    assert.equal(response.status, 400, 'oversized bcrypt input is rejected');

    response = await request('POST', '/api/helper/forgetpwd', { email: 'not-an-email' });
    assert.equal(response.status, 400);

    response = await request('POST', '/api/helper/add-patient', { fname: { value: 'object' } }, token);
    assert.equal(response.status, 400, 'direct API calls cannot bypass the request schema');

    before = calls.length;
    response = await request('POST', '/api/helper/search', { appmntDate: '<script>', docType: 'general' }, token);
    assert.equal(response.status, 400);
    assert.equal(calls.length, before + 1, 'only the helper identity lookup ran before invalid search input was rejected');

    response = await request('POST', '/api/helper/search', { appmntDate: '2026-10-25', docType: 'general' }, token);
    assert.equal(response.status, 404, 'valid search input reaches the existing no-results behavior');
    assert.deepEqual(Array.from(calls.at(-1).values), ['2026-10-25', 'general']);

    response = await request('POST', '/api/helper/medreport', {
      patient_id: '7', title: 'Valid title', content: '<b>preserved medical note</b>', recordDate: '2026-10-25',
    }, token);
    assert.equal(response.status, 404, 'valid rich text passes validation before ownership lookup');

    response = await request('GET', '/api/helper/medreports/7?page=1x', undefined, token);
    assert.equal(response.status, 400);
    response = await request('GET', '/api/helper/medreports/07?page=1', undefined, token);
    assert.equal(response.status, 400);

    const multipart = new FormData();
    multipart.set('patient_id', '7');
    multipart.set('unexpected', '<b>value</b>');
    response = await request('POST', '/api/helper/medreport', multipart, token, 'multipart/form-data');
    assert.equal(response.status, 400);
    assert.match(response.body, /not allowed/);
  });
});

test('malformed helper JSON returns a safe JSON 400 response', async () => {
  const app = express();
  app.use(express.json());
  app.use(require('../middleware/helper-json-errors'));
  app.post('/api/helper/login', (_req, res) => res.json({ ok: true }));

  await withServer(app, async request => {
    const response = await request('POST', '/api/helper/login', '{bad json', undefined, 'application/json');
    assert.equal(response.status, 400);
    assert.match(response.contentType, /application\/json/);
    assert.deepEqual(JSON.parse(response.body), {
      message: 'Invalid request.',
      errors: [{ field: 'body', message: 'must contain valid JSON' }],
    });
  });
});
