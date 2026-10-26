const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const jwt = require('jsonwebtoken');
const express = require('express');

function loadBlacklist() {
  const filename = path.resolve(__dirname, '../middleware/token-blacklist.js');
  const module = { exports: {} };
  const timers = [];
  let now = Date.now();
  class TestDate extends Date {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return now; }
  }
  const context = {
    module,
    exports: module.exports,
    require,
    Buffer,
    Date: TestDate,
    setTimeout: (callback, delay) => {
      timers.push({ callback, delay });
      return { unref() {} };
    },
  };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, { filename });
  return {
    ...module.exports,
    timers,
    now: () => now,
    advance: milliseconds => { now += milliseconds; },
  };
}

test('blacklist retains helper logout revocation through its JWT expiry', () => {
  const { blacklistToken, isBlacklisted, timers, now } = loadBlacklist();
  const token = jwt.sign({ helper_id: 17, role: 'helper' }, 'fixture-secret', { expiresIn: '7d' });

  blacklistToken(token);

  assert.equal(isBlacklisted(token), true);
  assert.equal(timers.length, 1);
  assert.ok(timers[0].delay > 6 * 24 * 60 * 60 * 1000, 'cleanup must track the seven day token lifetime');
  assert.ok(timers[0].delay >= jwt.decode(token).exp * 1000 - now(), 'cleanup cannot run before exp');
});

test('early cleanup callback reschedules and cannot remove the revocation before exp', () => {
  const { blacklistToken, isBlacklisted, timers, advance, now } = loadBlacklist();
  const token = jwt.sign({ userId: 1, role: 'patient' }, 'fixture-secret', { expiresIn: '1h' });
  blacklistToken(token);

  advance(jwt.decode(token).exp * 1000 - now() - 500);
  timers[0].callback(); // Simulate a timer firing early.

  assert.equal(isBlacklisted(token), true);
  assert.equal(timers.length, 2);
  assert.ok(timers[1].delay >= 1500, 'cleanup must wait until after exp');
});

test('missing and malformed exp retain revocation without an arbitrary timeout', () => {
  const { blacklistToken, isBlacklisted, timers } = loadBlacklist();
  const unsigned = payload => `header.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`;
  const missingExp = unsigned({ helper_id: 17 });
  const malformedExp = unsigned({ helper_id: 18, exp: 'not-a-timestamp' });

  blacklistToken(missingExp);
  blacklistToken(malformedExp);

  assert.equal(isBlacklisted(missingExp), true);
  assert.equal(isBlacklisted(malformedExp), true);
  assert.equal(timers.length, 0, 'unknown expiration must not trigger premature cleanup');
});

test('expired tokens do not need blacklist retention', () => {
  const { blacklistToken, isBlacklisted, timers } = loadBlacklist();
  const token = jwt.sign({ userId: 1, role: 'patient' }, 'fixture-secret', { expiresIn: -1 });

  blacklistToken(token);

  assert.equal(isBlacklisted(token), false);
  assert.equal(timers.length, 0);
});

test('protected API rejects logged-out token through exp, then accepts a fresh token', async t => {
  const secretKeys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = secretKeys.map(key => process.env[key]);
  process.env.JWT_SECRET_PATIENT = 'session-lifecycle-patient-fixture';
  process.env.JWT_SECRET_DOC = 'session-lifecycle-doctor-fixture';
  process.env.JWT_SECRET_ADMIN = 'session-lifecycle-admin-fixture';
  t.after(() => secretKeys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));

  const blacklist = require('../middleware/token-blacklist');
  const authenticate = require('../middleware/authenticate');
  const app = express();
  app.get('/protected', authenticate(['patient']), (req, res) => res.status(200).send('ok'));
  const server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const request = async token => fetch(`http://127.0.0.1:${server.address().port}/protected`, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(5000),
  });

  const capturedToken = jwt.sign({ userId: 71, role: 'patient' }, process.env.JWT_SECRET_PATIENT, { expiresIn: '2s' });
  blacklist.blacklistToken(capturedToken); // Same server-side action used by logout routes.
  assert.equal((await request(capturedToken)).status, 401);
  assert.equal(blacklist.isBlacklisted(capturedToken), true);

  await new Promise(resolve => setTimeout(resolve, 3200));
  assert.equal(blacklist.isBlacklisted(capturedToken), false, 'cleanup removes the expired revocation entry');
  assert.equal((await request(capturedToken)).status, 401, 'JWT expiry still rejects the old token after cleanup');

  const freshToken = jwt.sign({ userId: 71, role: 'patient' }, process.env.JWT_SECRET_PATIENT, { expiresIn: '1m' });
  assert.equal((await request(freshToken)).status, 200, 'fresh post-logout credential is accepted');
});

