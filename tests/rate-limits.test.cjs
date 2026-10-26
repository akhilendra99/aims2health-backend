const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const express = require("express");

const root = path.resolve(__dirname, "..");

function loadApp() {
  const filename = path.join(root, "app.js");
  const localRequire = createRequire(filename);
  const pass = (req, res, next) => next();
  const router = () => {
    const instance = express.Router();
    instance.use((req, res) => res.status(200).json({ handlerReached: true }));
    return instance;
  };
  const overrides = {
    "./middleware/security-headers": pass,
    "./middleware/csrf-protection": {
      requireTrustedOrigin: () => pass,
      requireCsrfToken: pass,
    },
    "./middleware/helper-json-errors": pass,
    "./middleware/protected-files": () => pass,
    "./routes/patients": router(),
    "./routes/doctors": router(),
    "./routes/patient_helpers": router(),
    "./routes/admin": router(),
    cors: () => pass,
  };
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
  vm.runInNewContext(
    `(function(exports,require,module,__filename,__dirname){${fs.readFileSync(filename, "utf8")}\n})`,
    context,
    { filename },
  )(module.exports, context.require, module, filename, path.dirname(filename));
  return module.exports;
}

async function withServer(app, run) {
  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const request = async route => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
      signal: AbortSignal.timeout(5000),
    });
    return { status: response.status, body: await response.json() };
  };
  try {
    await run(request);
  } finally {
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(resolve));
  }
}

const recoveryRoutes = [
  "/api/patient/forgetpwd",
  "/api/doctor/forgetpwd",
  "/api/helper/forgetpwd",
];
const otpRoutes = [
  "/api/patient/sendPhoneVerifyOTP",
  "/api/patient/sendEmailVerifyOTP",
  "/api/patient/send-otp-login",
  "/api/helper/sendPhoneVerifyOTP",
  "/api/helper/sendEmailVerifyOTP",
  "/api/patient/verify-otp-login",
  "/api/patient/verifyPhone",
  "/api/patient/verifyEmail",
  "/api/helper/verifyPhoneOTP",
  "/api/helper/verifyEmailOTP",
];

test("recovery limit is mounted before every recovery route and keeps a generic response", async () => {
  for (const route of recoveryRoutes) {
    await withServer(loadApp(), async request => {
      for (let attempt = 0; attempt < 5; attempt++) {
        const allowed = await request(route);
        assert.equal(allowed.status, 200, `${route} allowed request ${attempt + 1}`);
        assert.deepEqual(allowed.body, { handlerReached: true });
      }
      const limited = await request(route);
      assert.equal(limited.status, 429, `${route} rejects request 6`);
      assert.deepEqual(limited.body, { message: "If the account is eligible, instructions will be sent." });
    });
  }
});

test("OTP send and verification limits are mounted before all public and authenticated OTP routes", async () => {
  for (const route of otpRoutes) {
    await withServer(loadApp(), async request => {
      for (let attempt = 0; attempt < 5; attempt++) {
        const allowed = await request(route);
        assert.equal(allowed.status, 200, `${route} allowed request ${attempt + 1}`);
      }
      const limited = await request(route);
      assert.equal(limited.status, 429, `${route} rejects request 6`);
      const expectedMessage = route.includes("/send")
        ? "Too many OTP requests. Please try again later."
        : "Too many OTP verification attempts. Please try again later.";
      assert.deepEqual(limited.body, { message: expectedMessage });
    });
  }
});