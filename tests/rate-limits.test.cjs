const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const express = require("express");

const root = path.resolve(__dirname, "..");

function loadApp({ onHandler } = {}) {
  const filename = path.join(root, "app.js");
  const localRequire = createRequire(filename);
  const pass = (req, res, next) => next();
  const router = () => {
    const instance = express.Router();
    instance.use((req, res) => {
      onHandler?.(req, res);
      if (!res.headersSent) res.status(200).json({ handlerReached: true });
    });
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
  const request = async (route, { body = {}, headers = {} } = {}) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    return { status: response.status, headers: response.headers, body: await response.json() };
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
      assert.match(limited.headers.get("retry-after") || "", /^\d+$/);
    });
  }
});
test("contact-scoped send limits survive source-IP rotation, normalize email, and stop handler side effects", async () => {
  let handlerCalls = 0;
  await withServer(loadApp({ onHandler: () => { handlerCalls++; } }), async request => {
    const route = "/api/patient/send-otp-login";
    for (let attempt = 1; attempt <= 5; attempt++) {
      const allowed = await request(route, {
        body: { email: "Otp-Target@test.invalid" },
        headers: { "X-Forwarded-For": `198.51.100.${attempt}` },
      });
      assert.equal(allowed.status, 200, `request ${attempt} is allowed`);
    }
    const limited = await request(route, {
      body: { email: " otp-target@TEST.invalid " },
      headers: { "X-Forwarded-For": "198.51.100.6" },
    });
    assert.equal(limited.status, 429);
    assert.deepEqual(limited.body, { message: "Too many OTP requests. Please try again later." });
    assert.match(limited.headers.get("retry-after") || "", /^\d+$/);
    assert.equal(handlerCalls, 5, "rate-limited send never reaches the OTP/provider handler");

    const otherContact = await request(route, {
      body: { email: "other@test.invalid" },
      headers: { "X-Forwarded-For": "198.51.100.7" },
    });
    assert.equal(otherContact.status, 200, "another contact keeps its own bucket");
  });
});

test("incorrect and missing OTP submissions with a contact are limited by normalized contact and purpose", async () => {
  let handlerCalls = 0;
  await withServer(loadApp({ onHandler: (_req, res) => {
    handlerCalls++;
    res.status(400).json({ message: "Invalid or expired OTP" });
  } }), async request => {
    const route = "/api/helper/verifyPhoneOTP";
    const attempts = [
      { phone: "+1 (555) 123-4567", countryCode: "1", otp: "0000", purpose: "helper-registration" },
      { phone: "15551234567", countryCode: "1", otp: "0000", purpose: "helper-registration" },
      { phone: "5551234567", countryCode: "1", purpose: "helper-registration" },
      { phone: "555-123-4567", countryCode: "1", otp: "9999", purpose: "helper-registration" },
      { phone: "5551234567", countryCode: "1", otp: "nope", purpose: "helper-registration" },
    ];
    for (let i = 0; i < attempts.length; i++) {
      const invalid = await request(route, {
        body: attempts[i],
        headers: { "X-Forwarded-For": `203.0.113.${i + 1}` },
      });
      assert.equal(invalid.status, 400, `invalid attempt ${i + 1} reaches verification`);
      assert.deepEqual(invalid.body, { message: "Invalid or expired OTP" });
    }
    const limited = await request(route, {
      body: { phone: "5551234567", countryCode: "1", otp: "0001", purpose: "helper-registration" },
      headers: { "X-Forwarded-For": "203.0.113.6" },
    });
    assert.equal(limited.status, 429);
    assert.deepEqual(limited.body, { message: "Too many OTP verification attempts. Please try again later." });
    assert.match(limited.headers.get("retry-after") || "", /^\d+$/);
    assert.equal(handlerCalls, 5, "rate-limited guesses never reach OTP comparison");

    const otherPurpose = await request(route, {
      body: { phone: "5551234567", countryCode: "1", otp: "0000", purpose: "patient-contact" },
      headers: { "X-Forwarded-For": "203.0.113.7" },
    });
    assert.equal(otherPurpose.status, 400, "purpose-specific challenge gets a separate bucket");
  });
});



test("contact-scoped limits cover every OTP endpoint category", async () => {
  for (const route of otpRoutes) {
    let handlerCalls = 0;
    const isPhone = route.toLowerCase().includes("phone");
    const isHelper = route.startsWith("/api/helper/");
    const isLogin = route.includes("-otp-login");
    const contact = isPhone ? "5551234567" : "same-target@test.invalid";
    const body = {
      [isPhone ? "phone" : "email"]: contact,
      ...(isPhone ? { countryCode: "1" } : {}),
      ...(isHelper ? { purpose: "helper-registration" } : {}),
      ...(route.toLowerCase().includes("verify") ? { otp: "0000" } : {}),
    };
    const app = loadApp({ onHandler: (_req, res) => {
      handlerCalls++;
      if (route.toLowerCase().includes("verify")) {
        res.status(isLogin ? 401 : 400).json({ message: "Invalid or expired OTP" });
      }
    } });

    await withServer(app, async request => {
      for (let attempt = 1; attempt <= 5; attempt++) {
        const allowed = await request(route, {
          body,
          headers: { "X-Forwarded-For": `192.0.2.${attempt}` },
        });
        assert.notEqual(allowed.status, 429, `${route} permits attempt ${attempt}`);
      }
      const limited = await request(route, {
        body,
        headers: { "X-Forwarded-For": "192.0.2.6" },
      });
      assert.equal(limited.status, 429, `${route} limits attempt six`);
      assert.equal(handlerCalls, 5, `${route} limiter runs before route side effects`);
      assert.match(limited.headers.get("retry-after") || "", /^\d+$/);
    });
  }
});

test("patient contact limit ignores untrusted purpose fields", async () => {
  let handlerCalls = 0;
  await withServer(loadApp({ onHandler: () => { handlerCalls++; } }), async request => {
    const route = "/api/patient/verifyEmail";
    for (let attempt = 1; attempt <= 5; attempt++) {
      const allowed = await request(route, {
        body: { email: "patient@test.invalid", otp: "0000", purpose: `attacker-${attempt}` },
        headers: { "X-Forwarded-For": `192.0.2.${attempt}` },
      });
      assert.equal(allowed.status, 200);
    }
    const limited = await request(route, {
      body: { email: "PATIENT@test.invalid", otp: "0000", purpose: "different" },
      headers: { "X-Forwarded-For": "192.0.2.6" },
    });
    assert.equal(limited.status, 429);
    assert.equal(handlerCalls, 5);
  });
});

