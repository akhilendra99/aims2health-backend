const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const express = require("express");
const securityHeaders = require("../middleware/security-headers");
const root = path.resolve(__dirname, "..");

function loadApplicationWithFixtureRoutes() {
  const filename = path.join(root, "app.js");
  const localRequire = createRequire(filename);
  const helperRouter = express.Router();
  helperRouter.get("/fixture-error", (_req, res) => res.status(500).json({ message: "Server error" }));
  const emptyRouter = () => express.Router();
  const overrides = {
    "./routes/patients": emptyRouter(),
    "./routes/doctors": emptyRouter(),
    "./routes/patient_helpers": helperRouter,
    "./routes/admin": emptyRouter(),
    "./routes/auth": emptyRouter(),
    "./middleware/protected-files": () => (_req, _res, next) => next(),
  };
  const module = { exports: {} };
  const context = {
    module,
    exports: module.exports,
    require: id => Object.hasOwn(overrides, id) ? overrides[id] : localRequire(id),
    __dirname: root,
    __filename: filename,
    process,
    Buffer,
    console: { log() {}, error() {}, warn() {} },
    setTimeout,
    clearTimeout,
    URL,
  };
  vm.runInNewContext(`(function(exports,require,module,__filename,__dirname){${fs.readFileSync(filename, "utf8")}\n})`, context, { filename })(
    module.exports, context.require, module, filename, root,
  );
  return module.exports;
}

function start(app) {
  return new Promise(resolve => {
    const server = app.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function request(server, route, forwardedProto, method = "GET") {
  return new Promise((resolve, reject) => {
    const headers = forwardedProto ? { "X-Forwarded-Proto": forwardedProto } : {};
    const req = http.request({
      hostname: "127.0.0.1",
      port: server.address().port,
      path: route,
      method,
      headers,
    }, res => {
      const chunks = [];
      res.on("data", chunk => chunks.push(chunk));
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        rawHeaders: res.rawHeaders,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.on("error", reject);
    req.end();
  });
}

function assertRequiredHeaders(response) {
  assert.equal(response.headers["cache-control"], "no-store, no-cache, must-revalidate");
  assert.equal(response.headers["x-content-type-options"], "nosniff");
  assert.equal(response.headers["x-frame-options"], "DENY");
  assert.match(response.headers["content-security-policy"] || "", /frame-ancestors 'none'/);
  for (const name of ["cache-control", "x-content-type-options", "x-frame-options", "content-security-policy"]) {
    const count = response.rawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === name).length;
    assert.equal(count, 1, `${name} is emitted exactly once`);
  }
}

test("security headers cover login, private API, validation, and server-error responses", async t => {
  const app = express();
  app.set("trust proxy", 1);
  app.use(securityHeaders);
  app.post("/api/doctor/login", (_req, res) => res.status(401).json({ message: "Invalid Authentication Credentials!" }));
  app.get("/api/patient/private", (_req, res) => res.json({ private: true }));
  app.get("/api/invalid", (_req, res) => res.status(400).json({ message: "Invalid request." }));
  app.get("/api/error", (_req, _res, next) => next(new Error("fixture error")));
  app.use((err, _req, res, _next) => res.status(500).json({ message: "Server error" }));
  const server = await start(app);
  t.after(() => new Promise(resolve => server.close(resolve)));

  for (const [route, expectedStatus] of [
    ["/api/doctor/login", 401],
    ["/api/patient/private", 200],
    ["/api/invalid", 400],
    ["/api/error", 500],
  ]) {
    const response = await request(server, route, undefined, route === "/api/doctor/login" ? "POST" : "GET");
    assert.equal(response.status, expectedStatus);
    assertRequiredHeaders(response);
    assert.equal(response.headers["strict-transport-security"], undefined, "plain HTTP has no HSTS");
  }
});

test("application suppresses Express and application server-identifying headers on success, 404, and error", async t => {
  const app = loadApplicationWithFixtureRoutes();
  assert.equal(app.get("x-powered-by"), false, "Express X-Powered-By setting is explicitly disabled");
  const server = await start(app);
  t.after(() => new Promise(resolve => server.close(resolve)));

  for (const [route, status] of [["/health", 200], ["/not-a-route", 404], ["/api/helper/fixture-error", 500]]) {
    const response = await request(server, route);
    assert.equal(response.status, status, `${route} status`);
    assert.equal(response.headers["x-powered-by"], undefined, `${route} has no X-Powered-By`);
    assert.equal(response.headers.server, undefined, `${route} has no Server header from the Node application`);
    const identifyingHeaders = Object.entries(response.headers)
      .filter(([name, value]) => /^(server|x-powered-by)$/i.test(name) || /(?:express|node\.js|nginx\/\d|apache\/\d)/i.test(String(value)));
    assert.deepEqual(identifyingHeaders, [], `${route} does not reveal server software/version headers`);
  }
});

test("HSTS is emitted only for Express-secure requests and omits unapproved subdomain/preload flags", async t => {
  const trustedProxyApp = express();
  trustedProxyApp.set("trust proxy", 1);
  trustedProxyApp.use(securityHeaders);
  trustedProxyApp.get("/", (_req, res) => res.send("ok"));
  const trustedServer = await start(trustedProxyApp);
  t.after(() => new Promise(resolve => trustedServer.close(resolve)));

  const httpsAtTrustedProxy = await request(trustedServer, "/", "https");
  assertRequiredHeaders(httpsAtTrustedProxy);
  assert.equal(httpsAtTrustedProxy.headers["strict-transport-security"], "max-age=31536000");
  assert.doesNotMatch(httpsAtTrustedProxy.headers["strict-transport-security"], /includeSubDomains|preload/i);

  const untrustedForwardedHeaderApp = express();
  untrustedForwardedHeaderApp.use(securityHeaders);
  untrustedForwardedHeaderApp.get("/", (_req, res) => res.send("ok"));
  const untrustedServer = await start(untrustedForwardedHeaderApp);
  t.after(() => new Promise(resolve => untrustedServer.close(resolve)));
  const spoofedProto = await request(untrustedServer, "/", "https");
  assert.equal(spoofedProto.headers["strict-transport-security"], undefined,
    "an untrusted X-Forwarded-Proto header does not make the request secure");
});
