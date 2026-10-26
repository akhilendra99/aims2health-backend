const test = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const securityHeaders = require("../middleware/security-headers");

test("CSP is enforced once with only required same-origin sources on HTML responses", async t => {
  const app = express();
  app.use(securityHeaders);
  app.get("/", (_req, res) => res.type("html").send("<!doctype html><title>fixture</title>"));

  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(async () => {
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(resolve));
  });

  const response = await fetch(`http://127.0.0.1:${server.address().port}/`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/html/);

  const cspHeaders = response.headers.raw?.()["content-security-policy"];
  if (cspHeaders) assert.equal(cspHeaders.length, 1, "exactly one enforced CSP header is present");
  const policy = response.headers.get("content-security-policy");
  assert.ok(policy, "CSP header is present");
  assert.match(policy, /default-src 'self'/);
  assert.match(policy, /script-src 'self'/);
  assert.match(policy, /style-src 'self'/);
  assert.match(policy, /img-src 'self' data:/);
  assert.match(policy, /font-src 'self'/);
  assert.match(policy, /connect-src 'self'/);
  assert.match(policy, /object-src 'none'/);
  assert.match(policy, /base-uri 'self'/);
  assert.match(policy, /frame-ancestors 'none'/);
  assert.match(policy, /form-action 'self'/);
  assert.doesNotMatch(policy, /unsafe-inline|unsafe-eval|https:|\*/);
  assert.equal((policy.match(/default-src/g) || []).length, 1, "policy has no duplicate default-src directive");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
});
