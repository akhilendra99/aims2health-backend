const express = require("express");
const app = express();
app.disable("x-powered-by");
const crypto = require("crypto");

// Nginx sits directly in front of this process (127.0.0.1:9000) as the only
// reverse proxy — trust exactly that one hop so express-rate-limit and
// req.ip see the real client IP from X-Forwarded-For instead of nginx's own
// local address (which would either bucket every user's rate limit together
// or throw ERR_ERL_UNEXPECTED_X_FORWARDED_FOR, both observed in production).
app.set("trust proxy", 1);
const bodyParser = require("body-parser");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const { requireTrustedOrigin, requireCsrfToken } = require("./middleware/csrf-protection");

const patientRoutes = require("./routes/patients");
const doctorsRoutes = require("./routes/doctors");
const p_helpersRoutes = require("./routes/patient_helpers");
const adminRoutes = require("./routes/admin");
const authRoutes = require("./routes/auth");

const cors = require("cors");

const allowedOrigins = [
  "https://aims2.health",
  "https://backend.aims2.health",
  "https://aims2health.co.in",
  "http://localhost:4200",
  "https://niva-backend.aims2.health",
  "https://backend.aims2health.co.in",
];

// Security headers are configured before all routes and file delivery.
app.use(require("./middleware/security-headers"));

// ✅ Use CORS properly (no need for manual headers + *)
app.use(
  cors({
    origin: allowedOrigins,
    allowedHeaders: [
      "Origin",
      "X-Requested-With",
      "Content-Type",
      "Accept",
      "x-client-key",
      "x-client-token",
      "x-client-secret",
      "Authorization", // ✅ allow auth header
      "x-csrf-token",
    ],
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE"],
    exposedHeaders: ["Authorization", "Conversation", "Content-Disposition"],
    credentials: true,
  }),
);
// Preflight is handled by the cors() middleware above, which validates
// origin before responding — no blanket app.options("*", cors()) override.

app.use(cookieParser());

// Defense-in-depth CSRF protection: only bites on state-changing requests
// that carry an HttpOnly auth cookie (see middleware/csrf-protection.js
// for why header-based auth call sites are left untouched).
app.use(requireTrustedOrigin(allowedOrigins));
app.use(requireCsrfToken);

// Strict rate limit for auth endpoints (mitigates brute-force / credential stuffing)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many login attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/patient/login", authLimiter);
app.use("/api/doctor/login", authLimiter);
app.use("/api/admin/login", authLimiter);
app.use("/api/helper/login", authLimiter);
const recoveryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: "If the account is eligible, instructions will be sent." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/patient/forgetpwd", recoveryLimiter);
app.use("/api/doctor/forgetpwd", recoveryLimiter);
app.use("/api/helper/forgetpwd", recoveryLimiter);

function sendOtpLimitResponse(req, res, options) {
  const resetTime = req.rateLimit?.resetTime;
  if (resetTime instanceof Date) {
    const retryAfter = Math.max(1, Math.ceil((resetTime.getTime() - Date.now()) / 1000));
    res.set("Retry-After", String(retryAfter));
  }
  res.status(options.statusCode).json(options.message);
}
// Rate limit for OTP-sending endpoints (mitigates OTP flooding / SMS-cost abuse
// and brute-force OTP guessing via unlimited resend)
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: "Too many OTP requests. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, _next, options) => sendOtpLimitResponse(req, res, options),
});
app.use("/api/patient/sendPhoneVerifyOTP", otpLimiter);
app.use("/api/patient/sendEmailVerifyOTP", otpLimiter);
app.use("/api/patient/send-otp-login", otpLimiter);
app.use("/api/helper/sendPhoneVerifyOTP", otpLimiter);
app.use("/api/helper/sendEmailVerifyOTP", otpLimiter);
// Limit code-guessing attempts independently from OTP sends. These existing
// verification routes serve public login, registration, and authenticated
// contact-verification flows; using one shared limiter avoids route-specific
// bypasses while preserving the same per-IP policy across the OTP surface.
const otpVerificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: "Too many OTP verification attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, _next, options) => sendOtpLimitResponse(req, res, options),
});
app.use("/api/patient/verify-otp-login", otpVerificationLimiter);
app.use("/api/patient/verifyPhone", otpVerificationLimiter);
app.use("/api/patient/verifyEmail", otpVerificationLimiter);
app.use("/api/helper/verifyPhoneOTP", otpVerificationLimiter);
app.use("/api/helper/verifyEmailOTP", otpVerificationLimiter);

// Increase payload size limit
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));
// Contact-scoped limiting complements the broad per-IP limits above, so
// rotating source IPs does not bypass OTP send or code-guessing limits.
// Rate-limit stores receive only a keyed digest of normalized contact values.
const otpRateLimitSecret = process.env.OTP_RATE_LIMIT_SECRET || process.env.JWT_SECRET_PATIENT || crypto.randomBytes(32);

function otpContactKey(req, operation) {
  const route = String(req.originalUrl || req.path || "").split("?")[0].toLowerCase();
  const body = req.body || {};
  const isPhone = route.includes("phone");
  const contactType = isPhone ? "phone" : "email";
  const rawContact = isPhone ? body.phone : body.email;
  const normalizedContact = isPhone
    ? String(rawContact || "").replace(/\D/g, "").slice(-10)
    : String(rawContact || "").trim().toLowerCase().slice(0, 254);
  const roleScope = route.startsWith("/api/helper/") ? "helper" : "patient";
  const purpose = route.includes("-otp-login")
    ? "patient-login"
    : roleScope === "helper"
      ? String(body.purpose || "patient-contact").slice(0, 40)
      : "patient-contact";
  const contactScope = normalizedContact
    ? `${roleScope}:${purpose}:${contactType}:${normalizedContact}`
    : `${roleScope}:${purpose}:${contactType}:missing:${req.ip || "unknown"}`;

  return crypto.createHmac("sha256", otpRateLimitSecret)
    .update(`${operation}:${contactScope}`)
    .digest("hex");
}

function createOtpContactLimiter(operation, message) {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    keyGenerator: req => otpContactKey(req, operation),
    message: { message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, _next, options) => {
      const resetTime = req.rateLimit?.resetTime;
      if (resetTime instanceof Date) {
        const retryAfter = Math.max(1, Math.ceil((resetTime.getTime() - Date.now()) / 1000));
        res.set("Retry-After", String(retryAfter));
      }
      res.status(options.statusCode).json(options.message);
    },
  });
}

const otpSendContactLimiter = createOtpContactLimiter("send", "Too many OTP requests. Please try again later.");
const otpVerifyContactLimiter = createOtpContactLimiter("verify", "Too many OTP verification attempts. Please try again later.");
[
  "/api/patient/sendPhoneVerifyOTP",
  "/api/patient/sendEmailVerifyOTP",
  "/api/patient/send-otp-login",
  "/api/helper/sendPhoneVerifyOTP",
  "/api/helper/sendEmailVerifyOTP",
].forEach(route => app.use(route, otpSendContactLimiter));
[
  "/api/patient/verify-otp-login",
  "/api/patient/verifyPhone",
  "/api/patient/verifyEmail",
  "/api/helper/verifyPhoneOTP",
  "/api/helper/verifyEmailOTP",
].forEach(route => app.use(route, otpVerifyContactLimiter));

// Keep malformed JSON errors for the Helper Dashboard API within its public
// request-validation contract, without changing error handling for other APIs.
app.use(require("./middleware/helper-json-errors"));

app.use("/images", require("./middleware/protected-files")());

// Health check
app.get("/health", (req, res) => {
  res.status(200).send("Ok");
});

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/patient", patientRoutes);
app.use("/api/doctor", doctorsRoutes);
app.use("/api/helper", p_helpersRoutes);
app.use("/api/admin", adminRoutes);

module.exports = app;




