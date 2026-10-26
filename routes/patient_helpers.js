const express = require("express");
const router = express.Router();
const publicRecord = require("../utils/public-record");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const axios = require("axios");
const crypto = require("crypto");
const zeptomail = require("../utils/zeptomail");
const Razorpay = require("razorpay");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");
dotenv.config();

const { generateCsrfToken, CSRF_COOKIE } = require("../middleware/csrf-protection");
const { authCookieOptions, csrfCookieOptions, clearCookieOptions, csrfClearCookieOptions } = require("../utils/auth-cookies");
const { validateRequest, validateUploadedFile } = require("../middleware/validate-request");
const { buildLimit } = require("../utils/pagination");
const { comparePasswordOrDummy } = require("../utils/password-auth");

const twilio_accountSid = process.env.TWILIO_AC_SID;
const twilio_authToken = process.env.TWILIO_AUTHTOKEN;
const twilio_client = require("twilio")(twilio_accountSid, twilio_authToken);

const razorpay_instance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const passwordExpression =
  /^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,16}$/;
const emailInput = { type: "email", maxLength: 100, allowEmpty: true };
const phoneInput = { type: "phone", maxLength: 30, pattern: /^\+?[\d\s().-]{7,30}$/, allowEmpty: true };
const countryCodeInput = { type: "string", maxLength: 10, pattern: /^\+?\d{1,4}$/, allowEmpty: true };
const otpProofInput = { type: "string", maxLength: 48, pattern: /^[a-f\d]{48}$/i, allowEmpty: true };

const registerInput = validateRequest({
  body: {
    email_id: emailInput,
    phone_no: phoneInput,
    password: { type: "string", required: true, nonEmpty: true, maxBytes: 72 },
    phoneVerificationToken: otpProofInput,
    emailVerificationToken: otpProofInput,
    role: { type: "string", maxLength: 20 }, // Legacy client field; never trusted for authorization.
  },
  refine: ({ body }) => body.email_id || body.phone_no
    ? []
    : [{ field: "body", message: "email_id or phone_no is required" }],
});
const loginInput = validateRequest({
  body: {
    email_id: emailInput,
    phone_no: phoneInput,
    password: { type: "string", required: true, nonEmpty: true, maxBytes: 72 },
    role: { type: "string", maxLength: 20 }, // Legacy client field; ignored by the issuer.
  },
  refine: ({ body }) => body.email_id || body.phone_no
    ? []
    : [{ field: "body", message: "email_id or phone_no is required" }],
});
const addPatientInput = validateRequest({
  body: {
    abhaId: { type: "string", maxLength: 255, allowEmpty: true },
    address: { type: "digits", required: true, nonEmpty: true, maxLength: 6, pattern: /^\d{6}$/ },
    adhaar: { type: "string", maxLength: 30, allowEmpty: true },
    countryCode: { ...countryCodeInput },
    dob: { type: "dateOrYear", required: true, nonEmpty: true },
    ehr_id: { type: "string", maxLength: 30, allowEmpty: true },
    email_id: emailInput,
    fname: { type: "string", required: true, nonEmpty: true, maxLength: 50 },
    gender: { type: "string", required: true, nonEmpty: true, maxLength: 20 },
    password: { type: "string", maxBytes: 72, allowEmpty: true },
    helper_id: { type: "id" }, // Accepted for legacy clients; overwritten by authenticated identity.
    id_type: { type: "string", maxLength: 30, allowEmpty: true },
    lname: { type: "string", required: true, nonEmpty: true, maxLength: 50 },
    medical_history: { type: "string", required: true, nonEmpty: true, maxBytes: 65535 },
    mobile_no: { type: "phone", required: true, nonEmpty: true, maxLength: 30, pattern: /^\+?[\d\s().-]{10,30}$/ },
    mobile_secondary: { ...phoneInput },
    sec_countryCode: { ...countryCodeInput },
    whatsapp_no: { type: "digits", maxLength: 10, pattern: /^\d{10}$/, allowEmpty: true },
    phoneVerificationToken: otpProofInput,
    emailVerificationToken: otpProofInput,
    whatsappVerificationToken: otpProofInput,
    role: { type: "string", maxLength: 20 }, // Legacy client field; never trusted for authorization.
  },
});
const reportBodyInput = validateRequest({
  body: {
    patient_id: { type: "id", required: true },
    title: { type: "string", maxLength: 100, allowEmpty: true },
    content: { type: "string", maxBytes: 65535, allowEmpty: true },
    mediaType: { type: "string", maxLength: 30, allowEmpty: true },
    recordDate: { type: "date", allowEmpty: true },
  },
});
const updateReportBodyInput = validateRequest({
  body: {
    title: { type: "string", maxLength: 100, allowEmpty: true },
    content: { type: "string", maxBytes: 65535, allowEmpty: true },
    mediaType: { type: "string", maxLength: 30, allowEmpty: true },
    recordDate: { type: "date", allowEmpty: true },
  },
});
const changePasswordInput = validateRequest({
  body: {
    oldPassword: { type: "string", nonEmpty: true, maxBytes: 72 },
    newPassword: { type: "string", nonEmpty: true, maxLength: 16, maxBytes: 72 },
    confirmPassword: { type: "string", nonEmpty: true, maxLength: 16, maxBytes: 72 },
  },
  refine: ({ body }) => body.newPassword === body.confirmPassword
    ? []
    : [{ field: "body.confirmPassword", message: "must match newPassword" }],
});
const patientIdPathInput = { patient_id: { type: "id", required: true } };
const reportPathInput = { patient_id: { type: "id", required: true }, id: { type: "id", required: true } };
const deleteReportPathInput = { id: { type: "id", required: true } };
const reportListInput = validateRequest({
  params: patientIdPathInput,
  query: {
    pagesize: { type: "integer", min: 1, max: 100 },
    page: { type: "integer", min: 1, max: 1000000 },
  },
});
const reportIdInput = validateRequest({ params: reportPathInput });
const deleteReportInput = validateRequest({ params: deleteReportPathInput });

// Setting up multer
const MIME_TYPE_MAP = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/jpg": "jpg",
  "application/pdf": "pdf",
};

const storage = multer.diskStorage({
  destination: (req, file, call_back) => {
    const isValid = MIME_TYPE_MAP[file.mimetype];

    let error = new Error("Invalid Mime Type");
    if (isValid) {
      error = null;
    }
    // Absolute path (not cwd-dependent) with a self-healing mkdir — a
    // bare relative "images" string broke when the process's cwd wasn't
    // the backend root, producing ENOENT on every upload.
    const uploadDir = path.join(__dirname, "..", "images");
    fs.mkdirSync(uploadDir, { recursive: true });
    call_back(error, uploadDir);
  },
  filename: (req, file, call_back) => {
    const ext = MIME_TYPE_MAP[file.mimetype];
    // Strip anything but [a-z0-9] from the original filename — closes both
    // the mojibake issue (e.g. macOS's narrow-no-break-space in screenshot
    // names surviving a naive .split(" ")) and path traversal via a
    // malicious originalname (e.g. "../../etc/passwd").
    const safeName =
      path
        .basename(file.originalname, path.extname(file.originalname))
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 100) || "file";
    call_back(null, safeName + "-" + Date.now() + "." + ext);
  },
});
// ✅ Define JWT secret & expiry
// No hardcoded fallback — a guessable default secret is worse than failing
// outright if JWT_SECRET_PATIENT is ever missing from the environment.
const helperImageUpload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024, files: 1, fields: 10, fieldNameSize: 100, fieldSize: 65535 },
}).single("image");

function parseHelperImage(req, res, next) {
  helperImageUpload(req, res, error => {
    if (error) {
      if (req.file?.path) fs.unlink(req.file.path, () => {});
      return res.status(400).json({ message: "Invalid upload.", errors: [{ field: "file", message: "is invalid or exceeds the allowed size" }] });
    }
    return next();
  });
}

const validateHelperImage = validateUploadedFile({
  optional: true,
  maxBytes: 25 * 1024 * 1024,
  mimeTypes: Object.keys(MIME_TYPE_MAP),
});

const JWT_SECRET = process.env.JWT_SECRET_PATIENT;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "5h";

/////// end setting up multer

// var con = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "root",
//   database: "aims2health_main",
// });
const con = mysql
  .createPool({
    host: process.env.DBHOST,
    user: process.env.DBUSER,
    password: process.env.DBPWD,
    database: process.env.DBNAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  })
  .promise();

(async () => {
  try {
    await con.query("SELECT 1");
    console.log("Connected to MySQL Database!");
  } catch (err) {
    console.error("MySQL Connection Failed:", err.message);
    process.exit(1);
  }

  try {
    await con_ehr.query("SELECT 1");
    console.log("Connected to EHR Database (medicdb)!");
  } catch (err) {
    console.error("EHR DB Connection Failed:", err.message);
    process.exit(1);
  }
})();
const con_ehr = mysql
  .createPool({
    host: process.env.DBHOST,
    user: process.env.DBUSER,
    password: process.env.DBPWD,
    database: process.env.EHR_DBNAME || "medicdb",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  })
  .promise();

// Ensure this is imported

// WhatsApp Template API helper
const WHATSAPP_API_URL = "https://convergenow.ai/whatsapp-api/messaging_api/";
const WHATSAPP_CLIENT_ID = "917439937931"; // Put your full client_id here or in .env

async function sendWhatsAppTemplate(
  to,
  templateName,
  languageCode = "en",
  bodyParameters = [],
  buttonParameters = [],
) {
  try {
    const payload = {
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to: to.replace(/\D/g, "").slice(-10), // ensure clean 10-digit Indian number
      type: "template",
      template: {
        namespace: "264eb977_11b5_4bde_af0f_c2869b76016d", // keep your namespace
        name: templateName,
        language: {
          policy: "deterministic",
          code: languageCode,
        },
        components: [],
      },
    };

    // Add body parameters if any
    if (bodyParameters.length > 0) {
      payload.template.components.push({
        type: "body",
        parameters: bodyParameters.map((text) => ({ type: "text", text })),
      });
    }

    // Add button parameters if any (URL button example)
    if (buttonParameters.length > 0) {
      payload.template.components.push({
        type: "button",
        sub_type: "url",
        index: "0",
        parameters: buttonParameters.map((text) => ({ type: "text", text })),
      });
    }

    const response = await axios.post(
      `${WHATSAPP_API_URL}?client_id=${WHATSAPP_CLIENT_ID}`,
      payload,
      {
        headers: { "Content-Type": "application/json" },
        timeout: 10000,
      },
    );

    // WhatsApp usually returns 200 with { "messages": [...] } on success
    return { success: true, data: response.data };
  } catch (error) {
    console.error("WhatsApp API Error:", {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status,
    });
    return { success: false, error: error.message || "WhatsApp send failed" };
  }
}

const authorization = require('../utils/authorization')(async (sql, values) => (await con.query(sql, values))[0]);
const helperSession = authorization.guard(['helper']);
const helperPatient = id => authorization.guard(['helper'], async (req, access) => Boolean(req.authorizedPatient = await access.patient(req.userData, id(req))));
const helperReport = authorization.guard(['helper'], async (req, access) => {
  const params = req.validatedRequest?.params || req.params;
  return Boolean(req.authorizedReport = await access.report(req.userData, params.id, params.patient_id));
});
const adminSession = authorization.guard(['admin']);

router.post("/register", registerInput, async (req, res) => {
  try {
    const { email_id, phone_no, password, phoneVerificationToken, emailVerificationToken } = req.validatedRequest.body;

    // 1️⃣ Validate: At least one identifier + password
    if ((!email_id && !phone_no) || !password) {
      return res
        .status(400)
        .json({ message: "Email or Phone and Password are required" });
    }

    // 2️⃣ Validate Email Format (if provided)
    if (email_id) {
      const emailRegex = /^\S+@\S+\.\S+$/;
      if (!emailRegex.test(email_id)) {
        return res.status(400).json({ message: "Invalid email format" });
      }
    }

    // 3️⃣ Clean and validate Phone (if provided)
    let cleanPhone = null;
    if (phone_no) {
      const rawPhone = String(phone_no).replace(/\D/g, ""); // Remove non-digits
      cleanPhone = rawPhone.slice(-10); // Last 10 digits
      if (!/^\d{10}$/.test(cleanPhone)) {
        return res.status(400).json({ message: "Phone must have 10 digits" });
      }
    }

    const cleanEmail = email_id ? String(email_id).trim().toLowerCase() : null;
    if (cleanPhone && (!phoneVerificationToken || !hasVerificationToken(verifiedPhoneTokens, verificationKey("helper-registration", cleanPhone), phoneVerificationToken))) {
      return res.status(400).json({ message: "Phone number must be verified with OTP before registration." });
    }
    if (cleanEmail && (!emailVerificationToken || !hasVerificationToken(verifiedEmailTokens, verificationKey("helper-registration", cleanEmail), emailVerificationToken))) {
      return res.status(400).json({ message: "Email address must be verified with OTP before registration." });
    }

    // 4️⃣ Check for existing user (by email OR phone)
    const conditions = [];
    const values = [];

    if (email_id) {
      conditions.push("email_id = ?");
      values.push(email_id);
    }
    if (cleanPhone) {
      conditions.push("mobile = ?");
      values.push(cleanPhone);
    }

    const whereClause = conditions.join(" OR ");
    const [existing] = await con.query(
      `SELECT helper_id FROM helper_details WHERE ${whereClause}`,
      values,
    );

    if (existing.length > 0) {
      return res
        .status(400)
        .json({ message: "Registration could not be completed with these details." });
    }

    if (cleanPhone && !consumeVerificationToken(verifiedPhoneTokens, verificationKey("helper-registration", cleanPhone), phoneVerificationToken)) {
      return res.status(400).json({ message: "Phone verification expired. Please verify again." });
    }
    if (cleanEmail && !consumeVerificationToken(verifiedEmailTokens, verificationKey("helper-registration", cleanEmail), emailVerificationToken)) {
      return res.status(400).json({ message: "Email verification expired. Please verify again." });
    }

    // 5️⃣ Hash password
    const hashedPwd = await bcrypt.hash(password, 12); // 12 is stronger than 11

    // 6️⃣ Insert into DB
    const [insertResult] = await con.query(
      `INSERT INTO helper_details (email_id, mobile, hashed_pwd) 
       VALUES (?, ?, ?)`,
      [email_id || null, cleanPhone || null, hashedPwd],
    );

    // 7️⃣ Generate JWT Token (optional: auto-login after register)
    const token = jwt.sign(
      {
        helper_id: insertResult.insertId,
        email_id: email_id || null,
        mobile: cleanPhone || null,
        role: "helper",
      },
      process.env.JWT_SECRET_PATIENT,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" },
    );

    // 8️⃣ Success Response
    return res.status(201).json({
      message: "Helper registered successfully",
      token,
      helper_id: insertResult.insertId,
      user: {
        helper_id: insertResult.insertId,
        email_id: email_id || null,
        mobile: cleanPhone || null,
      },
    });
  } catch (error) {
    console.error("Register Error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

router.post("/login", loginInput, async (req, res) => {
  try {
    const { email_id, phone_no, password } = req.validatedRequest.body;

    // 1️⃣ Validate inputs
    if ((!email_id && !phone_no) || !password) {
      return res
        .status(400)
        .json({ message: "Email or Phone and Password are required" });
    }

    const field = email_id ? "email_id" : "mobile";
    const value = email_id || phone_no;

    // 2️⃣ Query user from DB
    const [results] = await con.query(
      `SELECT * FROM helper_details WHERE ${field} = ?`,
      [value],
    );

    if (results.length === 0) {
      await comparePasswordOrDummy(password, undefined, 12);
      // Deliberately identical status/message to the wrong-password branch
      // below — a distinct "user does not exist" response lets an attacker
      // enumerate registered accounts by testing email/phone values.
      return res
        .status(401)
        .json({ message: "Invalid Authentication Credentials!" });
    }

    const user = results[0];

    // 3️⃣ Compare password
    const isMatch = await comparePasswordOrDummy(password, user.hashed_pwd, 12);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "Invalid Authentication Credentials!" });
    }

    // 4️⃣ Generate JWT token
    const token = jwt.sign(
      {
        helper_id: user.helper_id,
        email_id: user.email_id,
        mobile: user.mobile,
        role: "helper",
      },
      process.env.JWT_SECRET_PATIENT,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" },
    );

    // 5️⃣ Send response
    const helperCookieMaxAgeMs = 7 * 24 * 60 * 60 * 1000; // matches the 7d default above
    const csrfToken = generateCsrfToken();
    res.cookie("auth_token", token, authCookieOptions(helperCookieMaxAgeMs));
    res.cookie(CSRF_COOKIE, csrfToken, csrfCookieOptions(helperCookieMaxAgeMs));
    return res.json({
      message: "Login successful",
      token,
      user: {
        helper_id: user.helper_id,
        email_id: user.email_id,
        mobile: user.mobile,
      },
    });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

router.post("/add-patient", addPatientInput, helperSession, async (req, res) => {
  let ehrConn;
  try {
    // 1. Token check (Authorization header, falling back to the auth_token cookie)
    const authHeader = req.headers["authorization"];
    let token;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies && req.cookies.auth_token) {
      token = req.cookies.auth_token;
    }
    if (!token)
      return res.status(401).json({ message: "No token provided" });

    // 2. Verify token
    let decoded;
    try {
      decoded = jwt.verify(
        token,
        process.env.JWT_SECRET_PATIENT,
      );
    } catch (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    // 3. Extract body + ADD whatsapp_no
    let {
      abhaId,
      address,
      adhaar,
      countryCode,
      dob,
      ehr_id,
      email_id,
      fname,
      gender,
      password,
      helper_id,
      id_type,
      lname,
      medical_history,
      mobile_no,
      mobile_secondary,
      sec_countryCode,
      whatsapp_no, // ← NEW FIELD
      phoneVerificationToken,
      emailVerificationToken,
      whatsappVerificationToken,
    } = req.validatedRequest.body;

    // Preserve the accepted legacy date, year-only, and age inputs after validation.
    const dobText = String(dob).trim();
    if (/^\d{4}$/.test(dobText)) dob = `${dobText}-01-01`;
    else if (/^\d{1,3}$/.test(dobText)) dob = `${new Date().getFullYear() - Number(dobText)}-01-01`;
    else dob = dobText;

    // Require proof that mobile_no/email_id were actually OTP-verified in this
    // session before creating a patient record with them (VAPT L2 Finding 4,
    // OTP Bypass — previously verifyPhoneOTP/verifyEmailOTP and add-patient
    // were entirely unrelated API calls, so OTP verification could be skipped
    // outright with no effect on whether patient creation succeeded).
    //
    // Two exceptions, both still secure — neither lets a caller introduce a
    // brand-new, never-verified number/email:
    //  1. The helper's own contact info (decoded.* comes from a signed JWT
    //     the caller can't forge) — e.g. adding themselves as a patient.
    //  2. Contact info already used by an existing patient under this same
    //     helper — e.g. a parent's phone shared across their children's
    //     records. That number was already verified at least once to get
    //     onto the earlier patient record in the first place.
    // Phone is unconditionally required and must be verified. Email is
    // optional; if provided, it must also be verified.
    helper_id = req.userData.userId;
    const helperIdForCheck = req.userData.userId;
    if (!mobile_no) {
      return res.status(400).json({ message: "Phone number is required." });
    }
    {
      const cleanMobile = String(mobile_no).replace(/\D/g, "").slice(-10);
      const isOwnMobile = decoded.mobile && String(decoded.mobile) === cleanMobile;
      let isExistingFamilyMobile = false;
      if (!isOwnMobile && helperIdForCheck) {
        const [rows] = await con.query(
          "SELECT 1 FROM patient_details WHERE helper_id = ? AND mobile_no = ? LIMIT 1",
          [helperIdForCheck, cleanMobile],
        );
        isExistingFamilyMobile = rows.length > 0;
      }
      if (
        !isOwnMobile &&
        !isExistingFamilyMobile &&
        (!phoneVerificationToken ||
          !consumeVerificationToken(verifiedPhoneTokens, verificationKey("patient-contact", cleanMobile), phoneVerificationToken))
      ) {
        return res.status(400).json({
          message: "Phone number has not been verified. Please verify with OTP first.",
        });
      }
    }
    if (email_id) {
      const cleanEmail = String(email_id).trim().toLowerCase();
      const isOwnEmail =
        decoded.email_id && String(decoded.email_id).trim().toLowerCase() === cleanEmail;
      let isExistingFamilyEmail = false;
      if (!isOwnEmail && helperIdForCheck) {
        const [rows] = await con.query(
          "SELECT 1 FROM patient_details WHERE helper_id = ? AND LOWER(email_id) = ? LIMIT 1",
          [helperIdForCheck, cleanEmail],
        );
        isExistingFamilyEmail = rows.length > 0;
      }
      if (
        !isOwnEmail &&
        !isExistingFamilyEmail &&
        (!emailVerificationToken ||
          !consumeVerificationToken(verifiedEmailTokens, verificationKey("patient-contact", cleanEmail), emailVerificationToken))
      ) {
        return res.status(400).json({
          message: "Email address has not been verified. Please verify with OTP first.",
        });
      }
    }
    if (whatsapp_no) {
      // WhatsApp OTP is sent/verified via the same /sendPhoneVerifyOTP and
      // /verifyPhoneOTP endpoints as the primary phone (just with the
      // WhatsApp number as the "phone" param), so its verification token
      // lives in the same verifiedPhoneTokens store.
      const cleanWhatsapp = String(whatsapp_no).replace(/\D/g, "").slice(-10);
      const isOwnWhatsapp = decoded.mobile && String(decoded.mobile) === cleanWhatsapp;
      let isExistingFamilyWhatsapp = false;
      if (!isOwnWhatsapp && helperIdForCheck) {
        const [rows] = await con.query(
          "SELECT 1 FROM patient_details WHERE helper_id = ? AND whatsapp_no = ? LIMIT 1",
          [helperIdForCheck, cleanWhatsapp],
        );
        isExistingFamilyWhatsapp = rows.length > 0;
      }
      if (
        !isOwnWhatsapp &&
        !isExistingFamilyWhatsapp &&
        (!whatsappVerificationToken ||
          !consumeVerificationToken(verifiedPhoneTokens, verificationKey("patient-contact", cleanWhatsapp), whatsappVerificationToken))
      ) {
        return res.status(400).json({
          message: "WhatsApp number has not been verified. Please verify with OTP first.",
        });
      }
    }

    // Optional: Validate whatsapp_no if provided
    if (whatsapp_no) {
      whatsapp_no = String(whatsapp_no).trim();
      if (!/^\d{10}$/.test(whatsapp_no)) {
        return res
          .status(400)
          .json({ message: "WhatsApp number must be 10 digits." });
      }
    } else {
      // Optional: default to primary mobile if not provided
      whatsapp_no = null;
    }

    const medical_history_val = medical_history.trim();
    const finalPassword = password?.trim() ? password : "Test@3009";
    const hashed_pwd = await bcrypt.hash(finalPassword, 10);
    const parent_id = helper_id || null;
    const today = new Date().toISOString().split("T")[0];

    // === TRANSACTION WITH LOCK ===
    ehrConn = await con_ehr.getConnection();
    await ehrConn.beginTransaction();
    await ehrConn.query(
      "LOCK TABLES pt_key WRITE, adm_new WRITE, casesheet WRITE",
    );

    // 1. Insert into patient_details — ADD whatsapp_no
    const insertSql = `
      INSERT INTO patient_details 
      (abhaId, address, adhaar, countryCode, dob, ehr_id, email_id, fname, gender, hashed_pwd, 
       helper_id, id_type, lname, medical_history, mobile_no, mobile_secondary, parent_id, 
       sec_countryCode, whatsapp_no)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const [insertResult] = await con.query(insertSql, [
      abhaId || null,
      address,
      adhaar || null,
      countryCode || "+91",
      dob,
      ehr_id || null,
      email_id || null,
      fname.trim(),
      gender,
      hashed_pwd,
      helper_id || null,
      id_type || null,
      lname.trim(),
      medical_history_val,
      mobile_no || null,
      mobile_secondary || null,
      parent_id,
      sec_countryCode || null,
      whatsapp_no, // ← SAVED HERE
    ]);

    const patientId = insertResult.insertId;

    // 2. Get crno from pt_key (unchanged)
    const [ptKeyRows] = await ehrConn.query(
      "SELECT crno FROM pt_key ORDER BY crno ASC LIMIT 1 FOR UPDATE",
    );
    if (!ptKeyRows.length) throw new Error("pt_key missing");

    let crno = Number(ptKeyRows[0].crno) + 1;
    if (crno <= 100) {
      crno = 101;
      await ehrConn.query("UPDATE pt_key SET crno = 100");
    }

    // 3. Insert into adm_new — you can add whatsapp_no here too if needed
    await ehrConn.query(
      `INSERT INTO adm_new 
       (ma_name, lname, ma_address, Date_of_birth, Telno, cellno, sex, email, admno, vs_frontend, ma_dated, whatsapp_no)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        fname,
        lname,
        address,
        dob,
        mobile_no,
        mobile_secondary || null,
        String(gender).toUpperCase()[0],
        email_id,
        crno,
        patientId,
        today,
        whatsapp_no, // ← Also saved in adm_new (optional but recommended)
      ],
    );

    // 4. Update pt_key
    const nowSql = new Date().toISOString().slice(0, 19).replace("T", " ");
    await ehrConn.query(
      `UPDATE pt_key SET crno = ?, cr_request = 'VirtualSathi', cr_time = ? WHERE crno = ?`,
      [crno, nowSql, ptKeyRows[0].crno],
    );

    // 5. Insert casesheet
    await ehrConn.query(
      `INSERT INTO casesheet (admno, cheif_complaint, ma_index) VALUES (?, ?, '0')`,
      [crno, medical_history_val],
    );

    // 6. Update local patient_details with ehr_id
    await con.query(
      `UPDATE patient_details SET ehr_id = ? WHERE patient_id = ?`,
      [crno, patientId],
    );

    await con.query(
      `INSERT INTO patient_additional (patient_id, registrationDate, email_verification, phone_verification)
       VALUES (?, ?, 1, 1)`,
      [patientId, today],
    );

    // COMMIT
    await ehrConn.query("UNLOCK TABLES");
    await ehrConn.commit();

    return res.status(201).json({
      message: "Patient added successfully with WhatsApp number!",
      patient_id: patientId,
      ehr_id: crno,
      whatsapp_no: whatsapp_no,
      createdBy: decoded.helper_id || null,
      usedDefaultPassword: !password,
    });
  } catch (error) {
    if (ehrConn) {
      await ehrConn.query("UNLOCK TABLES").catch(() => {});
      await ehrConn.rollback();
    }
    console.error("Add Patient API Error:", error);
    return res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  } finally {
    if (ehrConn) ehrConn.release();
  }
});

router.get("/get-patients", helperSession, async (req, res) => {
  try {
    // 1. Token verification (Authorization header, falling back to the auth_token cookie)
    const authHeader = req.headers["authorization"];
    let token;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies && req.cookies.auth_token) {
      token = req.cookies.auth_token;
    }
    if (!token)
      return res.status(401).json({ message: "No token provided" });

    let decoded;
    try {
      decoded = jwt.verify(
        token,
        process.env.JWT_SECRET_PATIENT,
      );
    } catch (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    const helperId = decoded.helper_id;
    if (!helperId)
      return res.status(400).json({ message: "Invalid helper ID in token" });

    // 2. Query (same as before - no age in SQL)
    const sql = `
      SELECT 
        pd.patient_id,
        pd.abhaId,
        pd.fname,
        pd.lname,
        pd.email_id,
        pd.mobile_no,
        pd.whatsapp_no,
        pd.dob,
        pd.gender,
        pd.address,
        pd.medical_history,
        pa.email_verification,
        pa.phone_verification,
        pa.patient_consent
      FROM patient_details pd
      LEFT JOIN patient_additional pa ON pd.patient_id = pa.patient_id
      WHERE pd.helper_id = ? AND pd.parent_id = ?
    `;

    const [results] = await con.query(sql, [helperId, helperId]);

    // 3. Helper function to calculate accurate age from DOB
    const calculateAge = (dob) => {
      if (!dob) return null;

      const birthDate = new Date(dob);
      const today = new Date();

      let age = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();

      // If birthday hasn't occurred this year yet, subtract 1
      if (
        monthDiff < 0 ||
        (monthDiff === 0 && today.getDate() < birthDate.getDate())
      ) {
        age--;
      }

      return age;
    };

    // 4. Map results and add calculated age
    const patients = results.map((row) => ({
      patient_id: row.patient_id,
      abhaId: row.abhaId,
      fname: row.fname,
      lname: row.lname,
      email_id: row.email_id,
      mobile_no: row.mobile_no,
      whatsapp_no: row.whatsapp_no || "",
      dob: row.dob,
      gender: row.gender,
      address: row.address,
      medical_history: row.medical_history,
      email_verification: row.email_verification || 0,
      phone_verification: row.phone_verification || 0,
      patient_consent: row.patient_consent || 0,
      age: calculateAge(row.dob), // This is the new field
    }));

    return res.status(200).json({
      message: "Patients fetched successfully",
      patients,
    });
  } catch (error) {
    console.error("API Error:", error);
    return res
      .status(500)
      .json({ message: "Server error", error: error.message });
  }
});

router.post("/change-password", helperSession, changePasswordInput, async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    let token;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies && req.cookies.auth_token) {
      token = req.cookies.auth_token;
    }
    if (!token) {
      return res.status(401).json({ message: "Unauthorized - missing token" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET_PATIENT);
    } catch (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    const helperId = decoded.helper_id;
    if (!helperId) {
      return res.status(400).json({ message: "Invalid token payload" });
    }

    const { oldPassword, newPassword, confirmPassword } = req.validatedRequest.body;

    if (typeof newPassword !== "string" || !passwordExpression.test(newPassword)) {
      return res.status(400).json({
        message:
          "Password must be 8-16 characters and include at least one number and one special character (!@#$%^&*).",
      });
    }

    // === Use await with .promise() ===
    const [results] = await con.query(
      "SELECT helper_id, hashed_pwd FROM helper_details WHERE helper_id = ?",
      [helperId],
    );

    if (!results || results.length === 0) {
      return res.status(404).json({ message: "Helper not found" });
    }

    const user = results[0];
    const match = await bcrypt.compare(oldPassword, user.hashed_pwd);
    if (!match) {
      return res.status(500).json({ message: "Old password is incorrect" });
    }

    const newHashed = await bcrypt.hash(newPassword, 10);

    const [updateResult] = await con.query(
      "UPDATE helper_details SET hashed_pwd = ? WHERE helper_id = ?",
      [newHashed, helperId],
    );

    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ message: "Failed to update password" });
    }

    return res.status(200).json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("API Error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// In-memory OTP store
const otpStorePhone = new Map();

// Verification proof tokens: issued once an OTP is actually confirmed, and
// required by /register or /add-patient before it will accept that contact.
// this, OTP verification and patient creation were two unrelated API calls —
// nothing stopped a caller from skipping straight to /add-patient with an
// unverified phone/email (VAPT L2 Finding 4, OTP Bypass).
const verifiedPhoneTokens = new Map();
const verifiedEmailTokens = new Map();
const VERIFICATION_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes to complete the protected action
const OTP_PURPOSES = new Set(["patient-contact", "helper-registration"]);

function verificationKey(purpose, contact) {
  return `${purpose}:${contact}`;
}

function getOtpPurpose(value) {
  if (value === undefined) return "patient-contact"; // Existing add-patient clients.
  return OTP_PURPOSES.has(value) ? value : null;
}

function issueVerificationToken(store, key) {
  const token = crypto.randomBytes(24).toString("hex");
  store.set(key, { token, expiresAt: Date.now() + VERIFICATION_TOKEN_TTL_MS });
  return token;
}

function hasVerificationToken(store, key, submittedToken) {
  const record = store.get(key);
  if (!record) return false;
  if (record.expiresAt <= Date.now()) {
    store.delete(key);
    return false;
  }
  return typeof submittedToken === "string" && record.token === submittedToken;
}

function consumeVerificationToken(store, key, submittedToken) {
  if (!hasVerificationToken(store, key, submittedToken)) return false;
  store.delete(key); // single-use
  return true;
}

// ✅ Helper: Validate phone numbers (only digits)
function isValidPhone(number) {
  return /^[0-9]+$/.test(number);
}

router.post("/sendPhoneVerifyOTP", async (req, res) => {
  let challengeKey;
  try {
    const { phone, countryCode } = req.body;
    const purpose = getOtpPurpose(req.body.purpose);
    if (!purpose) return res.status(400).json({ message: "Invalid OTP purpose." });

    // Step 1: Validate input
    if (!phone || !countryCode) {
      return res.status(400).json({
        vstatus: "Invalid input",
        message: "Phone number and country code are required.",
      });
    }

    // Step 2: Clean phone – keep only last 10 digits
    const rawPhone = String(phone).replace(/\D/g, ""); // Remove non-digits
    const cleanPhone = rawPhone.slice(-10); // Last 10 digits only

    if (!/^\d{10}$/.test(cleanPhone)) {
      return res.status(400).json({
        vstatus: "Invalid phone",
        message: "Phone number must contain exactly 10 digits.",
      });
    }

    // Step 3: Check if phone already registered (only 10 digits)
    const [existingRows] = await con.query(
      "SELECT helper_id FROM helper_details WHERE mobile = ? LIMIT 1",
      [cleanPhone],
    );

    if (existingRows.length > 0) {
      return res.status(201).json({
        vstatus: "OTP sent successfully",
        message: "If eligible, an OTP has been sent to the provided phone.",
      });
    }

    // Step 4: Generate 4-digit OTP
    const otp = crypto.randomInt(1000, 10000);
    // Store OTP with 8-minute expiry
    challengeKey = verificationKey(purpose, cleanPhone);
    otpStorePhone.set(challengeKey, {
      otp,
      expiresAt: Date.now() + 8 * 60 * 1000,
    });

    // Step 5: SMS Payload – EXACTLY as you provided
    const payload = {
      user: "LH_Aims",
      password: "Aims@789",
      peid: "1201159203611670874",
      templateid: "1207167403938428753",
      sender: "AIMSDD",
      dest: cleanPhone, // Only 10-digit number
      messagetype: "T",
      message: `AIMS2Health appointment request No: ${otp} received at 22:48 Mar 30 2022. Please check appointment status in www.aims2.health`,
      deliveryreport: "yes",
    };

    // Step 6: Send SMS
    const response = await axios.post(
      "https://convergenow.ai/sms-api/sms/",
      payload,
      {
        headers: { "Content-Type": "application/json" },
        timeout: 10000,
      },
    );

    const apiStatus = String(response.data?.status || "").toLowerCase();

    // === WHATSAPP INTEGRATION STARTS HERE (ADDED) ===
    // Send WhatsApp OTP in parallel (does not affect SMS flow)
    const whatsappPayload = {
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to: "91" + cleanPhone, // Full number with country code for WhatsApp
      type: "template",
      template: {
        name: "your_otp_code",
        language: {
          code: "en",
        },
        components: [
          {
            type: "body",
            parameters: [
              {
                type: "text",
                text: otp.toString(), // OTP in message body
              },
            ],
          },
          {
            type: "button",
            sub_type: "url",
            index: "0",
            parameters: [
              {
                type: "text",
                text: otp.toString(), // Same OTP in dynamic URL button
              },
            ],
          },
        ],
      },
    };

    // Fire-and-forget WhatsApp (non-blocking, won't fail the request even if WhatsApp fails)
    axios
      .post(
        "https://convergenow.ai/whatsapp-api/messaging_api/?client_id=917439937931",
        JSON.stringify(whatsappPayload),
        {
          headers: { "Content-Type": "application/json" },
          timeout: 10000,
        },
      )
      .then((waRes) => {
        console.log("WhatsApp OTP sent successfully");
      })
      .catch((waErr) => {
        console.error("WhatsApp OTP failed (non-critical):", {
          message: waErr.message,
          status: waErr.response?.status,
        });
        // Intentionally not throwing — SMS is primary channel
      });
    // === WHATSAPP INTEGRATION ENDS HERE ===

    if (apiStatus === "accepted" || apiStatus === "success") {
      return res.status(201).json({
        vstatus: "OTP sent successfully",
        message: "If eligible, an OTP has been sent to the provided phone.",
        // response: response.data, // Optional: hide in prod
      });
    } else {
      if (challengeKey) otpStorePhone.delete(challengeKey);
      return res.status(201).json({
        vstatus: "OTP sent successfully",
        message: "If eligible, an OTP has been sent to the provided phone.",
      });
    }
  } catch (error) {
    if (challengeKey) otpStorePhone.delete(challengeKey);

    console.error("Helper phone OTP request failed.");
    return res.status(201).json({
      vstatus: "OTP sent successfully",
      message: "If eligible, an OTP has been sent to the provided phone.",
    });
  }
});

// ✅ VERIFY OTP
router.post("/verifyPhoneOTP", async (req, res) => {
  let { phone, countryCode, otp } = req.body;
  const purpose = getOtpPurpose(req.body.purpose);
  if (!purpose) return res.status(400).json({ message: "Invalid OTP purpose." });

  if (!phone || !otp) {
    return res.status(400).json({ message: "Phone and OTP are required" });
  }

  // Default to India if countryCode is missing or empty
  if (!countryCode || String(countryCode).trim() === "") {
    countryCode = "91";
  } else {
    countryCode = String(countryCode).replace(/\D/g, "");
  }

  // Clean phone number
  const rawPhone = String(phone).replace(/\D/g, "");

  let fullPhoneNumber;
  if (rawPhone.length > 10) {
    fullPhoneNumber = rawPhone;
  } else {
    fullPhoneNumber = countryCode + rawPhone;
  }

  const cleanPhone = fullPhoneNumber.slice(-10); // last 10 digits

  const challengeKey = verificationKey(purpose, cleanPhone);
  const record = otpStorePhone.get(challengeKey);

  if (!record) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  if (record.expiresAt <= Date.now()) {
    otpStorePhone.delete(challengeKey);
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  if (!/^\d{4}$/.test(String(otp)) || record.otp !== Number(otp)) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  // OTP is correct → clean up
  otpStorePhone.delete(challengeKey);

  const verificationToken = issueVerificationToken(verifiedPhoneTokens, challengeKey);

  res.json({
    vstatus: "approved",
    message: "Phone verified successfully",
    verificationToken,
  });
});

// Simplified OTP storage

const otpStore = new Map();

router.post("/sendEmailVerifyOTP", async (req, res) => {
  try {
    const { email } = req.body;
    const purpose = getOtpPurpose(req.body.purpose);
    if (!purpose) return res.status(400).json({ message: "Invalid OTP purpose." });

    // Step 1: Validate input
    if (!email || typeof email !== "string") {
      return res.status(400).json({
        vstatus: "Invalid input",
        message: "Email is required and must be a string",
      });
    }

    const emailToSend = email.trim().toLowerCase();

    // Validate email format
    const emailRegex = /^\S+@\S+\.\S+$/;
    if (!emailRegex.test(emailToSend)) {
      return res.status(400).json({
        vstatus: "Invalid email",
        message: "Please provide a valid email address",
      });
    }

    // Step 2: Check if email already registered
    const [rows] = await con.query(
      "SELECT helper_id FROM helper_details WHERE LOWER(email_id) = ? LIMIT 1",
      [emailToSend],
    );

    if (rows.length > 0) {
      return res.status(201).json({
        vstatus: "OTP sent successfully",
        message: "If eligible, an OTP has been sent to the provided email.",
      });
    }

    // Step 3: Generate 4-digit OTP
    const otp = crypto.randomInt(1000, 10000);
    // Store OTP with 8-minute expiry
    const challengeKey = verificationKey(purpose, emailToSend);
    otpStore.set(challengeKey, {
      otp,
      expiresAt: Date.now() + 8 * 60 * 1000, // 8 minutes
    });

    // Step 4: Send OTP via ZeptoMail — services.netxcell.com:8081 (the
    // previous provider) is unreachable (confirmed independently from
    // multiple networks, not an EC2-specific firewall issue). VAPT L1
    // Finding 15 / L2 Finding 18, "Broken Functionality".
    try {
      await zeptomail.sendMail({
        to: emailToSend,
        subject: "Your AIMS2Health OTP for Email Verification",
        text: `Dear User,\n\nYour OTP for email verification is: ${otp}\n\nThis OTP is valid for 10 minutes only.\n\nThank you,\nAIMS2Health Team`,
        html: `<p>Dear User,</p>
             <p>Your OTP for email verification is: <strong>${otp}</strong></p>
             <p><strong>Valid for 10 minutes only.</strong></p>
             <p>Thank you,<br><strong>AIMS2Health Team</strong></p>`,
      });

      return res.status(201).json({
        vstatus: "OTP sent successfully",
        message: "If eligible, an OTP has been sent to the provided email.",
        // Do NOT send OTP in response (security)
      });
    } catch (sendError) {
      otpStore.delete(challengeKey);
      console.error("Helper email OTP delivery failed.");
      return res.status(201).json({
        vstatus: "OTP sent successfully",
        message: "If eligible, an OTP has been sent to the provided email.",
      });
    }
  } catch (error) {
    console.error("Helper email OTP request failed.");
    return res.status(201).json({
      vstatus: "OTP sent successfully",
      message: "If eligible, an OTP has been sent to the provided email.",
    });
  }
});

router.post("/mis-info", adminSession, async (req, res) => {
  const { doctor_id, from_date, to_date } = req.body;

  try {
    // Required fields check
    if (!doctor_id || !from_date || !to_date) {
      return res.status(400).json({
        success: false,
        message: "doctor_id, from_date and to_date are required",
      });
    }

    // Date format check
    const dateFormat = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateFormat.test(from_date) || !dateFormat.test(to_date)) {
      return res.status(400).json({
        success: false,
        message: "Dates must be in YYYY-MM-DD format",
      });
    }

    const sql = `
      SELECT 
        pd.fname AS pfname,
        pd.lname AS plname,
        a.date,
        a.time,
        dd.fname AS dfname,
        dd.lname AS dlname,
        dc.fees,
        pd.medical_history,
        a.doc_type
      FROM appointments a
      INNER JOIN patient_details pd ON a.patient_id = pd.patient_id
      INNER JOIN doctor_calendar dc ON a.calendar_id = dc.calendar_id
      INNER JOIN doctor_details dd ON dd.doctor_id = dc.doctor_id
      WHERE dc.doctor_id = ?
        AND a.date BETWEEN ? AND ?
      ORDER BY a.date ASC, a.time ASC;
    `;

    // IMPORTANT: use await because con is a promise pool
    const [rows] = await con.query(sql, [doctor_id, from_date, to_date]);

    return res.status(200).json({
      success: true,
      message: "Patient details fetched successfully",
      filters: {
        doctor_id: Number(doctor_id),
        from_date,
        to_date,
      },
      data: rows,
    });
  } catch (error) {
    console.error("Database Error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while fetching patient details",
    });
  }
});

// Verify Email Endpoint
router.post("/verifyEmailOTP", (req, res) => {
  const { email, otp } = req.body;
  const purpose = getOtpPurpose(req.body.purpose);
  if (!purpose) return res.status(400).json({ message: "Invalid OTP purpose." });

  const cleanEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
  const challengeKey = verificationKey(purpose, cleanEmail);
  const record = otpStore.get(challengeKey);
  if (!record)
    return res.status(400).json({ message: "Invalid or expired OTP" });
  if (record.expiresAt <= Date.now()) {
    otpStore.delete(challengeKey);
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }
  if (!/^\d{4}$/.test(String(otp)) || record.otp !== Number(otp))
    return res.status(400).json({ message: "Invalid or expired OTP" });

  otpStore.delete(challengeKey);
  const verificationToken = issueVerificationToken(verifiedEmailTokens, challengeKey);

  res.json({ message: "Email verified successfully", verificationToken });
});

router.post(
  "/medreport",
  helperSession,
  parseHelperImage,
  reportBodyInput,
  validateHelperImage,
  helperPatient(req => req.validatedRequest.body.patient_id),
  async (req, res) => {
    try {
      const { patient_id, title, content, mediaType: submittedMediaType, recordDate } = req.validatedRequest.body;

      const urlLive = process.env.BACKEND_PROTOCOL_PROD || "";
      let imagePath = "na";
      let mediaSize = 0;
      let mediaType = "na";

      // Case 1: File uploaded
      if (req.file) {
        imagePath = urlLive + "/images/" + req.file.filename;

        // Use req.file.path (multer already gives full path) — safer than building it
        const fileInfo = fs.statSync(req.file.path);
        mediaSize = fileInfo.size; // in bytes

        mediaType = submittedMediaType?.trim() || "Unknown";
      }
      // Case 2: No file → keep 'na' and 0

      // Upload limit logic
      const [countRows] = await con.query(
        "SELECT COUNT(*) AS p_count FROM appointments WHERE patient_id = ?",
        [patient_id],
      );
      const p_count = countRows[0]?.p_count || 0;
      const uploadLimitMB = p_count > 0 ? 25 : 5;
      const uploadLimitBytes = uploadLimitMB * 1024 * 1024;

      const [sumRows] = await con.query(
        "SELECT IFNULL(SUM(mediaSize), 0) AS current_size FROM patient_med_reports WHERE patient_id = ?",
        [patient_id],
      );
      const current_size = Number(sumRows[0]?.current_size || 0);

      if (req.file && current_size + mediaSize > uploadLimitBytes) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({
          message: `Upload limit exceeded! Max allowed: ${uploadLimitMB} MB total.`,
        });
      }

      // Insert record
      const insertSql = `
        INSERT INTO patient_med_reports 
        (patient_id, report_title, content, imagePath, mediaType, recordDate, mediaSize)
        SELECT ?, ?, ?, ?, ?, ?, ? FROM patient_details WHERE patient_id = ? AND helper_id = ?
      `;

      const [result] = await con.query(insertSql, [
        patient_id,
        (title || "").trim() || "Untitled Record",
        (content || "").trim(),
        imagePath,
        mediaType,
        recordDate || new Date().toISOString().split("T")[0],
        mediaSize,
        patient_id,
        req.userData.userId,
      ]);

      if (!result.affectedRows) {
        if (req.file) fs.unlink(req.file.path, () => {});
        return res.status(404).json({ message: "Resource not found." });
      }
      return res.status(201).json({
        message: "Medical Record added successfully",
        postId: result.insertId,
      });
    } catch (err) {
      console.error("medreport error:", err);

      if (req.file && fs.existsSync(req.file.path)) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (e) {
          console.error("Cleanup failed:", e);
        }
      }

      return res.status(500).json({
        message: "Failed to add medical record",
      });
    }
  },
);

router.get("/medreports/:patient_id", reportListInput, helperPatient(req => req.validatedRequest.params.patient_id), async (req, res) => {
  try {
    const { numPerPage, currentPage } = buildLimit(req.validatedRequest.query.pagesize || 20, req.validatedRequest.query.page || 1);
    const skip = (currentPage - 1) * numPerPage;

    const patient_id = req.validatedRequest.params.patient_id;

    // total rows
    const [countRows] = await con.query(
      "SELECT COUNT(*) as numRows FROM patient_med_reports WHERE patient_id = ?",
      [patient_id],
    );
    const numRows =
      countRows && countRows[0] && countRows[0].numRows
        ? Number(countRows[0].numRows)
        : 0;
    const numPages = Math.ceil(numRows / numPerPage);

    // fetch page
    const [rows] = await con.query(
      `SELECT * FROM patient_med_reports WHERE patient_id = ? ORDER BY report_id DESC LIMIT ?, ?`,
      [patient_id, skip, numPerPage],
    );

    return res.status(200).json({
      message: "Posts fetched successfully!",
      posts: rows,
      maxPosts: numRows,
      page: currentPage,
      pages: numPages,
    });
  } catch (err) {
    console.error("medreports fetch error:", err);
    return res
      .status(500)
      .json({ message: "Fetching posts failed" });
  }
});

router.post("/update-consent", validateRequest({ body: { patient_id: { type: "id", required: true } } }), helperPatient(req => req.validatedRequest.body.patient_id), async (req, res) => {
  const { patient_id } = req.validatedRequest.body;
  const email_id = req.authorizedPatient.email_id;

  try {
    console.log("Received payload:", { patient_id, email_id });

    // Update consent
    const [updateResult] = await con.query(
      "UPDATE patient_additional pa JOIN patient_details pd ON pd.patient_id = pa.patient_id SET pa.patient_consent = 1 WHERE pa.patient_id = ? AND pd.helper_id = ?",
      [patient_id, req.userData.userId],
    );
    console.log("Update Result:", updateResult);

    if (!email_id) {
      return res
        .status(200)
        .json({ message: " Consent updated successfully " });
    }

    if (!updateResult || updateResult.affectedRows === 0) {
      return res.status(404).json({ message: "Patient not found" });
    }

    // Fetch username
    const [userRows] = await con.query(
      "SELECT fname AS name FROM patient_details WHERE patient_id = ?",
      [patient_id],
    );
    if (!Array.isArray(userRows) || userRows.length === 0) {
      return res.status(404).json({ message: "Patient details not found" });
    }
    if (!patient_id) {
      return res.status(200).json({ message: " email_id are required" });
    }
    const username = userRows[0].name;

    // Send via ZeptoMail — services.netxcell.com:8081 (the previous
    // provider) is unreachable. VAPT L1 Finding 15 / L2 Finding 18,
    // "Broken Functionality".
    try {
      await zeptomail.sendMail({
        to: email_id,
        toName: username,
        subject: "Aims2health Consent Confirmation",
        text: `Dear ${username},\nYou have provided your consent to our service. Thank you!\nThis is a confirmation of your consent submission.`,
      });
    } catch (sendError) {
      console.error(
        "Email API Error:",
        sendError?.response?.data || sendError,
      );
      return res.status(500).json({ message: "Email sending failed" });
    }

    return res
      .status(200)
      .json({ message: "Consent updated and email sent successfully" });
  } catch (error) {
    console.error(
      "Error updating consent or sending email:",
      error.stack || error,
    );
    return res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// POST /forgetpwd
router.post("/forgetpwd", validateRequest({ body: { email: { type: "email", required: true, nonEmpty: true, maxLength: 100 } } }), async (req, res) => {
  try {
    const { email } = req.validatedRequest.body;

    const sql = `SELECT * FROM helper_details WHERE email_id = ?`;
    const [result] = await con.query(sql, [email]);

    // If email NOT found → Show error
    if (!result || result.length === 0) {
      return res.status(200).json({
        success: true,
        message: "If the account is eligible, password reset instructions will be sent.",
      });
    }

    const user = result[0];

    // Was a hardcoded literal (a copy of JWT_SECRET_PATIENT baked into
    // source) — moved to env so it tracks secret rotation and isn't
    // exposed via code shared externally (e.g. the VAPT auditor zip).
    // Must stay consistent with the verify side in routes/patients.js's
    // /forgetpwdresetpwd handler.
    const secret = process.env.JWT_SECRET_PATIENT + user.email_id + user.hashed_pwd;

    const token = jwt.sign(
      { email: user.email_id, userId: user.helper_id, role: "helper" },
      secret,
      { expiresIn: "10m" },
    );

    const link = `${process.env.FRONTEND_URL}/presetpwd/${user.helper_id}/${token}`;

    // Send via ZeptoMail — services.netxcell.com:8081 (the previous
    // provider) is unreachable (confirmed independently from multiple
    // networks, not an EC2-specific firewall issue). VAPT L1 Finding 15 /
    // L2 Finding 18, "Broken Functionality".
    try {
      await zeptomail.sendMail({
      to: user.email_id,
      toName: "Helper",
      subject: "AIMS2Health Login Password Reset",
      text: `Dear Helper,\nYour AIMS2Health login password reset link is ${link}.\nThis link is valid for only 10 minutes.\n\nIf you didn't request this, please ignore this email.`,
      html: `<p>Dear Helper,</p><p>Your AIMS2Health login password reset link is <a href="${link}" style="color:blue;">${link}</a>.</p><p>This link is valid for only <strong>10 minutes</strong>.</p><p>If you didn't request this, please ignore this email.</p>`,
      });
    } catch (sendError) {
      console.error("Helper password reset delivery failed.");
    }

    // Success response (email exists and mail sent)
    res.status(200).json({
      success: true,
      message: "If the account is eligible, password reset instructions will be sent.",
    });
  } catch (error) {
    console.error("Helper password recovery request failed.");
    return res.status(500).json({
      success: false,
      message: "Server error. Please try again later.",
    });
  }
});
router.get("/medreports/:patient_id/:id", reportIdInput, helperPatient(req => req.validatedRequest.params.patient_id), async (req, res) => {
  try {
    const { patient_id, id } = req.validatedRequest.params;
    const [rows] = await con.query('SELECT * FROM patient_med_reports WHERE report_id = ? AND patient_id = ?', [id, patient_id]);
    if (!rows.length) return res.status(404).json({ message: 'Resource not found.' });
    return res.status(200).json(rows);
  } catch (err) {
    return res.status(500).json({ message: 'Could not fetch medical report.' });
  }
});
router.put(
  "/medreport/:patient_id/:id",
  reportIdInput,
  helperReport,
  parseHelperImage,
  updateReportBodyInput,
  validateHelperImage,
  async (req, res) => {
    try {
      const { patient_id, id: report_id } = req.validatedRequest.params;
      const { title, content, mediaType: submittedMediaType, recordDate } = req.validatedRequest.body;

      // Default values when no file
      let imagePath = req.authorizedReport.imagePath || "na";
      let mediaType = req.authorizedReport.mediaType || "na";
      let mediaSize = req.authorizedReport.mediaSize || 0;

      // Check storage limit first (same logic as add)
      const [countRows] = await con.query(
        "SELECT COUNT(*) AS p_count FROM appointments WHERE patient_id = ?",
        [patient_id],
      );
      const p_count = countRows[0]?.p_count || 0;
      const uploadLimitMB = p_count > 0 ? 25 : 5;
      const uploadLimitBytes = uploadLimitMB * 1024 * 1024;

      // Current total size (excluding current record)
      const [sumRows] = await con.query(
        `SELECT IFNULL(SUM(mediaSize), 0) AS current_size 
         FROM patient_med_reports 
         WHERE patient_id = ? AND report_id != ?`,
        [patient_id, report_id],
      );
      const current_size = Number(sumRows[0]?.current_size || 0);

      // If new file is uploaded
      if (req.file) {
        imagePath =
          (process.env.BACKEND_PROTOCOL_PROD || "") +
          "/images/" +
          req.file.filename;
        const fileInfo = fs.statSync(req.file.path);
        mediaSize = fileInfo.size;

        // Check limit before saving
        if (current_size + mediaSize > uploadLimitBytes) {
          fs.unlinkSync(req.file.path); // delete file
          return res.status(400).json({
            message: `Upload limit exceeded! Max allowed: ${uploadLimitMB} MB total.`,
          });
        }

        mediaType = submittedMediaType?.trim() || "Unknown";
      }
      // If no file → keep 'na' values

      // Update query
      const updateSql = `
        UPDATE patient_med_reports r JOIN patient_details pd ON pd.patient_id = r.patient_id
        SET 
          report_title = ?, 
          content = ?, 
          imagePath = ?, 
          mediaType = ?, 
          recordDate = ?,
          mediaSize = ?
        WHERE r.report_id = ? AND r.patient_id = ? AND pd.helper_id = ?
      `;

      const [result] = await con.query(updateSql, [
        (title || "").trim() || "Untitled Record",
        (content || "").trim(),
        imagePath,
        mediaType,
        recordDate || new Date().toISOString().split("T")[0],
        mediaSize,
        report_id,
        patient_id,
        req.userData.userId,
      ]);

      if (result.affectedRows === 0) {
        // If file was uploaded but record not found → delete file
        if (req.file && fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
        return res
          .status(404)
          .json({ message: "Record not found or not authorized" });
      }

      return res.status(200).json({
        message: "Medical record updated successfully",
      });
    } catch (err) {
      console.error("Update medreport error:", err);

      // Clean up uploaded file if error occurred
      if (req.file && fs.existsSync(req.file.path)) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (e) {
          console.error("Failed to delete file after error:", e);
        }
      }

      return res.status(500).json({
        message: "Failed to update medical record",
      });
    }
  },
);

router.delete("/medrecords/:id", deleteReportInput, helperReport, async (req, res, next) => {
  const reportId = req.validatedRequest.params.id;

  var sql = `DELETE r FROM patient_med_reports r JOIN patient_details pd ON pd.patient_id = r.patient_id WHERE r.report_id = ? AND pd.helper_id = ?`;

  try {
    const [result] = await con.query(sql, [reportId, req.userData.userId]);

    if (!result.affectedRows) return res.status(404).json({ message: "Resource not found." });
    console.log("Number of records deleted: " + result.affectedRows);
    res.status(200).json({ message: "Patient deleted!" });
  } catch (err) {
    console.log(err);
    // Still respond even on error (as per original)
    res.status(500).json({ message: "Could not delete record." });
  }
});
router.post("/search", helperSession, validateRequest({
  body: {
    appmntDate: { type: "date", required: true },
    docType: { type: "string", required: true, nonEmpty: true, maxLength: 50 },
  },
}), async (req, res) => {
  try {
    const { appmntDate, docType } = req.validatedRequest.body;

    const sql = `SELECT * FROM ((doctor_calendar INNER JOIN doctor_details ON doctor_calendar.doctor_id = doctor_details.doctor_id) INNER JOIN doctor_additional ON doctor_calendar.doctor_id = doctor_additional.doctor_id)  WHERE doctor_calendar.date= ? AND doctor_calendar.doc_type= ?`;

    console.log(sql);

    const [result] = await con.query(sql, [appmntDate, docType]);

    if (result.length > 0) {
      res.status(201).json({
        message: "Search results fetched successfully",
        searchedResults: result.map(publicRecord),
      });
    } else {
      res.status(404).json({
        message: "No specified dcotor is available on the given date!",
      });
    }
  } catch (err) {
    console.log(err);
    res.status(401).json({
      message: "Searching Appointment failed!",
    });
  }
});

const { blacklistToken } = require("../middleware/token-blacklist");
router.post("/logout", helperSession, (req, res) => {
  blacklistToken(req.userData.token);
  res.clearCookie("auth_token", clearCookieOptions());
  res.clearCookie(CSRF_COOKIE, csrfClearCookieOptions());
  res.status(200).json({ message: "Logged out successfully." });
});

module.exports = router;
