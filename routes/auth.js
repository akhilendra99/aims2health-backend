const express = require("express");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const authenticate = require("../middleware/authenticate");
const createAuthorization = require("../utils/authorization");
require("dotenv").config();

const router = express.Router();
const db = mysql.createPool({
  host: process.env.DBHOST,
  user: process.env.DBUSER,
  password: process.env.DBPWD,
  database: process.env.DBNAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
}).promise();

async function queryRows(sql, values) {
  const [rows] = await db.query(sql, values);
  return rows;
}

const authorization = createAuthorization(queryRows);
const cookieSession = authenticate.cookieOnly(["patient", "doctor", "helper", "admin"]);

const profileQueries = {
  patient: {
    sql: "SELECT patient_id, email_id, fname, lname FROM patient_details WHERE patient_id = ? AND email_id <=> ? LIMIT 1",
    userId: "patient_id",
  },
  doctor: {
    sql: "SELECT doctor_id, email_id, fname, lname FROM doctor_details WHERE doctor_id = ? AND email_id <=> ? AND validated = 1 LIMIT 1",
    userId: "doctor_id",
  },
  helper: {
    sql: "SELECT helper_id, email_id, mobile FROM helper_details WHERE helper_id = ? AND email_id <=> ? LIMIT 1",
    userId: "helper_id",
  },
  admin: {
    sql: "SELECT admin_id, email_id FROM admin_details WHERE admin_id = ? AND email_id <=> ? LIMIT 1",
    userId: "admin_id",
  },
};

function fullName(first, last) {
  return [first, last]
    .filter(value => typeof value === "string" && value.trim())
    .map(value => value.trim())
    .join(" ");
}

function noStore(req, res, next) {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate");
  next();
}

function requireExpiringSession(req, res, next) {
  const claims = jwt.decode(req.userData.token);
  if (!Number.isSafeInteger(claims?.exp)) {
    return res.status(401).json({ message: "You are not authenticated!" });
  }
  next();
}

router.get("/session", noStore, cookieSession, requireExpiringSession, async (req, res) => {
  try {
    const identity = req.userData;
    if (!await authorization.identity(identity)) {
      return res.status(401).json({ message: "You are not authenticated!" });
    }

    const profileQuery = profileQueries[identity.role];
    if (!profileQuery) {
      return res.status(401).json({ message: "You are not authenticated!" });
    }

    const rows = await queryRows(profileQuery.sql, [identity.userId, identity.email ?? null]);
    const account = rows[0];
    if (!account) {
      return res.status(401).json({ message: "You are not authenticated!" });
    }

    const decoded = jwt.decode(identity.token);
    const expiresIn = Number.isSafeInteger(decoded?.exp)
      ? Math.max(0, decoded.exp - Math.floor(Date.now() / 1000))
      : null;
    const email = account.email_id || "";
    const result = {
      role: identity.role,
      expiresIn,
      userId: Number(account[profileQuery.userId]),
      userEmail: identity.role === "helper" && !email ? (account.mobile || "") : email,
      userName: identity.role === "admin"
        ? email
        : identity.role === "helper"
          ? ""
          : fullName(account.fname, account.lname),
    };

    if (identity.role === "helper") {
      result.user = {
        helper_id: Number(account.helper_id),
        email_id: account.email_id || null,
        mobile: account.mobile || null,
      };
    }

    return res.status(200).json(result);
  } catch (error) {
    console.error("Session bootstrap lookup failed:", error.code || "DATABASE_ERROR");
    return res.status(503).json({ message: "Unable to validate session right now." });
  }
});

module.exports = router;
