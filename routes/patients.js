const express = require("express");
const router = express.Router();
const publicRecord = require("../utils/public-record");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const { comparePasswordOrDummy } = require("../utils/password-auth");
const {
  createLoginLockKeys,
  isLoginLocked,
  recordLoginFailure,
  clearLoginFailures,
} = require("../utils/login-lockout");
const { isPasswordValid, INVALID_PASSWORD_MESSAGE } = require("../utils/password-policy");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const needle = require("needle");
const crypto = require("crypto");
const axios = require("axios");
const Razorpay = require("razorpay");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");
dotenv.config();
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// sendgrid testing
// const msgSG = {
//     to: 'aritrachakraborty101@gmail.com', // Change to your recipient
//     from: 'wizztechweb2@gmail.com', // Change to your verified sender
//     subject: 'Sending with SendGrid is Fun',
//     text: 'and easy to do anywhere, even with Node.js',
//     html: '<strong>and easy to do anywhere, even with Node.js</strong>',
//   }
//   sgMail
//     .send(msgSG)
//     .then(() => {
//       console.log('Email sent')
//     })
//     .catch((error) => {
//       console.error(error)
// })
//sendgrd testing ends

const { buildLimit } = require("../utils/pagination");
const zeptomail = require("../utils/zeptomail");
const { generateCsrfToken, CSRF_COOKIE } = require("../middleware/csrf-protection");
const { authCookieOptions, csrfCookieOptions, clearCookieOptions, csrfClearCookieOptions } = require("../utils/auth-cookies");
const { log } = require("util");

const twilio_accountSid = process.env.TWILIO_AC_SID;
const twilio_authToken = process.env.TWILIO_AUTHTOKEN;
const twilio_client = require("twilio")(twilio_accountSid, twilio_authToken);

const razorpay_instance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// regular expressions for input validation

const emailExpression = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
const phoneExpression = /^\d{10}$/;
const pinExpression = /^\d{6}$/;

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
    // Absolute path (not cwd-dependent) with a self-healing mkdir â€” a
    // bare relative "images" string broke when the process's cwd wasn't
    // the backend root, producing ENOENT on every upload.
    const uploadDir = path.join(__dirname, "..", "images");
    fs.mkdirSync(uploadDir, { recursive: true });
    call_back(error, uploadDir);
  },
  filename: (req, file, call_back) => {
    const ext = MIME_TYPE_MAP[file.mimetype];
    // Strip anything but [a-z0-9] from the original filename â€” closes both
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

/////// end setting up multer

// var con = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "root",
//   database: "aims2health_main",
// });

var con = mysql.createConnection({
  host: process.env.DBHOST,
  user: process.env.DBUSER,
  password: process.env.DBPWD,
  database: process.env.DBNAME,
});

con.connect(function (err) {
  if (err) {
    throw err;
  }
  console.log("Connected to MySQL Database!");
});

var con_ehr = mysql.createConnection({
  host: process.env.DBHOST,
  user: process.env.DBUSER,
  password: process.env.DBPWD,
  database: process.env.EHR_DBNAME || "medicdb",
});
// var con_ehr = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "root",
//   database: "medicdb",
// });
if (process.env.EHR_CONNECT == "true") {
  try {
    con_ehr.connect(function (err) {
      if (err) throw err;
      console.log("Connected to remote EHR Database!");
    });
  } catch (err) {
    console.log(err);
  }
}

// router.get('', patientSession, (req, res, next) => {

//     const pageSize = +req.query.pagesize; //converting query param from string to number using +
//     const currentPage = +req.query.page;

//     var numPerPage = 20;
//     numPerPage = pageSize;
//     page = currentPage;
//     var skip = (page-1) * numPerPage;
//     var limit = skip + ',' + numPerPage; // Here we compute the LIMIT parameter for MySQL query
//     con.query('SELECT count(*) as numRows FROM patient_details',function (err, rows, fields) {
//         if(err) {
//             console.log("error: ", err);
//             res.status(500).json({
//                 message: 'Fetching Posts Failed!'
//             });
//             //result(err, null);
//         }else{
//             var numRows = rows[0].numRows;
//             var numPages = Math.ceil(numRows / numPerPage);
//             con.query('SELECT * FROM patient_details LIMIT '+limit, function (err, rows, fields) {
//                 if(err) {
//                     console.log("error: ", err);
//                     //result(err, null);
//                 }else{
//                     console.log(rows)
//                     //result(null, rows,numPages);

//                     console.log(rows);

//                     res.status(200).json({
//                         message: 'Posts fetched successfully!',
//                         posts: rows,
//                         maxPosts: +numRows
//                     });

//                 }
//             });
//         }
//     });

// });
// Explicit shared policies preserve the admin and assigned-helper callers.
const authorization = require('../utils/authorization')((sql, values) => new Promise((resolve, reject) => con.query(sql, values, (err, rows) => err ? reject(err) : resolve(rows))));
const patientSession = authorization.guard(['patient']);
const patientAccess = id => authorization.guard(['patient', 'helper', 'admin'], async (req, access) => Boolean(req.authorizedPatient = await access.patient(req.userData, id(req))));
const ownReport = authorization.guard(['patient'], async (req, access) => {
  const record = await access.report(req.userData, req.params.id);
  return record && String(record.patient_id) === String(req.userData.userId) && (!req.body?.id || String(req.body.id) === String(req.params.id));
});
const reportAttachment = authorization.guard(['patient'], async (req, access) => {
  if (req.body.id && req.params.id && String(req.body.id) !== String(req.params.id)) return false;
  if (req.file || !req.body.image || req.body.image === 'na') return true;
  if (typeof req.body.image !== 'string') return false;
  return access.file(req.userData, req.body.image.split('/').pop());
});

router.post("/contact", (req, res) => {
  const { first_name, last_name, email, concern } = req.body;

  // Input validation
  if (!first_name || !last_name) {
    return res
      .status(400)
      .json({ message: "First and Last Name are required." });
  }
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ message: "Valid email is required." });
  }
  if (!concern || concern.trim() === "") {
    return res.status(400).json({ message: "Please enter your concern." });
  }

  const sql = `INSERT INTO contact_queries (first_name, last_name, email, concern) VALUES (?, ?, ?, ?)`;

  con.query(sql, [first_name, last_name, email, concern], (err, result) => {
    if (err) {
      console.error("Contact submission failed:", err);
      return res
        .status(500)
        .json({ message: "Failed to submit contact request." });
    }

    return res.status(201).json({
      message: "Thank you for contacting us. We'll get back to you soon!",
    });
  });
});

router.get("/currentMedReportTotal", patientSession, (req, res, next) => {
  console.log("get size api was hit");
  let uploadLimit = process.env.UPLOAD_LIMIT_WITHOUT_BOOKING;
  var sql = `SELECT count(*) as p_count FROM appointments WHERE patient_id= ?`;
  con.query(sql, [req.userData.userId], function (err, result) {
    if (err) {
      console.log(err);
      res.status(401).json({
        message: "Getting Current total uploaded size failed!",
      });
    } else {
      if (result[0].p_count > 0) {
        uploadLimit = process.env.UPLOAD_LIMIT_WITH_BOOKING;
      }
      var sql = `SELECT SUM(mediaSize) as currentSize FROM patient_med_reports WHERE patient_id= ?`;
      con.query(sql, [req.userData.userId], function (err, result) {
        if (err) {
          console.log(err);
          res.status(401).json({
            message: "Getting Current total uploaded size failed!",
          });
        } else {
          console.log("currentSize:", result[0].currentSize);
          console.log("uploadLimit:", uploadLimit);
          // res= {
          //     calendar_id: result.calendar_id,
          //     doctor_id: result.doctor_id,
          //     date:
          // }

          res.status(201).json({
            message: "Total uploaded size fetched successfully",
            currentSize: result[0].currentSize,
            uploadLimit: uploadLimit,
          });
        }
      });
    }
  });
});

router.get("/medreports", patientSession, (req, res, next) => {
  const { limit, numPerPage } = buildLimit(req.query.pagesize, req.query.page);
  con.query(
    `SELECT count(*) as numRows FROM patient_med_reports WHERE patient_id= ?`,
    [req.userData.userId],
    function (err, rows, fields) {
      if (err) {
        console.log("error: ", err);
        res.status(500).json({
          message: "Fetching Posts Failed!",
        });
        //result(err, null);
      } else {
        var numRows = rows[0].numRows;
        var numPages = Math.ceil(numRows / numPerPage);
        con.query(
          `SELECT * FROM patient_med_reports WHERE patient_id=? ORDER BY report_id DESC LIMIT ` +
            limit,
          [req.userData.userId],
          function (err, rows, fields) {
            if (err) {
              console.log("error: ", err);
              //result(err, null);
            } else {
              console.log(rows);
              //result(null, rows,numPages);

              console.log(rows);

              res.status(200).json({
                message: "Posts fetched successfully!",
                posts: rows,
                maxPosts: +numRows,
              });
            }
          },
        );
      }
    },
  );
});

router.post("/search", patientSession, (req, res, next) => {
  console.log(req.body);

  //var sql = `SELECT * FROM doctor_calendar INNER JOIN doctor_details ON doctor_calendar.doctor_id = doctor_details.doctor_id  WHERE doctor_calendar.date= ? AND doctor_calendar.doc_type= ?`;
  var sql = `SELECT * FROM ((doctor_calendar INNER JOIN doctor_details ON doctor_calendar.doctor_id = doctor_details.doctor_id) INNER JOIN doctor_additional ON doctor_calendar.doctor_id = doctor_additional.doctor_id)  WHERE doctor_calendar.date= ? AND doctor_calendar.doc_type= ?`;

  console.log(sql);
  con.query(
    sql,
    [req.body.appmntDate, req.body.docType],
    function (err, result) {
      if (err) {
        console.log(err);
        res.status(401).json({
          message: "Searching Appointment failed!",
        });
      } else {
        console.log(result);
        // res= {
        //     calendar_id: result.calendar_id,
        //     doctor_id: result.doctor_id,
        //     date:
        // }
        if (result.length > 0) {
          res.status(201).json({
            message: "Search results fetched successfully",
            searchedResults: result.map(publicRecord),
          });
        } else {
          res.status(401).json({
            message: "No specified dcotor is available on the given date!",
          });
        }
      }
    },
  );
});

router.post("/requestEmergency", patientSession, async (req, res, next) => {
  console.log(req.body);

  // Send SMS to admin via Twilio
  try {
    const twilioResponse = await twilio_client.messages.create({
      body: `Dear Admin! A Patient (Patient Id: ${req.userData.userId}) has requested for an emergency appointment. The requested date is : ${req.body.appmntDate} and the Problem he is facing is : ${req.body.probDetails}.`,
      to: `+91${process.env.ADMIN_PHONE}`, // Text this number
      from: `${process.env.TWILIO_PHONE_NUMBER}`, // From a valid Twilio number
    });

    console.log(twilioResponse.sid);

    // Send via ZeptoMail â€” services.netxcell.com:8081 (the previous
    // provider) is unreachable. VAPT L1 Finding 15 / L2 Finding 18,
    // "Broken Functionality".
    try {
      await zeptomail.sendMail({
        to: process.env.ADMIN_EMAIL,
        toName: "Admin",
        subject: "AIMS2Health - Emergency Appointment Requested",
        text: `Dear Admin! A Patient (Patient Id: ${req.userData.userId}) has requested for an emergency appointment. The requested date is : ${req.body.appmntDate} and the Problem he is facing is : ${req.body.probDetails}.`,
      });
      console.log("Emergency appointment email sent to admin");

      res.status(200).json({
        message: "Appointment booked Successfully",
      });
    } catch (emailError) {
      console.error("Email API error:", emailError);
      res.status(401).json({
        message: "Cannot send booking email to admin",
      });
    }
  } catch (twilioError) {
    console.error("Twilio error:", twilioError);
    res.status(401).json({
      message: "Cannot send booking SMS to admin",
    });
  }
});

router.get("/medreportlist/:id", patientAccess(req => req.params.id), (req, res, next) => {
  const { limit, numPerPage } = buildLimit(req.query.pagesize, req.query.page);
  con.query(
    `SELECT count(*) as numRows FROM patient_med_reports WHERE patient_id= ?`,
    [req.params.id],
    function (err, rows, fields) {
      if (err) {
        console.log("error: ", err);
        res.status(500).json({
          message: "Fetching Posts Failed!",
        });
        //result(err, null);
      } else {
        var numRows = rows[0].numRows;
        var numPages = Math.ceil(numRows / numPerPage);
        con.query(
          `SELECT * FROM patient_med_reports WHERE patient_id=? LIMIT ` + limit,
          [req.params.id],
          function (err, rows, fields) {
            if (err) {
              console.log("error: ", err);
              //result(err, null);
            } else {
              console.log(rows);
              //result(null, rows,numPages);

              console.log(rows);

              res.status(200).json({
                message: "Posts fetched successfully!",
                posts: rows,
                maxPosts: +numRows,
              });
            }
          },
        );
      }
    },
  );
});

router.get("/appointment/:id", patientAccess(req => req.params.id), (req, res, next) => {
  const { limit, numPerPage } = buildLimit(req.query.pagesize, req.query.page);
  con.query(
    `SELECT count(*) as numRows FROM appointments WHERE patient_id=?`,
    [req.params.id],
    function (err, rows, fields) {
      if (err) {
        console.log("error: ", err);
        res.status(500).json({
          message: "Fetching Posts Failed!",
        });
        //result(err, null);
      } else {
        var numRows = rows[0].numRows;
        var numPages = Math.ceil(numRows / numPerPage);
        con.query(
          `SELECT * FROM appointments WHERE patient_id=? ORDER BY date DESC LIMIT ` +
            limit,
          [req.params.id],
          function (err, rows, fields) {
            if (err) {
              console.log("error: ", err);
              //result(err, null);
            } else {
              console.log(rows);
              //result(null, rows,numPages);

              console.log(rows);

              res.status(200).json({
                message: "Posts fetched successfully!",
                posts: rows,
                maxPosts: +numRows,
              });
            }
          },
        );
      }
    },
  );
});
router.get("/medreports/:id", patientSession, (req, res, next) => {
  con.query(
    `SELECT * FROM patient_med_reports WHERE report_id = ? AND patient_id = ?`,
    [req.params.id, req.userData.userId],
    function (err, result, fields) {
      if (err) {
        console.log(err);

        res.status(404).json({
          message: "Patient not found!",
          post: result,
        });
      }
      console.log("A single med report", result);
      if (result.length <= 0) {
        res.status(404).json({
          message: "Patient not found!",
        });
      } else {
        res.status(200).json(result);
      }
    },
  );
});

router.put(
  "/medreport/:id",
  ownReport,
  multer({ storage: storage }).single("image"),
  reportAttachment,
  (req, res, next) => {
    let imagePath = req.body.image;
    if (req.file) {
      //const url = req.protocol + '://'+ req.get('host');
      const urlLive = process.env.BACKEND_PROTOCOL_PROD;
      imagePath = urlLive + "/images/" + req.file.filename;
    }
    var sql = `UPDATE patient_med_reports SET report_title = ?, content = ?, imagePath = ?, mediaType = ?, recordDate = ? WHERE report_id = ? AND patient_id =?`;
    con.query(
      sql,
      [
        req.body.title,
        req.body.content,
        imagePath,
        req.body.mediaType,
        req.body.recordDate,
        req.params.id,
        req.userData.userId,
      ],
      function (err, result) {
        if (err) {
          console.log(err);
          return res.status(500).json({
            message: "Couldn't Update Post!",
          });
        }
        //console.log("result: ", result);
        console.log(result.affectedRows + " record(s) updated");
        if (result.affectedRows == 0 || result.affectedRows == "0") {
          res.status(404).json({
            message: "Not Authorized!",
          });
        } else {
          res.status(201).json({
            message: "Post updated successfully",
          });
        }
      },
    );
  },
);

router.put("/medreportwoimage/:id", ownReport, reportAttachment, (req, res, next) => {
  // let imagePath = req.body.image;
  // if(req.file){
  //     const url = req.protocol + '://'+ req.get('host');
  //     imagePath = url + '/images/' + req.file.filename;
  // }
  var sql = `UPDATE patient_med_reports SET report_title = ?, content = ?, imagePath = ?, mediaType = ?, recordDate = ? WHERE report_id = ? AND patient_id =?`;
  con.query(
    sql,
    [
      req.body.title,
      req.body.content,
      req.body.image,
      req.body.mediaType,
      req.body.recordDate,
      req.params.id,
      req.userData.userId,
    ],
    function (err, result) {
      if (err) {
        console.log(err);
        return res.status(500).json({
          message: "Couldn't Update Post!",
        });
      }
      //console.log("result: ", result);
      console.log(result.affectedRows + " record(s) updated");
      if (result.affectedRows == 0 || result.affectedRows == "0") {
        res.status(404).json({
          message: "Not Authorized!",
        });
      } else {
        res.status(201).json({
          message: "Post updated successfully",
        });
      }
    },
  );
});

// router.get('/:id', patientSession, (req, res, next) => {

//     con.query(`SELECT * FROM patient_details WHERE patient_id = ?`, [req.params.id], function (err, result, fields) {
//         if (err){
//             console.log(err)

//             res.status(404).json({
//                 message: 'Patient not found!',
//                 post: result
//             });
//         }
//         console.log(result);
//         if( result.length <= 0){
//             res.status(404).json({
//                 message: 'Patient not found!'

//             });
//         }else{
//             res.status(200).json(result);
//         }

//     });
// })

router.post("/patientExists", (req, res) => {
  // Availability is decided by the transactional signup handler. Returning
  // an account-specific boolean here would expose patient registration state.
  return res.status(200).json({ message: "Continue registration if eligible." });
});

router.post("/getvdetails", patientSession, (req, res, next) => {
  console.log("User id", req.userData.userId);
  con.query(
    `SELECT mobile_no, countryCode, email_id FROM patient_details WHERE patient_id = ?`,
    [req.userData.userId],
    function (err, result, fields) {
      if (err) {
        console.log(err);

        res.status(404).json({
          message: "Patient not found!",
          post: result,
        });
      }
      console.log(result);
      if (result.length <= 0) {
        res.status(404).json({
          message: "Patient not found!",
        });
      } else {
        let mobile = result[0].mobile_no;
        let countryCode = result[0].countryCode;
        let email = result[0].email_id;
        con.query(
          `SELECT * FROM patient_additional WHERE patient_id = ?`,
          [req.userData.userId],
          function (err, result) {
            if (err) {
              console.log(err);

              res.status(404).json({
                message: "Patient not found!",
                post: result,
              });
            } else {
              let verify_mob = result[0]?.phone_verification;
              let verify_email = result[0]?.email_verification;
              let p_consent = result[0]?.patient_consent;
              let p_consent_date = result[0]?.patient_consent_date_time;
              let p_consent_ipaddr = result[0]?.patient_consend_ip_addr;

              let res_obj = {
                mobile: mobile,
                countryCode: countryCode,
                email: email,
                verify_mob: verify_mob,
                verify_email: verify_email,
                p_consent: p_consent,
                p_consent_date: p_consent_date,
                p_consent_ipaddr: p_consent_ipaddr,
              };
              console.log("P Verification details:", res_obj);

              res.status(200).json({ data: res_obj });
            }
          },
        );
      }
    },
  );
});

router.get("/getappointmentreceipt/:patientId", patientAccess(req => req.params.patientId), (req, res, next) => {
  console.log("Patient id", req.params.patientId);
  con.query(
    `SELECT mobile_no, email_id FROM patient_details WHERE patient_id = ?`,
    [req.params.patientId],
    function (err, result, fields) {
      if (err) {
        console.log(err);

        res.status(404).json({
          message: "Patient Appointments not found!",
          post: result,
        });
      }
      console.log(result);
      if (result.length <= 0) {
        res.status(404).json({
          message: "Appointments not found!",
        });
      } else {
        let mobile = result[0].mobile_no;
        let email = result[0].email_id;
        con.query(
          `SELECT * FROM appointments WHERE patient_id = ?`,
          [req.params.patientId],
          function (err, result) {
            if (err) {
              console.log(err);

              res.status(404).json({
                message: "Patient not found!",
                post: result,
              });
            } else {
              res.status(200).json({ data: result });
            }
          },
        );
      }
    },
  );
});

const otpStorePhone = new Map(); // Per-patient phone OTP challenges

function patientOtpKey(userId, contact) {
  return `${userId}:${contact}`;
}

router.post("/sendPhoneVerifyOTP", patientSession, async (req, res, next) => {
  // Use only the phone number without country code
  const phone_no = typeof req.body.phone === "string" ? req.body.phone.trim() : "";

  // Validate phone number format (basic check for digits only)
  if (!/^\d+$/.test(phone_no)) {
    return res.status(400).json({
      vstatus: "Invalid phone number",
      message: "Phone number must contain only digits",
    });
  }

  try {
    const [rows] = await con.promise().query(
      "SELECT mobile_no FROM patient_details WHERE patient_id = ? LIMIT 1",
      [req.userData.userId],
    );
    if (!rows.length || String(rows[0].mobile_no || "").replace(/\D/g, "").slice(-10) !== phone_no.slice(-10)) {
      return res.status(400).json({ message: "Phone number does not match the authenticated account." });
    }
  } catch {
    return res.status(500).json({ message: "Unable to start phone verification." });
  }

  const otp = crypto.randomInt(1000, 10000); // Generate a cryptographically random 4-digit OTP

  // Store the OTP in otpStorePhone with an 8-minute expiry time
  const challengeKey = patientOtpKey(req.userData.userId, phone_no);
  otpStorePhone.set(challengeKey, { otp, expiresAt: Date.now() + 8 * 60 * 1000 });

  // Prepare the data object for the message
  const smsPayload = {
    user: "LH_Aims",
    password: "Aims@789",
    peid: "1201159203611670874",
    templateid: "1207167403938428753",
    sender: "AIMSDD",
    dest: phone_no,
    messagetype: "T",
    message: `AIMS2Health appointment request No: ${otp} received at 22:48 Mar 30 2022. Please check appointment status in www.aims2.health`,
    deliveryreport: "yes",
  };

  // Send OTP via the Converge SMS API
  try {
    const response = await axios.post(
      "https://convergenow.ai/sms-api/sms/",
      smsPayload,
      {
        headers: {
          "Content-Type": "application/json",
          "accept": "application/json",
        },
        timeout: 10000,
      },
    );
    // Check if the API response indicates success
    if (response.data.status === "Accepted") {
      res.status(200).json({
        vstatus: "OTP sent successfully",
      });
    } else {
      otpStorePhone.delete(challengeKey);
      res.status(500).json({
        vstatus: "OTP sending failed",
        message: "SMS not accepted by API",
      });
    }
  } catch (error) {
    otpStorePhone.delete(challengeKey);
    res.status(500).json({
      vstatus: "OTP generation failed",
      message: "Unable to send OTP. Please try again.",
    });
  }
});

router.post("/verifyPhone", patientSession, (req, res, next) => {
  const { phone, otp } = req.body;

  // Use the raw phone number without country code for lookup
  const phone_no = typeof phone === "string" ? phone.trim() : "";

  // Check if the OTP exists and is not expired
  const challengeKey = patientOtpKey(req.userData.userId, phone_no);
  const storedOTP = otpStorePhone.get(challengeKey);

  if (!storedOTP || storedOTP.expiresAt <= Date.now()) {
    otpStorePhone.delete(challengeKey);
    return res.status(400).json({
      vstatus: "error",
      message: "OTP not found or expired. Please request a new OTP.",
    });
  }

  // Check if the provided OTP matches the stored OTP
  if (!/^\d{4}$/.test(String(otp)) || storedOTP.otp !== Number(otp)) {
    return res.status(400).json({
      vstatus: "error",
      message: "Invalid OTP. Please try again.",
    });
  }

  // Consume before asynchronous database work so concurrent replays cannot
  // both pass validation. A database error leaves verification unmarked.
  otpStorePhone.delete(challengeKey);

  // OTP is valid, proceed to update the database
  const updated_sql = `UPDATE patient_additional SET phone_verification = '1' WHERE patient_id = ?`;

  con.query(updated_sql, [req.userData.userId], function (err, result) {
    if (err) {
      console.error("Error updating database:", err);
      return res.status(500).json({
        vstatus: "error",
        message: "Error updating database",
      });
    }

    // OTP verified and phone number marked as verified
    res.status(201).json({
      vstatus: "approved",
      message: "Phone number successfully verified.",
    });
  });
});

// Simplified /sendEmailVerifyOTP route
const otpStore = new Map(); // Per-patient email OTP challenges
// Function to validate email format
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

router.post("/sendEmailVerifyOTP", patientSession, async (req, res, next) => {
  const emailToSend = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";

  // Validate email format
  if (!isValidEmail(emailToSend)) {
    return res.status(400).json({
      vstatus: "Invalid email",
      message: "Email address is not valid",
    });
  }

  try {
    const [rows] = await con.promise().query(
      "SELECT email_id FROM patient_details WHERE patient_id = ? LIMIT 1",
      [req.userData.userId],
    );
    if (!rows.length || String(rows[0].email_id || "").trim().toLowerCase() !== emailToSend) {
      return res.status(400).json({ message: "Email address does not match the authenticated account." });
    }
  } catch {
    return res.status(500).json({ message: "Unable to start email verification." });
  }

  // Function to generate a random 4-digit OTP
  function generateOTP() {
    return crypto.randomInt(1000, 10000); // 4-digit OTP
  }

  const otp = generateOTP();
  // Store the OTP with the email as the key (with an 8-minute expiry time)
  const challengeKey = patientOtpKey(req.userData.userId, emailToSend);
  otpStore.set(challengeKey, { otp, expiresAt: Date.now() + 8 * 60 * 1000 });

  // Send OTP email via ZeptoMail â€” services.netxcell.com:8081 (the previous
  // provider) is unreachable (confirmed independently from multiple
  // networks, not an EC2-specific firewall issue). VAPT L1 Finding 15 / L2
  // Finding 18, "Broken Functionality".
  try {
    await zeptomail.sendMail({
      to: emailToSend,
      subject: "Your OTP for Email Verification",
      text: `Dear User,\n\nYour OTP for secure login is ${otp}.\nThis OTP is valid for 8 minutes.`,
    });
    res.status(201).json({
      vstatus: "OTP sent successfully",
      message: "Check your email for the OTP.",
    });
  } catch (error) {
    otpStore.delete(challengeKey);
    res.status(500).json({
      vstatus: "OTP sending failed",
      message: "Error sending OTP email",
    });
  }
});
router.post("/verifyEmail", patientSession, (req, res, next) => {
  const { email, otp } = req.body;

  const cleanEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
  const challengeKey = patientOtpKey(req.userData.userId, cleanEmail);
  const storedOTP = otpStore.get(challengeKey);

  if (!storedOTP || storedOTP.expiresAt <= Date.now()) {
    otpStore.delete(challengeKey);
    return res.status(400).json({
      message: "OTP not found or expired. Please request a new OTP.",
    });
  }

  // Convert the received OTP to a number before comparing
  if (!/^\d{4}$/.test(String(otp)) || storedOTP.otp !== Number(otp)) {
    return res.status(400).json({
      message: "Invalid OTP. Please try again.",
    });
  }

  // Consume before asynchronous database work to enforce single use under
  // concurrent requests. Database errors do not mark the account verified.
  otpStore.delete(challengeKey);

  // OTP is valid, proceed with verification
  var updated_sql = `UPDATE patient_additional SET email_verification = '1' WHERE patient_id = ?`;

  con.query(updated_sql, [req.userData.userId], function (err, result) {
    if (err) {
      console.log(err);
      return res.status(500).json({
        vstatus: "Error updating database",
      });
    }

    // OTP verified and email marked as verified
    res.status(201).json({
      vstatus: "approved",
      message: "Email successfully verified.",
    });
  });
});

router.post("/sendConsent", patientSession, (req, res) => {
  const userId = req.userData.userId;

  console.log("User ID:", userId);

  const updated_sql = `
    UPDATE patient_additional 
    SET patient_consent = '1', 
        patient_consent_date_time = NOW() 
    WHERE patient_id = ?
  `;

  con.query(updated_sql, [userId], (err, result) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ vstatus: "error updating db" });
    }

    const getEmailSQL = `SELECT email_id, fname FROM patient_details WHERE patient_id = ?`;
    con.query(getEmailSQL, [userId], (err2, result2) => {
      if (err2 || result2.length === 0) {
        console.error("Error fetching email:", err2);
        return res.status(200).json({
          cstatus: result,
          emailStatus: "Consent saved, but email not sent",
        });
      }

      const userEmail = result2[0].email_id;
      const firstName = result2[0].fname || "User";

      sgMail
        .send({
          to: userEmail,
          from: process.env.SENDGRID_FROM_ADDRESS,
          subject: "Consent Confirmation",
          text: `Hi ${firstName},\n\nYour consent has been successfully recorded.\n\nThank you!`,
        })
        .then(() => {
          console.log("Email sent successfully to", userEmail);
          res.status(201).json({
            cstatus: result,
            emailStatus: "Consent email sent",
          });
        })
        .catch((emailErr) => {
          console.error(
            "SendGrid Error:",
            emailErr?.response?.body || emailErr,
          );
          res.status(201).json({
            cstatus: result,
            emailStatus: "Consent saved, but email failed",
          });
        });
    });
  });
});

const otpStoreLogin = new Map();

// OTP Generator for login
function generateOTPLogin() {
  return crypto.randomInt(100000, 1000000).toString();
}
router.post("/send-otp-login", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

  const sql = `SELECT * FROM patient_details WHERE email_id = ?`;
  con.query(sql, [email], (err, result) => {
    const response = { message: "If the account is eligible, an OTP has been sent." };
    if (err || result.length === 0) {
      if (err) console.error("Patient OTP login lookup failed.");
      return res.status(200).json(response);
    }

    const otp = generateOTPLogin();
    otpStoreLogin.set(email, { otp, expiresAt: Date.now() + 5 * 60 * 1000 });

    sgMail
      .send({
        to: email,
        from: process.env.SENDGRID_FROM_ADDRESS,
        subject: "Your OTP Code",
        text: `Your OTP is ${otp}, valid for 5 minutes.`,
      })
      .then(() => {
        res.status(200).json(response);
      })
      .catch((err) => {
        otpStoreLogin.delete(email);
        console.error("Patient OTP login delivery failed.");
        res.status(200).json(response);
      });
  });
});

// Route: POST /login/verify-otp
router.post("/verify-otp-login", (req, res) => {
  const { email, otp } = req.body;
  const record = otpStoreLogin.get(email);

  if (!record || record.otp !== otp || Date.now() >= record.expiresAt) {
    if (record && Date.now() >= record.expiresAt) otpStoreLogin.delete(email);
    return res.status(401).json({ message: "Invalid or expired OTP" });
  }

  otpStoreLogin.delete(email);

  const sql = `SELECT * FROM patient_details WHERE email_id = ?`;
  con.query(sql, [email], (err, result) => {
    if (err || result.length === 0) {
      return res.status(401).json({ message: "Invalid or expired OTP" });
    }

    const token = jwt.sign(
      {
        email: result[0].email_id,
        userId: result[0].patient_id,
        role: "patient",
      },
      process.env.JWT_SECRET_PATIENT,
      { expiresIn: "1h" },
    );

    const csrfToken = generateCsrfToken();
    res.cookie("auth_token", token, authCookieOptions());
    res.cookie(CSRF_COOKIE, csrfToken, csrfCookieOptions());
    res.status(200).json({
      expiresIn: 3600,
      userId: result[0].patient_id,

      userEmail: result[0].email_id,
      userName: result[0].fname + " " + result[0].lname,
    });
  });
});

router.put("/chpwd", patientSession, (req, res, next) => {
  if (typeof req.body?.oldpwd !== "string" || !req.body.oldpwd || Buffer.byteLength(req.body.oldpwd, "utf8") > 72 || !isPasswordValid(req.body.newpwd)) {
    return res.status(400).json({ message: INVALID_PASSWORD_MESSAGE });
  }

  var sql = `SELECT * FROM patient_details WHERE patient_id= ?`;
  //console.log(req.body)
  con.query(sql, [req.userData.userId], function (err, result, fields) {
    if (err) {
      res.status(401).json({
        message: "Invalid Authentication Credentials!",
      });
    } else {
      if (result.length <= 0) {
        res.status(401).json({
          message: "Invalid Authentication Credentials!",
        });
      } else {
        bcrypt
          .compare(req.body.oldpwd, result[0].hashed_pwd)
          .then((auth_result) => {
            if (!auth_result) {
              res.status(401).json({
                message: "Incorrect Old Password!",
              });
            } else {
              bcrypt
                .hash(req.body.newpwd, 11)
                .then((hash) => {
                  var sql = `UPDATE patient_details SET hashed_pwd = ? WHERE patient_id = ?`;
                  con.query(
                    sql,
                    [hash, req.userData.userId],
                    function (err, result) {
                      if (err) {
                        console.log(err);
                        res.status(401).json({
                          message: "Updating Patient Password failed!",
                        });
                      } else {
                        console.log(result);

                        res.status(201).json({
                          message: "Patient password updated successfully",
                        });
                      }
                    },
                  );
                })
                .catch((err) => {
                  console.log("This error: ", err);
                  res.status(401).json({
                    message: "Incorrect pwd",
                  });
                });
            }
          })
          .catch((err) => {
            console.log("This error: ", err);
            res.status(401).json({
              message: "Incorrect old pwd",
            });
          });
        //res.status(200).json(result[0].email);
      }
    }
  });
});

router.post("/signup", (req, res, next) => {
  if (!isPasswordValid(req.body?.password)) {
    return res.status(400).json({ message: INVALID_PASSWORD_MESSAGE });
  }
  if (req.body.medical_history == "") {
    medical_history = "Default from Virtual Sathi";
  }
  let dob = req.body.dob; // Assuming 'dob' can be either a date or age (e.g., "1995-04-12" or "29")
  console.log(dob, "from frontend");

  // Check if dob is a number (representing age), and calculate the birth year
  if (!isNaN(dob)) {
    const currentYear = new Date().getFullYear();
    const age = parseInt(dob, 10); // Convert the dob (age) to an integer
    const birthYear = currentYear - age;

    // Set dob to the calculated birth year with default day and month (e.g., "1995-01-01")
    dob = `${birthYear}-01-01`;
  } else {
    // If dob is not a number, check if it's a valid date format
    const parsedDate = Date.parse(dob);
    if (isNaN(parsedDate)) {
      res.status(400).json({
        message: "Invalid date of birth format!",
      });
      return;
    }
  }

  console.log(dob, "calculated or valid dob");

  // Input validation server side - starts here
  if (req.body.fname == "" || req.body.lname == "") {
    //alert("Please enter your first name and last name correctly!");
    //this.toastr.error('Please enter your first name and last name correctly!', 'Error!');
    this.dialog.open(AuthDialogBoxComponent, {
      data: {
        message: `The First name and the Last name cannot be empty.`,
      },
    });

    return;
  } else if (
    String(req.body.fname).length > 20 ||
    String(req.body.lname).length > 30
  ) {
    //alert("Please enter your first name and last name correctly!");
    //this.toastr.error('Please enter your first name and last name correctly!', 'Error!');
    res.status(401).json({
      message: "Adding Patient failed! Very long first name and last name.",
    });
  } else if (!emailExpression.test(req.body.email)) {
    res.status(401).json({
      message: "Adding Patient failed! Invalid email.",
    });
  } else if (req.body.dob == "") {
    //this.toastr.error('Please enter your first name and last name correctly!');
    //alert("Please enter your date of birth!");
    res.status(401).json({
      message: "Adding Patient failed! Date of Birth field cannot be empty.",
    });
  } else if (req.body.mobile_no == "") {
    //alert("Please enter your phone number!");
    //this.toastr.error('Please enter your first name and last name correctly!');

    res.status(401).json({
      message: "Adding Patient failed! Phone field cannot be blank.",
    });
  } else if (req.body.mobile_secondary == "") {
    //alert("Please enter your secondary phone number!");
    //this.toastr.error('Please enter your first name and last name correctly!');
    res.status(401).json({
      message: "Adding Patient failed! Secondary phone field cannot be blank.",
    });
  } else if (
    !phoneExpression.test(req.body.mobile_no) ||
    !phoneExpression.test(req.body.mobile_secondary)
  ) {
    res.status(401).json({
      message: "Adding Patient failed! Invalid phone numbers.",
    });
  } else if (req.body.gender == "") {
    //alert("Please enter your gender!");
    //this.toastr.error('Please enter your first name and last name correctly!');

    res.status(401).json({
      message: "Adding Patient failed! Gender missing.",
    });
  } else if (req.body.address == "") {
    //alert("Please enter your PIN code!");
    //this.toastr.error('Please enter your first name and last name correctly!');
    res.status(401).json({
      message: "Adding Patient failed! PIN missing.",
    });
  } else if (!pinExpression.test(req.body.address.split(" ")[1])) {
    res.status(401).json({
      message: "Adding Patient failed! PIN is invalid.",
    });
  }
  // Input validation server side - ends here
  else {
    con.query(
      `SELECT * FROM patient_details WHERE email_id = ?`,
      [req.body.email],
      function (err, result) {
        if (err) {
          console.log(err);
          res.status(401).json({
            message: "Adding Patient failed!",
          });
        } else {
          if (result.length > 0) {
            res.status(401).json({
              message: "Registration could not be completed with these details.",
            });
          } else {
            bcrypt.hash(req.body.password, 11).then((hash) => {
              var sql = `INSERT INTO patient_details (helper_id, fname, lname, address, dob, countryCode, mobile_no, sec_countryCode, mobile_secondary, medical_history, id_type, adhaar, gender, email_id, hashed_pwd, abhaId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
              con.query(
                sql,
                [
                  -1,
                  req.body.fname,
                  req.body.lname,
                  req.body.address,
                  dob,
                  req.body.countrycode,
                  req.body.mobile_no,
                  req.body.countrycode,
                  req.body.mobile_secondary,
                  req.body.medical_history,
                  req.body.idType,
                  req.body.idNumber,
                  req.body.gender,
                  req.body.email,
                  hash,
                  req.body.abhaId,
                ],
                function (err, result) {
                  if (err) {
                    console.log(err);
                    res.status(401).json({
                      message: "Adding Patient failed!",
                    });
                  } else {
                    var patientId = result.insertId;
                    console.log(patientId, "patientId");
                    var crno = `select crno from pt_key order by rownum asc limit 1; `;
                    con_ehr.query(crno, function (err, result) {
                      if (err) {
                        console.log(err);
                        return res.status(500).json({
                          message: "Inserting Patient failed!",
                        });
                      } else {
                        console.log(result, "res");
                        const crno = result[0].crno + 1;
                        const today = new Date().toISOString().split("T")[0];

                        var sql2 = `INSERT INTO adm_new (ma_name, lname, ma_address, Date_of_birth,
                         Telno, cellno, sex, email,admno,vs_frontend,ma_dated) VALUES (?, ?, ?, ?, ?, ?, ?, ?,?,?,?)`;
                        con_ehr.query(
                          sql2,
                          [
                            req.body.fname,
                            req.body.lname,
                            req.body.address,
                            req.body.dob,
                            req.body.mobile_no,
                            req.body.idNumber,
                            req.body.gender === "male" ? "M" : "F",
                            req.body.email,
                            crno,
                            patientId,
                            today,
                          ],
                          function (err, result) {
                            if (err) {
                              console.log(err);
                              return res.status(500).json({
                                message: "Inserting Patient failed!",
                              });
                            } else {
                              console.log("Success");
                              var sql2 = `update pt_key set crno=crno+1 order by rownum asc limit 1;`;
                              con_ehr.query(sql2, function (err, result) {
                                if (err) {
                                  console.log(err);
                                  return res.status(500).json({
                                    message: "Inserting Patient failed!",
                                  });
                                } else {
                                  return res.status(201).json({
                                    message: "Patient added successfully",
                                  });
                                }
                              });
                            }
                          },
                        );
                      }
                    });
                    var updated_sql = `UPDATE patient_details SET email_id = ?, hashed_pwd = ?, gender = ?, id_type = ? WHERE patient_id = ?`;

                    con.query(
                      updated_sql,
                      [
                        req.body.email,
                        hash,
                        req.body.gender,
                        req.body.idType,
                        patientId,
                      ],
                      function (err, result) {
                        if (err) {
                          res.status(401).json({
                            message: "Adding Patient failed!",
                          });
                        } else {
                          Date_aptToDate = new Date();
                          dateStr = Date_aptToDate.toLocaleDateString("en-GB")
                            .split("/")
                            .reverse()
                            .join("-");
                          console.log("dateStr:", dateStr);
                          var additional_sql = `INSERT INTO patient_additional (patient_id, registrationDate) VALUES (?, ?)`;
                          con.query(
                            additional_sql,
                            [patientId, dateStr],
                            function (err, result) {
                              if (err) {
                                res.status(401).json({
                                  message: "Adding Patient failed!",
                                });
                              } else {
                                const formatYmd = (date) =>
                                  date.toISOString().slice(0, 10);
                                const dateNow = formatYmd(new Date());
                                var pin = req.body.address.split(" ")[1];
                                max_admno_ehr_sql =
                                  "SELECT crno FROM pt_key WHERE rownum = 1";

                                if (process.env.EHR_CONNECT == "true") {
                                  con_ehr.query(
                                    max_admno_ehr_sql,
                                    function (err, result) {
                                      if (err) {
                                        console.log("EHR Error:", err);
                                        res.status(401).json({
                                          message:
                                            "Adding Patient to EHR failed!",
                                        });
                                      } else {
                                        var admno = +result[0].crno + 1;
                                        var cur_ts = new Date()
                                          .toISOString()
                                          .replace(/T/, " ")
                                          .replace(/\..+/, "");

                                        var update_pt_key = `UPDATE pt_key SET crno = ?, cr_request = 'VirtualSathi', cr_time = ? WHERE rownum = '1'`;

                                        con_ehr.query(
                                          update_pt_key,
                                          [admno, cur_ts],
                                          function (err, result) {
                                            if (err) {
                                              console.log("EHR Error:", err);
                                              res.status(401).json({
                                                message:
                                                  "Updating Pt_key in EHR failed!",
                                              });
                                            } else {
                                              console.log(dateNow, "dateNow");
                                              var update_ehr_sql = `INSERT INTO adm_new 
                                              (ma_dated, ma_name, lname, ma_address, Date_of_birth, Telno, cellno, sex,
                                               email, admno, vs_frontend) 
                                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

                                              con_ehr.query(
                                                update_ehr_sql,
                                                [
                                                  "2024-01-19", // ma_dated value
                                                  req.body.fname, // ma_name
                                                  req.body.lname, // lname
                                                  req.body.address, // ma_address
                                                  req.body.dob, // Date_of_birth
                                                  req.body.mobile_no, // Telno
                                                  req.body.mobile_secondary, // cellno
                                                  req.body.gender.toUpperCase()[0], // sex
                                                  req.body.email, // email
                                                  admno, // admno
                                                  patientId, // vs_frontend
                                                ],
                                                function (err, result) {
                                                  if (err) {
                                                    console.log(
                                                      "EHR Error:",
                                                      err,
                                                    );
                                                    res.status(401).json({
                                                      message:
                                                        "Adding Patient to adm new in EHR failed!",
                                                    });
                                                  } else {
                                                    var casesheet_sql = `INSERT INTO casesheet (admno, cheif_complaint, ma_index) VALUES (?, ?, '0')`;
                                                    con_ehr.query(
                                                      casesheet_sql,
                                                      [
                                                        admno,
                                                        req.body
                                                          .medical_history,
                                                      ],
                                                      function (err, result) {
                                                        if (err) {
                                                          console.log(
                                                            "EHR Error:",
                                                            err,
                                                          );
                                                          res.status(401).json({
                                                            message:
                                                              "Adding Patient data to casesheet in EHR failed!",
                                                          });
                                                        } else {
                                                          var add_admno_to_local_db = `UPDATE patient_details SET ehr_id = ? WHERE email_id = ?`;

                                                          con.query(
                                                            add_admno_to_local_db,
                                                            [
                                                              admno,
                                                              req.body.email,
                                                            ],
                                                            function (
                                                              err,
                                                              result,
                                                            ) {
                                                              if (err) {
                                                                console.log(
                                                                  "EHR Error:",
                                                                  err,
                                                                );
                                                                res
                                                                  .status(401)
                                                                  .json({
                                                                    message:
                                                                      "Adding Patient ehr_id from EHR to Local db failed!",
                                                                  });
                                                              } else {
                                                                console.log(
                                                                  "EHR Updated and ehr_id added to local",
                                                                );
                                                                console.log(
                                                                  result,
                                                                );
                                                                res
                                                                  .status(201)
                                                                  .json({
                                                                    message:
                                                                      "Patient added successfully to EHR and Local",
                                                                  });
                                                              }
                                                            },
                                                          );
                                                        }
                                                      },
                                                    );
                                                  }
                                                },
                                              );
                                            }
                                          },
                                        );
                                      }
                                    },
                                  );
                                }
                              }
                            },
                          );
                        }
                      },
                    );
                  }
                },
              );
            });
          }
        }
      },
    );
  }
});

router.post("/add-patients", patientSession, async (req, res) => {
  try {
    const helperId = -1;
    const {
      fname,
      lname,
      email,
      password,
      mobile_no,
      mobile_secondary,
      countrycode,
      idType,
      idNumber,
      gender,
      address,
      medical_history,
      dob: dobInput,
      abhaId,
    } = req.body;

    if (!isPasswordValid(password)) {
      return res.status(400).json({ message: INVALID_PASSWORD_MESSAGE });
    }

    let medical_history_val =
      medical_history?.trim() || "Default from Virtual Sathi";

    // Normalize dob
    let dob = dobInput;
    if (!dob)
      return res
        .status(400)
        .json({ message: "Date of birth cannot be empty." });
    if (!isNaN(dob)) {
      const year = new Date().getFullYear() - parseInt(dob, 10);
      dob = `${year}-01-01`;
    } else if (isNaN(Date.parse(dob))) {
      return res.status(400).json({ message: "Invalid date format for dob." });
    }

    // Basic validations
    if (!fname || !lname)
      return res
        .status(400)
        .json({ message: "First and last name are required." });
    if (fname.length > 20 || lname.length > 30)
      return res.status(400).json({ message: "Name too long." });
    if (!emailExpression.test(email))
      return res.status(400).json({ message: "Invalid email." });
    if (!isPasswordValid(password))
      return res.status(400).json({ message: INVALID_PASSWORD_MESSAGE });
    if (!mobile_no || !mobile_secondary)
      return res
        .status(400)
        .json({ message: "Both phone numbers are required." });
    if (
      !phoneExpression.test(mobile_no) ||
      !phoneExpression.test(mobile_secondary)
    )
      return res.status(400).json({ message: "Invalid phone numbers." });
    if (!gender)
      return res.status(400).json({ message: "Gender is required." });
    if (!address) return res.status(400).json({ message: "PIN is required." });
    if (!/^\d{6}$/.test(address.trim()))
      return res.status(400).json({ message: "Invalid PIN." });

    // Check email uniqueness
    const [existing] = await new Promise((resolve, reject) => {
      con.query(
        "SELECT 1 FROM patient_details WHERE email_id = ?",
        [email],
        (err, rows) => (err ? reject(err) : resolve(rows)),
      );
    });
    if (existing)
      return res.status(409).json({ message: "Registration could not be completed with these details." });

    // Hash password & insert patient
    const hash = await bcrypt.hash(password, 11);
    const parentId = req.userData.userId;
    const insertSql = `
      INSERT INTO patient_details
      (helper_id, parent_id, fname, lname, address, dob, countryCode, mobile_no,
      sec_countryCode, mobile_secondary, medical_history, id_type, adhaar,
      gender, email_id, hashed_pwd, abhaId)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const insertParams = [
      helperId,
      parentId,
      fname,
      lname,
      address,
      dob,
      countrycode,
      mobile_no,
      countrycode,
      mobile_secondary,
      medical_history_val,
      idType,
      idNumber,
      gender,
      email,
      hash,
      abhaId,
    ];
    const insertResult = await new Promise((resolve, reject) =>
      con.query(insertSql, insertParams, (err, result) =>
        err ? reject(err) : resolve(result),
      ),
    );
    const patientId = insertResult.insertId;

    // Step: EHR crno
    const [crnoRow] = await new Promise((resolve, reject) => {
      con_ehr.query(
        "SELECT crno FROM pt_key ORDER BY rownum ASC LIMIT 1",
        (err, rows) => (err ? reject(err) : resolve(rows)),
      );
    });
    const crno = crnoRow.crno + 1;
    const today = new Date().toISOString().split("T")[0];

    // Insert into adm_new
    await new Promise((resolve, reject) => {
      con_ehr.query(
        `INSERT INTO adm_new (ma_name, lname, ma_address, Date_of_birth, Telno, cellno, sex, email, admno, vs_frontend, ma_dated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          fname,
          lname,
          address,
          dob,
          mobile_no,
          mobile_secondary,
          gender.toUpperCase()[0],
          email,
          crno,
          patientId,
          today,
        ],
        (err, result) => (err ? reject(err) : resolve(result)),
      );
    });

    // Update pt_key
    await new Promise((resolve, reject) => {
      con_ehr.query(
        `UPDATE pt_key SET crno = ?, cr_request = 'VirtualSathi', cr_time = ? WHERE rownum = '1'`,
        [crno, new Date().toISOString().slice(0, 19).replace("T", " ")],
        (err, result) => (err ? reject(err) : resolve(result)),
      );
    });

    // Insert into casesheet
    await new Promise((resolve, reject) => {
      con_ehr.query(
        `INSERT INTO casesheet (admno, cheif_complaint, ma_index) VALUES (?, ?, '0')`,
        [crno, medical_history_val],
        (err, result) => (err ? reject(err) : resolve(result)),
      );
    });

    // Update local patient_details with ehr_id
    await new Promise((resolve, reject) => {
      con.query(
        `UPDATE patient_details SET ehr_id = ? WHERE patient_id = ?`,
        [crno, patientId],
        (err, result) => (err ? reject(err) : resolve(result)),
      );
    });

    // Insert into patient_additional
    const dateStr = new Date()
      .toLocaleDateString("en-GB")
      .split("/")
      .reverse()
      .join("-");
    await new Promise((resolve, reject) => {
      con.query(
        `INSERT INTO patient_additional (patient_id, registrationDate) VALUES (?, ?)`,
        [patientId, dateStr],
        (err, result) => (err ? reject(err) : resolve(result)),
      );
    });

    // Final Response
    return res.status(201).json({
      message: "Patient added successfully to EHR and Local",
      patientId: patientId,
      ehrId: crno,
    });
  } catch (err) {
    console.error("Error:", err);
    return res
      .status(500)
      .json({ message: "Server error during patient creation." });
  }
});

router.get("/get-patients", patientSession, (req, res) => {
  const parentId = req.userData.userId;
  if (req.query.id && String(req.query.id) !== String(parentId)) return res.status(404).json({ message: "Resource not found." });
  console.log("et-patient");
  if (!parentId) {
    return res.status(400).json({ message: "Invalid or missing parent ID." });
  }

  con.query(
    "SELECT * FROM patient_details WHERE parent_id = ? AND (helper_id IS NULL OR helper_id = -1)",
    [parentId],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Could not fetch patients." });
      }
      return res.status(200).json({ patients: rows.map(publicRecord) });
    },
  );
});

router.post(
  "/medreport",
  patientSession,
  multer({ storage: storage }).single("image"),
  (req, res, next) => {
    console.log(req.body);
    //const url = req.protocol + '://'+ req.get('host');
    // const url = process.env.BACKEND_PROTOCOL + "://" + req.get("host");
    // const url = process.env.BACKEND_PROTOCOL_LOCAL;
    const urlLive = process.env.BACKEND_PROTOCOL_PROD;

    const imagePath = urlLive + "/images/" + req.file.filename;
    const creator = req.userData.userId;

    const localPath = "./images/" + req.file.filename;
    const fileInfo = fs.statSync(localPath);

    const fileSize = fileInfo.size;
    const fileSizeMB = fileInfo.size / (1024 * 1024);

    let uploadLimit = 5;

    const post = {
      title: req.body.title,
      content: req.body.content,
      imagePath: imagePath,
      creator: req.userData.userId,
    };

    //var sql = `INSERT INTO patient_med_reports (patient_id, report_title, content, imagePath, mediaType, recordDate) VALUES ('${req.userData.userId}', '${req.body.title}', '${req.body.content}', '${imagePath}', '${req.body.mediaType}', '${req.body.recordDate}')`;
    var sql = `SELECT COUNT(*) AS p_count FROM appointments WHERE patient_id = ?`;

    con.query(sql, [req.userData.userId], function (err, result) {
      if (err) {
        console.log(err);
        res.status(500).json({
          message:
            "Adding A Medical Record Failed- error in counting appointments!",
        });
      } else {
        if (result[0].p_count > 0) {
          uploadLimit = 25;
          var sql = `SELECT SUM(mediaSize) AS current_size FROM patient_med_reports WHERE patient_id = ?`;

          con.query(sql, [req.userData.userId], function (err, result) {
            if (err) {
              console.log(err);
              res.status(500).json({
                message:
                  "Adding A Medical Record Failed- error in summing up size of all reords!",
              });
            } else {
              if (result[0].current_size + fileSizeMB > uploadLimit) {
                res.status(401).json({
                  message:
                    "The size of the uploaded file exceed your overall upload limit! Delete old files, or reduce the size of the current file and try again or Call our helpline.",
                });
              } else {
                var sql = `INSERT INTO patient_med_reports (patient_id, report_title, content, imagePath, mediaType, recordDate, mediaSize) VALUES (?, ?, ?, ?, ?, ?, ?)`;

                con.query(
                  sql,
                  [
                    req.userData.userId,
                    req.body.title,
                    req.body.content,
                    imagePath,
                    req.body.mediaType,
                    req.body.recordDate,
                    fileSizeMB,
                  ],
                  function (err, result) {
                    if (err) {
                      console.log(err);
                      res.status(500).json({
                        message: "Adding A Medical Record Failed!",
                      });
                    } else {
                      res.status(201).json({
                        message: "Medical Record addeded successfully",
                        post: result,
                      });
                    }
                  },
                );
              }
            }
          });
        } else {
          uploadLimit = 5;

          var sql = `SELECT SUM(mediaSize) AS current_size FROM patient_med_reports WHERE patient_id = ?`;

          con.query(sql, [req.userData.userId], function (err, result) {
            if (err) {
              console.log(err);
              res.status(500).json({
                message:
                  "Adding A Medical Record Failed- error in summing up size of all reords!",
              });
            } else {
              if (result[0].current_size + fileSizeMB > uploadLimit) {
                res.status(401).json({
                  message:
                    "The size of the uploaded file exceed your overall upload limit! Delete old files, or reduce the size of the current file and try again or Call our helpline.",
                });
              } else {
                var sql = `INSERT INTO patient_med_reports (patient_id, report_title, content, imagePath, mediaType, recordDate, mediaSize) VALUES (?, ?, ?, ?, ?, ?, ?)`;

                con.query(
                  sql,
                  [
                    req.userData.userId,
                    req.body.title,
                    req.body.content,
                    imagePath,
                    req.body.mediaType,
                    req.body.recordDate,
                    fileSizeMB,
                  ],
                  function (err, result) {
                    if (err) {
                      console.log(err);
                      res.status(500).json({
                        message: "Adding A Medical Record Failed!",
                      });
                    } else {
                      res.status(201).json({
                        message: "Medical Record addeded successfully",
                        post: result,
                      });
                    }
                  },
                );
              }
            }
          });
        }
      }
      //console.log(result);
    });

    // res.status(201).json({
    //     message: 'Post addeded successfully',
    //     post: post
    // });
  },
);

router.post("/medreportwoimage", patientSession, reportAttachment, (req, res, next) => {
  console.log(req.body);
  // const url = req.protocol + '://'+ req.get('host');
  // const imagePath = url + '/images/' + req.file.filename;
  const creator = req.userData.userId;
  //console.log('image path: ', imagePath);

  // const post = {
  //     title: req.body.title,
  //     content: req.body.content,
  //     imagePath: imagePath,
  //     creator: req.userData.userId
  // }

  //var sql = `INSERT INTO patient_med_reports (patient_id, report_title, content, imagePath, mediaType, recordDate) VALUES ('${req.userData.userId}', '${req.body.title}', '${req.body.content}', '${req.body.image}', '${req.body.mediaType}', '${req.body.recordDate}')`;
  var sql = `INSERT INTO patient_med_reports (patient_id, report_title, content, imagePath, mediaType, recordDate) VALUES (?, ?, ?, ?, ?, ?)`;

  con.query(
    sql,
    [
      req.userData.userId,
      req.body.title,
      req.body.content,
      req.body.image,
      req.body.mediaType,
      req.body.recordDate,
    ],
    function (err, result) {
      if (err) {
        console.log(err);
        res.status(500).json({
          message: "Adding A Medical Record Failed!",
        });
      } else {
        res.status(201).json({
          message: "Medical Record addeded successfully",
          post: result,
        });
      }
      //console.log(result);
    },
  );

  // res.status(201).json({
  //     message: 'Post addeded successfully',
  //     post: post
  // });
});

router.post("/getorderid", patientAccess(req => req.body.patient_id ?? (req.userData.role === "patient" ? req.userData.userId : undefined)), (req, res, next) => {
  req.body.patient_id = req.authorizedPatient.patient_id;
  //Yet to add the appointments available checks before creating the order id
  console.log("Order details:", req.body);
  var params = {
    amount: req.body.amount,
    currency: "INR",
    receipt: "wizztechdevelopment",
    payment_capture: "1",
  };

  var sql = `SELECT * FROM appointments WHERE calendar_id= ? AND patient_id= ?`;
  con.query(
    sql,
    [req.body.calendar_id, req.body.patient_id],
    function (err, result) {
      if (err) {
        console.log(err);
        res.status(500).json({
          message: "Error while creating appointment!",
        });
      } else {
        console.log("sql1", sql);
        console.log("j1", result);
        if (result.length > 0) {
          res.status(401).json({
            message: "Cannot Book The Same Appointment Twice!",
          });
        } else {
          //sql =`SELECT * FROM doctor_calendar WHERE calendar_id='${req.body.calenderId}'`;

          ////////

          sql = `SELECT * FROM doctor_calendar WHERE calendar_id= ?`;
          con.query(sql, [req.body.calendar_id], function (err, result) {
            if (err) {
              console.log(err);
              res.status(500).json({
                message:
                  "Error while fetching calender details - creating appointment!",
              });
            } else {
              console.log("j2", result);
              if (!result.length) return res.status(404).json({ message: "Calendar not found." });
              var calendarData = result[0];
              console.log("Calendar Data 1: ", result);
              //console.log(result);
              console.log("Max Patient", result[0].max_patients);
              console.log("Patient Count: ", result[0].patient_count);
              if (+result[0].patient_count < +result[0].max_patients) {
                let count = result[0].patient_count + 1;
                razorpay_instance.orders
                  .create(params)
                  .then((data) => {
                    console.log("Order Id Data: ", data);
                    res.status(201).json({
                      message: "success",
                      ky: process.env.RAZORPAY_KEY_ID,
                      sub: data,
                      status: "success",
                    });
                    // // res.send({ message: 'success', ky: process.env.RAZORPAY_KEY_ID, sub: data, status: "success" });
                    // // })
                    // .catch((error) => {
                    // res.send({ message: 'error',sub: error, status: "failed" });
                  })
                  .catch((err) => {
                    res.status(401).json({
                      message: "error",
                      sub: err,
                      status: "failed",
                    });
                  });
              } else {
                res.status(201).json({
                  message: "Cannot take anymore patients!",
                });
              }
            }
          });
        }
      }
    },
  );
});
function formatTime(timeStr) {
  if (!timeStr) return "N/A";
  const str = String(timeStr).padStart(4, "0"); // Ensure 4 digits
  const hours = str.substring(0, 2);
  const minutes = str.substring(2, 4);
  return `${hours}:${minutes}`;
}

function formatDate(dateStr) {
  if (!dateStr) return "N/A";
  const [year, month, day] = dateStr.split("-");
  return `${day}-${month}-${year}`;
}
router.post("/setappointment", patientAccess(req => req.body.patient_id ?? (req.userData.role === "patient" ? req.userData.userId : undefined)), (req, res, next) => {
  req.body.patient_id = req.authorizedPatient.patient_id;
  console.log("appointment");
  console.log(req.body, "req apoointenment");
  var doctarId; // Resolved from the booked calendar, never the frontend doctor key.
  var emailId = req.authorizedPatient.email_id;
  const post = {
    calenderId: req.body.calenderId,
    userId: req.body.patient_id,
  };

  sql = `SELECT * FROM doctor_calendar INNER JOIN doctor_details ON doctor_calendar.doctor_id = doctor_details.doctor_id WHERE doctor_calendar.calendar_id=?`;

  con.query(sql, [req.body.calendar_id], function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message:
          "Error while fetching calendar details - creating appointment!",
      });
    } else {
      if (!result.length) return res.status(404).json({ message: "Calendar not found." });
      var calendarData = result[0];
      doctarId = calendarData.doctor_id;
      console.log("Calendar Data 1: ", result);
      console.log("Max Patient", result[0].max_patients);
      console.log("Patient Count: ", result[0].patient_count);
      console.log("Doctor email:", result[0].email_id);
      console.log("Doctor phone:", result[0].mobile);
      let docEmailId = result[0].email_id;
      let apptDate = result[0].date; // e.g., '2025-12-23'
      let apptTime = result[0].time; // e.g., '0730'
      let docFname = result[0].fname;
      let docLname = result[0].lname;

      let count = result[0].patient_count + 1;

      body = req.body.razorpay_order_id + "|" + req.body.razorpay_payment_id;

      var expectedSignature = crypto
        .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
        .update(body.toString())
        .digest("hex");

      console.log("sig" + req.body.razorpay_signature);
      console.log("sig" + expectedSignature);

      if (expectedSignature === req.body.razorpay_signature) {
        sql = `UPDATE doctor_calendar SET patient_count = ? WHERE calendar_id = ?`;
        con.query(sql, [count, req.body.calendar_id], function (err, result) {
          if (err) {
            console.log(err);
            res.status(500).json({
              message:
                "Error while updating calendar details - creating appointment!",
            });
          } else {
            var cur_date_time = new Date().toLocaleString("en-GB", {
              timeZone: "Asia/Kolkata",
            });

            sql = `INSERT INTO appointments (patient_id, calendar_id, doc_type, date, booking_date_time, time, fees) VALUES (?, ?, ?, ?, ?, ?, ?)`;

            con.query(
              sql,
              [
                req.body.patient_id,
                req.body.calendar_id,
                calendarData.doc_type,
                calendarData.date,
                cur_date_time,
                calendarData.time,
                calendarData.fees,
              ],
              async function (err, result) {
                if (err) {
                  console.log(err);
                  res.status(500).json({
                    message: "Error while creating appointment!",
                  });
                } else {
                  console.log("message: ", "Appointment Booked Successfully");

                  console.log(doctarId, emailId);
                  sql = `SELECT * FROM adm_new where email=?`;
                  con_ehr.query(sql, [emailId], function (err, result) {
                    if (err) {
                      console.log(err);
                      res.status(500).json({
                        message:
                          "Error while fetching calendar details - creating appointment!",
                      });
                    } else {
                      if (result[0]?.doc_incharge != null) {
                        sql = `update adm_new set consultant=? where email=?`;
                        con_ehr.query(
                          sql,
                          [doctarId, emailId],
                          async function (err, result) {
                            if (err) {
                              console.log(err);
                              res.status(500).json({
                                message:
                                  "Error while fetching calendar details - creating appointment!",
                              });
                            } else {
                              console.log("updated...");

                              // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                              // WHATSAPP NOTIFICATION TO DOCTOR (fixed time + date format)
                              // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                              try {
                                let doctorMobile =
                                  calendarData.mobile != null
                                    ? String(calendarData.mobile)
                                    : null;

                                if (doctorMobile) {
                                  doctorMobile = doctorMobile.replace(
                                    /^\+/,
                                    "",
                                  );

                                  const formattedDate = formatDate(apptDate);
                                  const formattedTime = formatTime(apptTime);

                                  const whatsappPayload = {
                                    messaging_product: "whatsapp",
                                    to: doctorMobile,
                                    recipient_type: "individual",
                                    type: "template",
                                    template: {
                                      namespace:
                                        "264eb977_11b5_4bde_af0f_c2869b76016d",
                                      name: "aims2health_new_appointment_booked",
                                      language: {
                                        policy: "deterministic",
                                        code: "en",
                                      },
                                      components: [
                                        {
                                          type: "body",
                                          parameters: [
                                            {
                                              type: "text",
                                              text: req.body.patient_id,
                                            },
                                            {
                                              type: "text",
                                              text: `${formattedDate} at ${formattedTime}`, // Now: 23-12-2025 at 07:30
                                            },
                                          ],
                                        },
                                      ],
                                    },
                                  };

                                  const needle = require("needle");
                                  const whatsappResponse = await needle(
                                    "post",
                                    "https://convergenow.ai/whatsapp-api/messaging_api/?client_id=917439937931",
                                    JSON.stringify(whatsappPayload),
                                    { headers: { "Content-Type": "application/json" } },
                                  );

                                  if (
                                    whatsappResponse.statusCode === 200 ||
                                    whatsappResponse.statusCode === 201
                                  ) {
                                    console.log(
                                      "WhatsApp sent to doctor successfully",
                                    );
                                  } else {
                                    console.log(
                                      "WhatsApp failed:",
                                      whatsappResponse.body ||
                                        whatsappResponse.statusCode,
                                    );
                                  }
                                } else {
                                  console.log(
                                    "No doctor mobile number found â€” skipping WhatsApp",
                                  );
                                }
                              } catch (whatsappErr) {
                                console.error(
                                  "Error sending WhatsApp to doctor:",
                                  whatsappErr,
                                );
                              }
                              // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

                              const formattedDate = formatDate(apptDate);

                              // Send via ZeptoMail â€” services.netxcell.com:8081
                              // (the previous provider) is unreachable. VAPT L1
                              // Finding 15 / L2 Finding 18, "Broken Functionality".
                              try {
                                await zeptomail.sendMail({
                                  to: process.env.ADMIN_EMAIL,
                                  toName: "Admin",
                                  subject: "Aims2health Appointment",
                                  text: `Dear Admin,\nA Patient (Patient Id: ${
                                    req.body.patient_id
                                  }) has booked an appointment with Dr. ${docFname} ${docLname} on: ${formattedDate} at ${formatTime(
                                    apptTime,
                                  )} Hrs. Let the doctor know that he/she needs to login to AIMS2Health at the scheduled date and time to create the zoom meeting and send a link to the patient(s).`,
                                });
                                console.log("Email sent to admin");

                                await zeptomail.sendMail({
                                  to: docEmailId,
                                  toName: "Doctor",
                                  subject: "Aims2health Appointment",
                                  text: `Dear Dr. ${docFname} ${docLname},\nA Patient (Patient Id: ${
                                    req.body.patient_id
                                  }) has booked an appointment with you on: ${formattedDate} at ${formatTime(
                                    apptTime,
                                  )} Hrs. Please login to AIMS2Health at the scheduled date and time to create the zoom meeting and send a link to the patient(s).`,
                                });
                                console.log("Email sent to doctor");

                                res.status(200).json({
                                  message: "Appointment booked Successfully",
                                });
                              } catch (error) {
                                console.error(error);
                                res.status(401).json({
                                  message: "Cannot Send booking email!",
                                });
                              }
                            }
                          },
                        );
                      } else {
                        sql = `update adm_new set doc_incharge=? where email=?`;
                        con_ehr.query(
                          sql,
                          [doctarId, emailId],
                          async function (err, result) {
                            if (err) {
                              console.log(err);
                              res.status(500).json({
                                message:
                                  "Error while fetching calendar details - creating appointment!",
                              });
                            } else {
                              // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                              // WHATSAPP NOTIFICATION TO DOCTOR (fixed time + date format)
                              // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                              try {
                                let doctorMobile =
                                  calendarData.mobile != null
                                    ? String(calendarData.mobile)
                                    : null;

                                if (doctorMobile) {
                                  doctorMobile = doctorMobile.replace(
                                    /^\+/,
                                    "",
                                  );

                                  const formattedDate = formatDate(apptDate);
                                  const formattedTime = formatTime(apptTime);

                                  const whatsappPayload = {
                                    messaging_product: "whatsapp",
                                    to: doctorMobile,
                                    recipient_type: "individual",
                                    type: "template",
                                    template: {
                                      namespace:
                                        "264eb977_11b5_4bde_af0f_c2869b76016d",
                                      name: "aims2health_new_appointment_booked",
                                      language: {
                                        policy: "deterministic",
                                        code: "en",
                                      },
                                      components: [
                                        {
                                          type: "body",
                                          parameters: [
                                            {
                                              type: "text",
                                              text: req.body.patient_id,
                                            },
                                            {
                                              type: "text",
                                              text: `${formattedDate} at ${formattedTime}`,
                                            },
                                          ],
                                        },
                                      ],
                                    },
                                  };

                                  const needle = require("needle");
                                  const whatsappResponse = await needle(
                                    "post",
                                    "https://convergenow.ai/whatsapp-api/messaging_api/?client_id=917439937931",
                                    JSON.stringify(whatsappPayload),
                                    { headers: { "Content-Type": "application/json" } },
                                  );

                                  if (
                                    whatsappResponse.statusCode === 200 ||
                                    whatsappResponse.statusCode === 201
                                  ) {
                                    console.log(
                                      "WhatsApp sent to doctor successfully",
                                    );
                                  } else {
                                    console.log(
                                      "WhatsApp failed:",
                                      whatsappResponse.body ||
                                        whatsappResponse.statusCode,
                                    );
                                  }
                                } else {
                                  console.log(
                                    "No doctor mobile number found â€” skipping WhatsApp",
                                  );
                                }
                              } catch (whatsappErr) {
                                console.error(
                                  "Error sending WhatsApp to doctor:",
                                  whatsappErr,
                                );
                              }
                              // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

                              const formattedDate = formatDate(apptDate);

                              // Send via ZeptoMail â€” services.netxcell.com:8081
                              // (the previous provider) is unreachable. VAPT L1
                              // Finding 15 / L2 Finding 18, "Broken Functionality".
                              try {
                                await zeptomail.sendMail({
                                  to: process.env.ADMIN_EMAIL,
                                  toName: "Admin",
                                  subject: "Aims2health Appointment",
                                  text: `Dear Admin,\nA Patient (Patient Id: ${
                                    req.body.patient_id
                                  }) has booked an appointment with Dr. ${docFname} ${docLname} on: ${formattedDate} at ${formatTime(
                                    apptTime,
                                  )} Hrs. Let the doctor know that he/she needs to login to AIMS2Health at the scheduled date and time to create the zoom meeting and send a link to the patient(s).`,
                                });
                                console.log("Email sent to admin");

                                await zeptomail.sendMail({
                                  to: docEmailId,
                                  toName: "Doctor",
                                  subject: "Aims2health Appointment",
                                  text: `Dear Dr. ${docFname} ${docLname},\nA Patient (Patient Id: ${
                                    req.body.patient_id
                                  }) has booked an appointment with you on: ${formattedDate} at ${formatTime(
                                    apptTime,
                                  )} Hrs. Please login to AIMS2Health at the scheduled date and time to create the zoom meeting and send a link to the patient(s).`,
                                });
                                console.log("Email sent to doctor");

                                res.status(200).json({
                                  message: "Appointment booked Successfully",
                                });
                              } catch (error) {
                                console.error(error);
                                res.status(401).json({
                                  message: "Cannot Send booking email!",
                                });
                              }
                            }
                          },
                        );
                      }
                    }
                  });

                  //..........................................................
                }
              },
            );
          }
        });
      } else {
        res.status(500).json({
          message: "Payment Not Successful!",
        });
      }
    }
  });
});

router.post("/login", (req, res, next) => {
  (async () => {
    const identifierKeys = createLoginLockKeys({ identifier: req.body?.email, identifierType: "email" });
    if (await isLoginLocked(con, identifierKeys)) {
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }

    const result = await new Promise((resolve, reject) => {
      con.query("SELECT * FROM patient_details WHERE email_id = ?", [req.body?.email], (err, rows) => err ? reject(err) : resolve(rows));
    });
    if (result.length <= 0) {
      await comparePasswordOrDummy(req.body?.password, undefined, 11);
      await recordLoginFailure(con, identifierKeys);
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }

    const user = result[0];
    const lockKeys = createLoginLockKeys({ identifier: req.body?.email, role: "patient", accountId: user.patient_id });
    if (await isLoginLocked(con, lockKeys)) {
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    const authResult = await comparePasswordOrDummy(req.body?.password, user.hashed_pwd, 11);
    if (!authResult) {
      await recordLoginFailure(con, lockKeys);
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    if (await isLoginLocked(con, lockKeys)) {
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    await clearLoginFailures(con, lockKeys);

    const token = jwt.sign(
      { email: user.email_id, userId: user.patient_id, role: "patient" },
      "" + process.env.JWT_SECRET_PATIENT,
      { expiresIn: "1h" },
    );
    const csrfToken = generateCsrfToken();
    res.cookie("auth_token", token, authCookieOptions());
    res.cookie(CSRF_COOKIE, csrfToken, csrfCookieOptions());
    return res.status(200).json({
      expiresIn: 3600,
      userId: +user.patient_id,
      userEmail: user.email_id,
      userName: user.fname + " " + user.lname,
    });
  })().catch(error => {
    console.error("Patient login failed safely:", error);
    if (!res.headersSent) res.status(503).json({ message: "Unable to authenticate right now." });
  });
});

router.post("/forgetpwd", (req, res, next) => {
  //var sql = `SELECT * FROM patient_details WHERE email_id= '${req.body.email}'`;
  var sql = `SELECT * FROM patient_details WHERE email_id= ?`;

  //console.log(req.body)
  con.query(sql, [req.body.email], function (err, result, fields) {
    if (err) {
      res.status(500).json({
        message: "Unable to process the password recovery request.",
      });
    } else {
      if (result.length <= 0) {
        res.status(200).json({
          message: "If the account is eligible, password reset instructions will be sent.",
        });
      } else {
        const secret =
          "" +
          process.env.JWT_SECRET_PATIENT +
          result[0].email_id +
          result[0].hashed_pwd;

        const token = jwt.sign(
          {
            email: result[0].email_id,
            userId: result[0].patient_id,
            role: "patient",
          },
          secret,
          { expiresIn: "10m" },
        );

        const link = `${process.env.FRONTEND_URL}/presetpwd/${result[0].patient_id}/${token}`;

        const msg = {
          to: result[0].email_id, // Change to your recipient
          from: process.env.SENDGRID_FROM_ADDRESS, // Change to your verified sender
          subject: "AIMS2Health Login Password Reset",
          text: `Dear Patient! Your AIMS2Health login password reset link is ${link} , this link will be valid for only 10mins.`,
          html: `Dear Patient! Your AIMS2Health login password reset link is ${link} , this link will be valid for only 10mins.`,
        };

        sgMail
          .send(msg)
          .then(() => {
            console.log(
              "Email sent for password reset for Patient-id:",
              result[0].patient_id,
            );
            res.status(200).json({
              message: "If the account is eligible, password reset instructions will be sent.",
            });
          })
          .catch((error) => {
            console.error("Patient password reset delivery failed.");
            res.status(200).json({
              message: "If the account is eligible, password reset instructions will be sent.",
            });
          });

        //res.status(200).json(result[0].email);
      }
    }
  });
});

// POST /forgetpwdresetpwd
router.post("/forgetpwdresetpwd", (req, res) => {
  const { patient_id, token, password } = req.body;
  const invalidLink = () => res.status(401).json({ message: "Invalid or expired reset link." });
  if (!isPasswordValid(password)) {
    return res.status(400).json({ message: INVALID_PASSWORD_MESSAGE });
  }
  const numericId = Number(patient_id);
  if (!Number.isSafeInteger(numericId) || numericId <= 0 || typeof token !== "string" || !token || typeof password !== "string" || !password) {
    return invalidLink();
  }

  const accountTables = {
    patient: { table: "patient_details", idColumn: "patient_id" },
    helper: { table: "helper_details", idColumn: "helper_id" },
  };
  const load = (role) => new Promise((resolve, reject) => {
    const { table, idColumn } = accountTables[role];
    con.query(`SELECT email_id, hashed_pwd FROM ${table} WHERE ${idColumn} = ?`, [numericId], (err, rows) => {
      if (err) reject(err);
      else resolve({ role, row: rows?.[0] });
    });
  });

  (async () => {
    try {
      // New links carry a signed role. Old links had no role and remain valid
      // during their 10-minute lifetime only when exactly one account verifies.
      const decoded = jwt.decode(token);
      const roles = decoded?.role && Object.hasOwn(accountTables, decoded.role)
        ? [decoded.role]
        : ["patient", "helper"];
      const candidates = await Promise.all(roles.map(load));
      const verified = [];
      for (const candidate of candidates) {
        if (!candidate.row) continue;
        const secret = process.env.JWT_SECRET_PATIENT + candidate.row.email_id + candidate.row.hashed_pwd;
        try {
          const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
          const claimedRole = payload.role;
          if (String(payload.userId) === String(numericId) && payload.email === candidate.row.email_id &&
              (!claimedRole || claimedRole === candidate.role)) {
            verified.push(candidate);
          }
        } catch (_) {
          // Keep all token validation failures indistinguishable to the caller.
        }
      }
      if (verified.length !== 1) return invalidLink();

      const account = verified[0];
      const { table, idColumn } = accountTables[account.role];
      const hash = await bcrypt.hash(password, 11);
      con.query(`UPDATE ${table} SET hashed_pwd = ? WHERE ${idColumn} = ?`, [hash, numericId], (updateError, result) => {
        if (updateError || !result?.affectedRows) {
          return res.status(500).json({ message: "Unable to update password." });
        }
        return res.status(201).json({ message: "Password updated successfully." });
      });
    } catch (_) {
      return res.status(500).json({ message: "Unable to process the password reset request." });
    }
  })();
});
// router.post("/hlogin", (req, res, next) => {
//         //    var sql = `SELECT * FROM helper_details WHERE email_id= '${req.body.email}'`;
//         var sql = `SELECT * FROM helper_details WHERE email_id= ?`;
//         //console.log(req.body)
//         con.query(sql, [req.body.email], function (err, result, fields) {
//             if (err){
//                 res.status(401).json({
//                     message: 'Invalid Authentication Credentials!'
//                 })
//             }else{
//                 console.log(result);
//                 if( result.length <= 0){
//                     res.status(401).json({
//                         message: 'Invalid Authentication Credentials!'
//                     });
//                 }else{
//                     console.log("Login data from DB:",result);
//                     bcrypt.compare(req.body.password, result[0].hashed_pwd)
//                     .then(auth_result => {
//                         console.log("auth_result: ",auth_result);
//                         if(!auth_result){
//                             res.status(401).json({
//                                 message: 'Invalid Authentication Credentials!'
//                             });
//                         }else{
//                             var sql = `SELECT helper_id, patient_id FROM patient_details  WHERE email_id = '${req.body.patient_email}'`;
//                             con.query(sql, function (err, result) {
//                                 if (err){
//                                     res.status(401).json({
//                                         message: 'Patient - Helper, error fetching data!'
//                                     });
//                                 }else{
//                                     console.log("res", result);
//                                     let patient_id = result[0].patient_id;
//                                     if(result.helper_id != -1){
//                                         var sql = `SELECT email_id FROM helper_details WHERE helper_id = '${result[0].helper_id}'`;
//                                         con.query(sql, function (err, result) {
//                                             if(err){
//                                                 console.log("jerr1");
//                                                 res.status(401).json({
//                                                     message: 'Error in Patien-Helper mapping!'
//                                                 });
//                                             }else{
//                                                 if(result.length > 0){
//                                                     if(result[0].email_id == ""+req.body.email){
//                                                         const token = jwt.sign({
//                                                             email: ""+req.body.patient_email,
//                                                             userId: patient_id
//                                                         }, 'secret_this_should_be_longer_&_more_complex_string', {expiresIn: "1h"});
//                                                         res.status(200).json({
//                                                             token: token,
//                                                             expiresIn: 3600,
//                                                             userId: +patient_id,
//                                                             userEmail: ""+req.body.email
//                                                         });
//                                                     }else{
//                                                         res.status(401).json({
//                                                             message: 'Patient - Helper, incorrect mapping!'
//                                                         });
//                                                     }
//                                                 }else{
//                                                     res.status(401).json({
//                                                         message: 'Helper not assigned for selected patient!'
//                                                     });
//                                                 }
//                                             }
//                                         })
//                                     }else{
//                                         res.status(401).json({
//                                             message: 'No helper added for the patient yet'
//                                         });
//                                     }
//                                     console.log("helper-patient:",result);
//                                 }
//                             })
//                         }
//                     })
//                     .catch(err => {
//                         console.log("This error: ",err);
//                         res.status(401).json({
//                             message: 'Invalid Authentication Credentials!'
//                         });
//                     })
//                 }
//             }
//         });
// });
router.post("/listprescriptions", patientAccess(req => req.body.patientId), function (req, res, next) {
  const sql = `
    SELECT 
      p.*,
      CONCAT(d.fname, ' ', d.lname) AS doctor_name,
      d.doc_type AS doctor_specialty
    FROM prescriptions p
    LEFT JOIN doctor_calendar dc ON p.calendar_id = dc.calendar_id
    LEFT JOIN doctor_details d ON dc.doctor_id = d.doctor_id
    WHERE p.patient_id = ? 
      AND p.calendar_id = ?`;
  con.query(
    sql,
    [req.body.patientId, req.body.calendarId],
    function (err, result) {
      if (err) {
        console.log("Error:", err);
        return res.status(500).json({
          message: "Fetching Prescriptions Failed!",
        });
      }
      res.status(200).json({
        message: "Received Prescriptions successfully",
        post: result,
      });
    },
  );
});
router.delete("/medrecords/:id", ownReport, (req, res, next) => {
  console.log(req.params.id);

  var sql = `DELETE FROM patient_med_reports WHERE report_id = ? AND patient_id = ?`;
  con.query(sql, [req.params.id, req.userData.userId], function (err, result) {
    if (err) {
      return res.status(500).json({ message: "Could not delete record." });
    }
    if (!result.affectedRows) return res.status(404).json({ message: "Resource not found." });
    console.log("Number of records deleted: " + result.affectedRows);
    res.status(200).json({ message: "Patient deleted!" });
  });
});

const { blacklistToken } = require("../middleware/token-blacklist");
router.post("/logout", patientSession, (req, res) => {
  blacklistToken(req.userData.token);
  res.clearCookie("auth_token", clearCookieOptions());
  res.clearCookie(CSRF_COOKIE, csrfClearCookieOptions());
  res.status(200).json({ message: "Logged out successfully." });
});

router.post("/:id", patientAccess(req => req.params.id), (req, res, next) => {
  con.query(
    `SELECT patient_id, helper_id, fname, lname, address, dob, mobile_no, mobile_secondary, medical_history, id_type, adhaar, gender, email_id FROM patient_details WHERE patient_id = ?`,
    [req.params.id],
    function (err, result, fields) {
      if (err) {
        console.log(err);

        res.status(404).json({
          message: "Patient not found!",
          post: result,
        });
      }
      console.log(result);
      if (result.length <= 0) {
        res.status(404).json({
          message: "Patient not found!",
        });
      } else {
        res.status(200).json({ data: result });
      }
    },
  );
});

module.exports = router;

