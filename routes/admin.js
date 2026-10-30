const express = require("express");
const router = express.Router();
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const { comparePasswordOrDummy } = require("../utils/password-auth");
const {
  createLoginLockKeys,
  isLoginLocked,
  recordLoginFailure,
  clearLoginFailures,
} = require("../utils/login-lockout");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const sgMail = require("@sendgrid/mail");

const { generateCsrfToken, CSRF_COOKIE } = require("../middleware/csrf-protection");
const { authCookieOptions, csrfCookieOptions, clearCookieOptions, csrfClearCookieOptions } = require("../utils/auth-cookies");
const dotenv = require("dotenv");
dotenv.config();

const twilio_accountSid = process.env.TWILIO_AC_SID;
const twilio_authToken = process.env.TWILIO_AUTHTOKEN;
const twilio_client = require("twilio")(twilio_accountSid, twilio_authToken);

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

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
  if (err) throw err;
  console.log("Connected to MySQL Database!");
});

const authorization = require('../utils/authorization')((sql, values) => new Promise((resolve, reject) => con.query(sql, values, (err, rows) => err ? reject(err) : resolve(rows))));
const adminSession = authorization.guard(['admin']);

router.post("/login", (req, res) => {
  (async () => {
    const identifierKeys = createLoginLockKeys({ identifier: req.body?.email, identifierType: "email" });
    if (await isLoginLocked(con, identifierKeys)) {
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    const result = await new Promise((resolve, reject) => {
      con.query("SELECT * FROM admin_details WHERE email_id = ?", [req.body?.email], (err, rows) => err ? reject(err) : resolve(rows));
    });
    if (result.length <= 0) {
      await comparePasswordOrDummy(req.body?.password, undefined, 11);
      await recordLoginFailure(con, identifierKeys);
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    const user = result[0];
    const lockKeys = createLoginLockKeys({ identifier: req.body?.email, role: "admin", accountId: user.admin_id });
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
      { email: user.email_id, userId: user.admin_id, role: "admin" },
      "" + process.env.JWT_SECRET_ADMIN,
      { expiresIn: "1h" },
    );
    const csrfToken = generateCsrfToken();
    res.cookie("auth_token", token, authCookieOptions());
    res.cookie(CSRF_COOKIE, csrfToken, csrfCookieOptions());
    return res.status(200).json({
      expiresIn: 3600,
      userId: +user.admin_id,
      Useremail: user.email_id,
      userName: user.email_id,
    });
  })().catch(error => {
    console.error("Admin login failed safely:", error);
    if (!res.headersSent) res.status(503).json({ message: "Unable to authenticate right now." });
  });
});

router.get("/listdoctorstovalidate", adminSession, function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  console.log("Get Prescription body:", req.body);

  var sql = `SELECT doctor_id, fname, lname, dob, mstatus, religion, mobile, educational_details, years_exp, registration_no, doc_type, adhaar, validated, ehr_id, email_id FROM doctor_details WHERE validated = '0'`;
  con.query(sql, function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message: "Adding A Medical Record Failed!",
      });
    } else {
      console.log("Doctors:", result);
      res.status(201).json({
        message: "Retreived Doctors data successfully",
        post: result,
      });
    }
    console.log("Prescriptions:", result);
  });
});

router.get("/listhelpers", adminSession, function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  console.log("Get Prescription body:", req.body);

  var sql = `SELECT helper_id, fname, lname, dob, mstatus, religion, mobile, educational_details, helper_type, adhaar, email_id FROM helper_details`;
  con.query(sql, function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message: "error fetching helper data!",
      });
    } else {
      console.log("Helpers:", result);
      res.status(201).json({
        message: "Retreived Helper data successfully",
        post: result,
      });
    }
    //console.log("Prescriptions:",result);
  });
});

router.get("/listdoctors", adminSession, function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  console.log("Get Prescription body:", req.body);

  var sql = `SELECT doctor_id, email_id, fname, lname, dob, mobile, educational_details, years_exp, registration_no, doc_type, ehr_id, validated FROM doctor_details`;
  con.query(sql, function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message: "error fetching doctors data!",
      });
    } else {
      console.log("Helpers:", result);
      res.status(201).json({
        message: "Retreived doctors data successfully",
        post: result,
      });
    }
    //console.log("Prescriptions:",result);
  });
});

router.get(
  "/listdoctorspayments/:doctorId",
  adminSession,
  function (req, res, next) {
    // console.log(req.body);
    // console.log("id:", req.body.id);
    var responseData;
    console.log("Reguest body param:", req.params.doctorId);

    //    var sql = `SELECT doctor_id, email_id, fname, lname, dob, mobile, educational_details, years_exp, registration_no, doc_type, ehr_id, validated FROM doctor_details`;
    var sql = `SELECT * FROM doctor_calendar WHERE doctor_id=? ORDER BY calendar_id DESC`;

    con.query(sql, [req.params.doctorId], function (err, result) {
      if (err) {
        console.log(err);
        res.status(500).json({
          message: "error fetching doctors data!",
        });
      } else {
        console.log("Helpers:", result);
        res.status(201).json({
          message: "Retreived doctors consutations data successfully",
          post: result,
        });
      }
      //console.log("Prescriptions:",result);
    });
  }
);

router.get("/listdoctorsextras", adminSession, function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  console.log("Reguest body param:", req.params.doctorId);

  //    var sql = `SELECT doctor_id, email_id, fname, lname, dob, mobile, educational_details, years_exp, registration_no, doc_type, ehr_id, validated FROM doctor_details`;
  var sql = `SELECT doctor_details.doctor_id AS doctor_id, doctor_details.fname AS fname, doctor_details.lname AS lname, doctor_details.ehr_id AS ehr_id, doctor_additional.bank_ifsc AS ifsc, doctor_additional.bank_ac_no AS bank_ac_no, doctor_additional.bank_ac_name AS bank_ac_name, doctor_additional.bio_data_url AS bio_data_url FROM doctor_details INNER JOIN doctor_additional ON doctor_details.doctor_id=doctor_additional.doctor_id`;

  con.query(sql, [req.params.doctorId], function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message: "error fetching doctors data!",
      });
    } else {
      console.log("Helpers:", result);
      res.status(201).json({
        message: "Retreived doctors consutations data successfully",
        post: result,
      });
    }
  });
});

router.post("/updateAmountPaidToDoc", adminSession, (req, res, next) => {
  var sql = `UPDATE doctor_calendar SET amt_paid_to_doc= ? WHERE calendar_id = ?`;
  //console.log(req.body)
  con.query(
    sql,
    [req.body.amount_paid, req.body.calendar_id],
    function (err, result, fields) {
      if (err) {
        res.status(401).json({
          message: "Invalid Authentication Credentials!",
        });
      } else {
        res.status(200).json({
          message: "Doctor Validated Successfully",
        });
      }
    }
  );
});

router.post("/updateIfsc", adminSession, (req, res, next) => {
  var sql = `UPDATE doctor_additional SET bank_ifsc= ? WHERE doctor_id = ?`;
  console.log(req.body);
  con.query(
    sql,
    [req.body.updatedValue, req.body.doctor_id],
    function (err, result, fields) {
      if (err) {
        res.status(401).json({
          message: "Invalid Authentication Credentials!",
        });
      } else {
        res.status(200).json({
          message: "Doctor Validated Successfully",
        });
      }
    }
  );
});

router.post("/updateAcNo", adminSession, (req, res, next) => {
  var sql = `UPDATE doctor_additional SET bank_ac_no= ? WHERE doctor_id = ?`;
  //console.log(req.body)
  con.query(
    sql,
    [req.body.updatedValue, req.body.doctor_id],
    function (err, result, fields) {
      if (err) {
        res.status(401).json({
          message: "Invalid Authentication Credentials!",
        });
      } else {
        res.status(200).json({
          message: "Doctor Validated Successfully",
        });
      }
    }
  );
});

router.post("/updateAcName", adminSession, (req, res, next) => {
  var sql = `UPDATE doctor_additional SET bank_ac_name= ? WHERE doctor_id = ?`;
  //console.log(req.body)
  con.query(
    sql,
    [req.body.updatedValue, req.body.doctor_id],
    function (err, result, fields) {
      if (err) {
        res.status(401).json({
          message: "Invalid Authentication Credentials!",
        });
      } else {
        res.status(200).json({
          message: "Doctor Validated Successfully",
        });
      }
    }
  );
});

router.post("/updateBioDataUrl", adminSession, (req, res, next) => {
  var sql = `UPDATE doctor_additional SET bio_data_url= ? WHERE doctor_id = ?`;
  //console.log(req.body)
  con.query(
    sql,
    [req.body.updatedValue, req.body.doctor_id],
    function (err, result, fields) {
      if (err) {
        res.status(401).json({
          message: "Invalid Authentication Credentials!",
        });
      } else {
        res.status(200).json({
          message: "Doctor Validated Successfully",
        });
      }
    }
  );
});

router.get("/listpatients", adminSession, function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  console.log("Get Prescription body:", req.body);

  var sql = `SELECT patient_id, helper_id, fname, lname, address, dob, mobile_no, mobile_secondary, medical_history, adhaar, email_id, ehr_id FROM patient_details`;
  con.query(sql, function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message: "error fetching helper data!",
      });
    } else {
      console.log("Helpers:", result);
      res.status(201).json({
        message: "Retreived Helper data successfully",
        post: result,
      });
    }
    //console.log("Prescriptions:",result);
  });
});

router.get("/listpatientswithbookings", adminSession, function (req, res, next) {
  const sql = `
    SELECT 
      pd.patient_id,
      pd.helper_id,
      pd.fname,
      pd.lname,
      pd.address,
      pd.dob,
      pd.mobile_no,
      pd.mobile_secondary,
      pd.medical_history,
      pd.id_type,
      pd.adhaar,
      pd.gender,
      pd.email_id,
      pd.ehr_id,
      pa.phone_verification,
      pa.email_verification,
      pa.patient_consent,
      COUNT(a.appointment_id) AS appointmentsBooked,

      /* Check if patient has any uploaded medical report (imagePath != 'na') */
      CASE 
        WHEN EXISTS (
          SELECT 1 
          FROM patient_med_reports pmr 
          WHERE pmr.patient_id = pd.patient_id 
            AND pmr.imagePath IS NOT NULL 
            AND TRIM(pmr.imagePath) != '' 
            AND LOWER(TRIM(pmr.imagePath)) != 'na'
        ) THEN TRUE 
        ELSE FALSE 
      END AS documentsUploaded

    FROM patient_details pd
    INNER JOIN patient_additional pa ON pd.patient_id = pa.patient_id
    LEFT OUTER JOIN appointments a ON pd.patient_id = a.patient_id
    LEFT OUTER JOIN patient_med_reports pmr ON pd.patient_id = pmr.patient_id   -- optional, only for EXISTS check

    GROUP BY 
      pd.patient_id,
      pd.helper_id, pd.fname, pd.lname, pd.address, pd.dob, pd.mobile_no, pd.mobile_secondary,
      pd.medical_history, pd.id_type, pd.adhaar, pd.gender, pd.email_id, pd.ehr_id,
      pa.phone_verification, pa.email_verification, pa.patient_consent

    ORDER BY pd.patient_id DESC   -- Latest patients (highest patient_id) first
  `;

  con.query(sql, (err, result) => {
    if (err) {
      console.error("Error fetching patients with bookings:", err);
      return res.status(500).json({
        success: false,
        message: "Error fetching patient data!",
      });
    }

    res.status(200).json({
      success: true,
      message: "Patients retrieved successfully",
      data: result, // each patient object now has "documentsUploaded": true/false
    });
  });
});

router.post("/validatedoc", adminSession, (req, res, next) => {
  var sql = `UPDATE doctor_details SET validated='1' WHERE email_id = ?`;
  //console.log(req.body)
  con.query(sql, [req.body.email_id], function (err, result, fields) {
    if (err) {
      res.status(401).json({
        message: "Invalid Authentication Credentials!",
      });
    } else {
      var sql2 = `SELECT doctor_id FROM doctor_details WHERE email_id = ?`;
      con.query(sql2, [req.body.email_id], function (err, result, fields) {
        if (err) {
          res.status(401).json({
            message:
              "Error doctor validation and additional fields additional!",
          });
        } else {
          Date_aptToDate = new Date();
          dateStr = Date_aptToDate.toLocaleDateString("en-GB")
            .split("/")
            .reverse()
            .join("-");
          var sql3 = `INSERT INTO doctor_additional (doctor_id, registrationValidationDate) VALUES (?, ?)`;
          con.query(
            sql3,
            [result[0].doctor_id, dateStr],
            function (err, result, fields) {
              if (err) {
                res.status(401).json({
                  message:
                    "Error doctor validation and additional fields additional!",
                });
              } else {
                res.status(200).json({
                  message:
                    "Doctor Validated and additional fields added Successfully",
                });
              }
            }
          );
        }
      });
    }
  });
});

router.post("/createNewDocType", adminSession, (req, res, next) => {
  if (req.body.docType.length > 25) {
    res.status(401).json({
      message: "The length of the new doctor type is too long!",
    });
  } else {
    var sql = `SELECT * FROM doc_types WHERE value=?`;
    con.query(
      sql,
      [req.body.docType.split(" ").join("_").toLowerCase()],
      function (err, result, fields) {
        if (err) {
          res.status(401).json({
            message: "Error in updating the new doctor type!",
          });
        } else {
          if (result.length > 0) {
            res.status(401).json({
              message: "A doctor type with the same name already exists!",
            });
          } else {
            var sql = `INSERT INTO doc_types (view_value, value) VALUES (?, ?)`;
            con.query(
              sql,
              [
                req.body.docType,
                req.body.docType.split(" ").join("_").toLowerCase(),
              ],
              function (err, result, fields) {
                if (err) {
                  res.status(401).json({
                    message: "Error in adding the new doctor type!",
                  });
                } else {
                  res.status(200).json({
                    message: "Doctor Type added Successfully",
                  });
                }
              }
            );
          }
        }
      }
    );
  }
});

router.post("/updateDocType", adminSession, (req, res, next) => {
  if (req.body.docType.length > 25 || req.body.docType == "") {
    res.status(401).json({
      message:
        "The length of the new doctor type is either too long or it is empty!",
    });
  } else {
    var sql = `SELECT * FROM doc_types WHERE value=?`;
    con.query(
      sql,
      [req.body.docType.split(" ").join("_").toLowerCase()],
      function (err, result, fields) {
        if (err) {
          res.status(401).json({
            message: "Error in updating the new doctor type!",
          });
        } else {
          if (result.length != 0) {
            res.status(401).json({
              message: "The updated type already exists!",
            });
          } else {
            var sql = `SELECT fname FROM doctor_details WHERE doc_type = ?`;
            con.query(
              sql,
              [req.body.existingValue],
              function (err, result, fields) {
                if (err) {
                  res.status(401).json({
                    message: "Error in getting the doctor type details!",
                  });
                } else {
                  if (result.length > 0) {
                    res.status(401).json({
                      message:
                        "Cannot update the specified doctor type. There are registered doctor(s) in the system with the given type!",
                    });
                  } else {
                    var sql = `UPDATE doc_types SET view_value = ?, value = ? WHERE value =?`;
                    con.query(
                      sql,
                      [
                        req.body.docType,
                        req.body.docType.split(" ").join("_").toLowerCase(),
                        req.body.existingValue,
                      ],
                      function (err, result, fields) {
                        if (err) {
                          res.status(401).json({
                            message: "Error in adding the new doctor type!",
                          });
                        } else {
                          res.status(200).json({
                            message: "Doctor Type added Successfully",
                          });
                        }
                      }
                    );
                  }
                }
              }
            );
          }
        }
      }
    );
  }
});

router.post("/deleteDocType", adminSession, (req, res, next) => {
  if (req.body.docType.length > 25) {
    res.status(401).json({
      message: "The length of the new doctor type is too long!",
    });
  } else {
    var sql = `SELECT * FROM doc_types WHERE value=?`;
    con.query(sql, [req.body.docType], function (err, result, fields) {
      if (err) {
        res.status(401).json({
          message: "Error in updating the new doctor type!",
        });
      } else {
        if (result.length == 0) {
          res.status(401).json({
            message: "The specified doctor type does not exist!",
          });
        } else {
          var sql = `SELECT fname FROM doctor_details WHERE doc_type = ?`;
          con.query(sql, [req.body.docType], function (err, result, fields) {
            if (err) {
              res.status(401).json({
                message: "Error in getting the doctor type details!",
              });
            } else {
              if (result.length > 0) {
                res.status(401).json({
                  message:
                    "Cannot delete the specified doctor type. There are registered doctor(s) in the system with the given type!",
                });
              } else {
                var sql = `DELETE FROM doc_types WHERE value = ?`;
                con.query(
                  sql,
                  [req.body.docType],
                  function (err, result, fields) {
                    if (err) {
                      res.status(401).json({
                        message: "Error in deleting doctor type!",
                      });
                    } else {
                      res.status(200).json({
                        message: "Doctor Type deleted Successfully",
                      });
                    }
                  }
                );
              }
            }
          });
        }
      }
    });
  }
});

router.get("/getdoctorTypes", function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  //console.log("Get Prescription body:", req.body);

  //var sql = `SELECT  * FROM doc_types`;
  //var sql =  `SELECT doc_types.view_value AS view_value, doc_types.value AS value, count(doctor_details.doc_type) FROM doc_types INNER JOIN doctor_details ON doctor_details.doc_types=doctor_types.value GROUP BY doc_types`;
  var sql = `SELECT doc_types.view_value AS view_value, doc_types.value AS value FROM doc_types`;
  con.query(sql, function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message: "error fetching doctor types!",
      });
    } else {
      console.log("Listing Doc Types:", result);
      res.status(201).json({
        message: "Retreived doctor type data successfully",
        post: result,
      });
    }
    //console.log("Prescriptions:",result);
  });
});

router.get("/listdoctorTypes", function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  //console.log("Get Prescription body:", req.body);

  //var sql = `SELECT  * FROM doc_types`;
  //var sql =  `SELECT doc_types.view_value AS view_value, doc_types.value AS value, count(doctor_details.doc_type) FROM doc_types INNER JOIN doctor_details ON doctor_details.doc_types=doctor_types.value GROUP BY doc_types`;
  var sql = `SELECT 
    doc_types.value AS value, 
    doc_types.view_value AS view_value,
    COUNT(DISTINCT doctor_details.doc_type) AS doc_count 
FROM 
    doc_types 
LEFT JOIN 
    doctor_details 
ON 
    doctor_details.doc_type = doc_types.value 
GROUP BY 
    doc_types.value, doc_types.view_value;`;
  con.query(sql, function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message: "error fetching doctor types!",
      });
    } else {
      console.log("Listing Doc Types:", result);
      res.status(201).json({
        message: "Retreived doctor type data successfully",
        post: result,
      });
    }
    //console.log("Prescriptions:",result);
  });
});

router.get("/listdoctorTypes/:date", function (req, res, next) {
  var responseData;
  console.log("Get req params:", req.params.date);

  // Updated SQL query with GROUP BY clause corrected
  var sql = `
    SELECT 
        doc_types.view_value AS view_value, 
        doc_types.value AS value, 
        COUNT(doctor_calendar.doc_type) AS doc_count 
    FROM 
        doc_types 
    INNER JOIN 
        doctor_calendar 
    ON 
        doctor_calendar.doc_type = doc_types.value 
    WHERE 
        doctor_calendar.date = ? 
    GROUP BY 
        doc_types.view_value, 
        doc_types.value 
    LIMIT 0, 1000;
  `;

  // Execute the query with the date parameter
  con.query(sql, [req.params.date], function (err, result) {
    if (err) {
      console.log(err);
      res.status(500).json({
        message: "Error fetching doctor types!",
      });
    } else {
      console.log("Listing Doc Types:", result);
      res.status(201).json({
        message: "Retrieved doctor type data successfully",
        post: result,
      });
    }
  });
});

router.post("/updatehelperforpatient", adminSession, (req, res, next) => {
  var sql = `UPDATE patient_details SET helper_id= ? WHERE email_id = ?`;
  //console.log(req.body)
  con.query(
    sql,
    [req.body.helper_id, req.body.patient_email],
    function (err, result, fields) {
      if (err) {
        res.status(401).json({
          message: "Invalid Authentication Credentials!",
        });
      } else {
        res.status(200).json({
          message: "Doctor Validated Successfully",
        });
      }
    }
  );
});

const { blacklistToken } = require("../middleware/token-blacklist");
router.post("/logout", adminSession, (req, res) => {
  blacklistToken(req.userData.token);
  res.clearCookie("auth_token", clearCookieOptions());
  res.clearCookie(CSRF_COOKIE, csrfClearCookieOptions());
  res.status(200).json({ message: "Logged out successfully." });
});

module.exports = router;
