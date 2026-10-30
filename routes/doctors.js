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
const axios = require("axios");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const needle = require("needle");
const fetch = require("fix-esm").require("node-fetch");

const sgMail = require("@sendgrid/mail");
const zeptomail = require("../utils/zeptomail");

const { buildLimit } = require("../utils/pagination");
const { generateCsrfToken, CSRF_COOKIE } = require("../middleware/csrf-protection");
const { authCookieOptions, csrfCookieOptions, clearCookieOptions, csrfClearCookieOptions } = require("../utils/auth-cookies");
const dotenv = require("dotenv");
dotenv.config();

const twilio_accountSid = process.env.TWILIO_AC_SID;
const twilio_authToken = process.env.TWILIO_AUTHTOKEN;
const twilio_client = require("twilio")(twilio_accountSid, twilio_authToken);

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// regular expressions for input validation (same policy as patients.js)
const emailExpression = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
const phoneExpression = /^\d{10}$/;

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
console.log("welcome to server !");
con.connect(function (err) {
  if (err) throw err;
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
  con_ehr.connect(function (err) {
    if (err) throw err;
    console.log("Connected to remote EHR Database!");
  });
}

// router.get('', doctorSession, (req, res, next) => {

//     const pageSize = +req.query.pagesize; //converting query param from string to number using +
//     const currentPage = +req.query.page;

//     var numPerPage = 20;
//     numPerPage = pageSize;
//     page = currentPage;
//     var skip = (page-1) * numPerPage;
//     var limit = skip + ',' + numPerPage; // Here we compute the LIMIT parameter for MySQL query
//     con.query('SELECT count(*) as numRows FROM doctor_details',function (err, rows, fields) {
//         if(err) {
//             console.log("error: ", err);
//             res.status(500).json({
//                 message: 'Fetching Posts Failed!'
//             });
//             //result(err, null);
//         }else{
//             var numRows = rows[0].numRows;
//             var numPages = Math.ceil(numRows / numPerPage);
//             con.query('SELECT * FROM doctor_details LIMIT ' + limit,function (err, rows, fields) {
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

const authorization = require('../utils/authorization')((sql, values) => new Promise((resolve, reject) => con.query(sql, values, (err, rows) => err ? reject(err) : resolve(rows))));
const doctorSession = authorization.guard(['doctor']);
const doctorProfile = authorization.guard(['doctor', 'admin'], req => req.userData.role === 'admin' || String(req.params.id) === String(req.userData.userId));
const calendarAccess = (id, roles = ['doctor', 'admin']) => authorization.guard(roles, (req, access) => access.calendar(req.userData, id(req)));
const doctorPatient = id => authorization.guard(['doctor'], async (req, access) => Boolean(await access.patient(req.userData, id(req))));
const doctorConsultation = authorization.guard(['doctor'], (req, access) => access.consultation(req.userData, req.body.patientId, req.body.calendarId));
const doctorAppointment = authorization.guard(['doctor'], async (req, access) => Boolean(req.authorizedPatient = await access.appointment(req.userData, req.body.appointmentId)));

router.post("/doctorExists", (req, res) => {
  // Registration decides whether the submitted email can be used; a public
  // availability boolean would enumerate doctor accounts.
  return res.status(200).json({ message: "Continue registration if eligible." });
});

router.get("/appointment/:id", doctorProfile, (req, res, next) => {
  const { limit, numPerPage } = buildLimit(req.query.pagesize, req.query.page);
  //console.log(" appt date:", dateStr);

  con.query(
    `SELECT count(*) as numRows FROM doctor_calendar WHERE doctor_id = ? ORDER BY date DESC`,
    [req.params.id],
    function (err, rows, fields) {
      //SELECT count(*) as numRows FROM `doctor_calendar` WHERE `doctor_id`=2 ORDER BY `calendar_id` DESC
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
          `SELECT * FROM doctor_calendar WHERE doctor_id = ? ORDER BY date DESC LIMIT ` +
            limit,
          [req.params.id],
          function (err, rows, fields) {
            //con.query(`SELECT * FROM doctor_calendar WHERE doctor_id = ? ORDER BY date DESC LIMIT ` + numPerPage, [req.params.id], function (err, rows, fields) {

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

router.get("/upcomingAppointment/:id", doctorProfile, (req, res, next) => {
  const pageSize = +req.query.pagesize || 20;
  const currentPage = +req.query.page || 1;

  const numPerPage = pageSize;
  const skip = (currentPage - 1) * numPerPage;

  todaysDate = new Date();
  dateStr = todaysDate
    .toLocaleDateString("en-GB")
    .split("/")
    .reverse()
    .join("-");

  console.log("upcoming date:", dateStr);

  // Count Query - Only  upcoming
  con.query(
    `SELECT COUNT(*) as numRows 
     FROM doctor_calendar 
     WHERE doctor_id = ? 
       AND date >= ?`,
    [req.params.id, dateStr],
    function (err, countRows) {
      if (err) {
        console.log("Count Error: ", err);
        return res.status(500).json({ message: "Fetching Failed!" });
      }

      const numRows = countRows[0].numRows;

      // Data Query - Same filter
      con.query(
        `SELECT * FROM doctor_calendar 
         WHERE doctor_id = ? 
           AND date >= ?  
         ORDER BY date ASC 
         LIMIT ? OFFSET ?`,
        [req.params.id, dateStr, numPerPage, skip],
        function (err, rows) {
          if (err) {
            console.log("Data Error: ", err);
            return res.status(500).json({ message: "Fetching Failed!" });
          }

          console.log("Upcoming Records Found:", rows.length);

          res.status(200).json({
            message: "Upcoming appointments fetched successfully!",
            posts: rows,
            maxPosts: numRows,
            currentPage: currentPage,
            pageSize: numPerPage,
          });
        },
      );
    },
  );
});

router.get("/pastAppointment/:id", doctorProfile, (req, res, next) => {
  const pageSize = +req.query.pagesize || 20;
  const currentPage = +req.query.page || 1;

  const numPerPage = pageSize;
  const skip = (currentPage - 1) * numPerPage;

  todaysDate = new Date();
  dateStr = todaysDate
    .toLocaleDateString("en-GB")
    .split("/")
    .reverse()
    .join("-");

  console.log("past date:", dateStr);

  // Count Query - Only past records with patient_count > 0
  con.query(
    `SELECT COUNT(*) as numRows 
     FROM doctor_calendar 
     WHERE doctor_id = ? 
       AND date < ? 
       AND patient_count > 0`,
    [req.params.id, dateStr],
    function (err, countRows) {
      if (err) {
        console.log("Count Error: ", err);
        return res.status(500).json({ message: "Fetching Failed!" });
      }

      const numRows = countRows[0].numRows;

      // Data Query - Same filter applied
      con.query(
        `SELECT * FROM doctor_calendar 
         WHERE doctor_id = ? 
           AND date < ? 
           AND patient_count > 0 
         ORDER BY date DESC 
         LIMIT ? OFFSET ?`,
        [req.params.id, dateStr, numPerPage, skip],
        function (err, rows) {
          if (err) {
            console.log("Data Error: ", err);
            return res.status(500).json({ message: "Fetching Failed!" });
          }

          console.log("Past Records Found:", rows.length);

          res.status(200).json({
            message: "Past appointments fetched successfully!",
            posts: rows,
            maxPosts: numRows,
            currentPage: currentPage,
            pageSize: numPerPage,
          });
        },
      );
    },
  );
});

router.get("/:id", doctorProfile, (req, res, next) => {
  con.query(
    `SELECT * FROM doctor_details WHERE doctor_id = ?`,
    [req.params.id],
    function (err, result, fields) {
      if (err) {
        console.log(err);

        res.status(404).json({
          message: "Doctor not found!",
          post: result,
        });
      }
      console.log(result);
      if (result.length <= 0) {
        res.status(404).json({
          message: "Doctor not found!",
        });
      } else {
        res.status(200).json({ res: result.map(publicRecord) });
      }
    },
  );
});

// router.get('/:id', (req, res, next) => {

//     con.query(`SELECT * FROM doctor_details WHERE doctor_id = '${req.params.id}'`, function (err, result, fields) {
//         if (err){
//             console.log(err)

//             res.status(404).json({
//                 message: 'Doctor not found!',
//                 post: result
//             });
//         }
//         console.log(result);
//         if( result.length <= 0){
//             res.status(404).json({
//                 message: 'Doctor not found!'

//             });
//         }else{
//             res.status(200).json(result);
//         }

//     });
// })

router.get("/patientDetails/:id", calendarAccess(req => req.params.id), (req, res, next) => {
  //sql = `SELECT * FROM patient_details INNER JOIN appointment ON patient_details.patient_id = appointment.patient_id WHERE appointments.calendar_id = '${req.params.id}'; `;
  //sql=`SELECT * FROM appointments WHERE calendar_id = '${req.params.id}'`;
  con.query(
    `SELECT * FROM patient_details INNER JOIN appointments ON patient_details.patient_id = appointments.patient_id WHERE appointments.calendar_id = ?`,
    [req.params.id],
    function (err, result, fields) {
      if (err) {
        console.log(err);

        res.status(404).json({
          message: "Appointment Details not found!",
          post: result,
        });
      } else {
        console.log(result);
        if (result.length <= 0) {
          res.status(200).json(result.map(publicRecord));
        } else {
          res.status(200).json(result.map(publicRecord));
        }
      }
    },
  );
});

// router.put('/:id', (req, res, next) => {

//     var sql = `UPDATE patients SET fname = '${req.body.fname}', lname = '${req.body.lname}' WHERE id = '${req.body.id}'`;
//     con.query(sql, function (err, result) {
//         if (err){
//             console.log(err);
//         }
//         console.log(result.affectedRows + " record(s) updated");

//         res.status(201).json({
//             message: 'Patient Name updated successfully'
//         });

//     });
// })

router.put("/chpwd", doctorSession, (req, res, next) => {
  if (typeof req.body?.oldpwd !== "string" || !req.body.oldpwd || Buffer.byteLength(req.body.oldpwd, "utf8") > 72 || !isPasswordValid(req.body.newpwd)) {
    return res.status(400).json({ message: INVALID_PASSWORD_MESSAGE });
  }

  var sql = `SELECT * FROM doctor_details WHERE doctor_id= ?`;
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
            console.log("auth_result: ", auth_result);
            if (!auth_result) {
              res.status(401).json({
                message: "Incorrect Old Password!",
              });
            } else {
              bcrypt
                .hash(req.body.newpwd, 11)
                .then((hash) => {
                  var sql = `UPDATE doctor_details SET hashed_pwd = ? WHERE doctor_id = ?`;
                  con.query(
                    sql,
                    [hash, req.userData.userId],
                    function (err, result) {
                      if (err) {
                        Doctor;
                        console.log(err);
                        res.status(401).json({
                          message: "Updating Doctor Password failed!",
                        });
                      } else {
                        console.log(result);

                        res.status(201).json({
                          message: "Doctor password updated successfully",
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

router.post("/deleteAppointment", calendarAccess(req => req.body.caledarId, ["doctor"]), (req, res, next) => {
  console.log(req.body);
  var docType = "";
  var dateTime = req.body.appmntDate + "|" + req.body.appmntTime;
  con.query(
    `SELECT patient_count FROM doctor_calendar WHERE calendar_id=? AND doctor_id=?`,
    [req.body.caledarId, req.userData.userId],
    function (err, result1) {
      if (err) {
        console.log(err);
        res.status(401).json({
          message: "Adding Appointment schedule failed!",
        });
      } else {
        if (!result1.length) return res.status(404).json({ message: "Resource not found." });
        if (+result1[0].patient_count > 0) {
          res.status(401).json({
            message: `Cannot delete appointment! ${result1[0].patient_count} patient(s) has(have) already booked the appointment.`,
          });
        } else {
          var sql = `DELETE FROM doctor_calendar WHERE calendar_id=? AND doctor_id=? AND patient_count=0`;
          con.query(sql, [req.body.caledarId, req.userData.userId], function (err, result) {
            if (err) {
              console.log(err);
              res.status(401).json({
                message: "Deleting Appointment failed!",
              });
            } else {
              if (!result.affectedRows) return res.status(404).json({ message: "Resource not found." });
              console.log(result);
              res.status(201).json({
                message: "Appointment deleted successfully",
              });
            }
          });
        }
        console.log(
          "Calendar Id booking count from db: ",
          result1[0].patient_count,
        );
        // res.status(201).json({
        //     message: 'Appointment Schedule addeded successfully'
        // });
      }
    },
  );
});

router.get("/medreportlist/:id", doctorPatient(req => req.params.id), (req, res, next) => {
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

router.post("/schedule", doctorSession, (req, res, next) => {
  console.log(req.body);
  var docType = "";
  var dateTime = req.body.appmntDate + "|" + req.body.appmntTime;
  con.query(
    `SELECT doc_type FROM doctor_details WHERE doctor_id=?`,
    [req.userData.userId],
    function (err, result1) {
      if (err) {
        console.log(err);
        res.status(401).json({
          message: "Adding Appointment schedule failed!",
        });
      } else {
        console.log("Doc type from db", result1[0]);
        docType = result1[0].doc_type;
        // res.status(201).json({
        //     message: 'Appointment Schedule addeded successfully'
        // });
        if (req.body.mode == "single" && result1[0].doc_type != "") {
          //run the db query once

          var sql = `INSERT INTO doctor_calendar (doctor_id, doc_type, date, time, max_patients, avg_time_p_ptnt, fees, patient_count) VALUES (?, ?, ?, ?, ?, ?, ?, '0')`;
          con.query(
            sql,
            [
              req.userData.userId,
              result1[0].doc_type,
              req.body.appmntDate,
              req.body.appmntTime,
              req.body.maxPatient,
              req.body.perPatientTime,
              req.body.docFees,
            ],
            function (err, result) {
              if (err) {
                console.log(err);
                res.status(401).json({
                  message: "Adding Appointment schedule failed!",
                });
              } else {
                console.log(result);
                res.status(201).json({
                  message: "Appointment Schedule addeded successfully",
                });
              }
            },
          );
        } else if (req.body.mode == "multiple" && result1[0].doc_type != "") {
          //run a loop to increment the appmntDate by one day and run the db query each time
          aptFromDate = req.body.appmntDate;
          aptToDate = req.body.appmntToDate;
          Date_aptFromDate = new Date(aptFromDate);
          //Date_aptFromDate=Date_aptFromDate.toLocaleDateString("en-GB")
          Date_aptToDate = new Date(aptToDate);
          //Date_aptToDate=Date_aptToDate.toLocaleDateString("en-GB")
          while (Date_aptFromDate <= Date_aptToDate) {
            // day = Date_aptFromDate.getDate();
            // month = Date_aptFromDate.getMonth();
            dateStr = Date_aptFromDate.toLocaleDateString("en-GB")
              .split("/")
              .reverse()
              .join("-");
            console.log("Multiple date string:", dateStr);

            var sql = `INSERT INTO doctor_calendar (doctor_id, doc_type, date, time, max_patients, avg_time_p_ptnt, fees, patient_count) VALUES (?, ?, ?, ?, ?, ?, ?, '0')`;
            con.query(
              sql,
              [
                req.userData.userId,
                result1[0].doc_type,
                dateStr,
                req.body.appmntTime,
                req.body.maxPatient,
                req.body.perPatientTime,
                req.body.docFees,
              ],
              function (err, result) {
                if (err) {
                  console.log(err);
                  res.status(401).json({
                    message: "Adding Appointment schedule failed!",
                  });
                } else {
                  console.log(result);
                  // res.status(201).json({
                  //     message: 'Appointment Schedule addeded successfully'
                  // });
                }
              },
            );
            //Incrementing date by one day
            Date_aptFromDate.setDate(Date_aptFromDate.getDate() + 1);
            // tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
          }
          res.status(201).json({
            message: "Appointments Schedule addeded successfully",
          });
        } else {
          res.status(401).json({
            message: "Illegal value to the mode assigned!",
          });
        }
      }
    },
  );
});

router.post("/signup", (req, res, next) => {
  if (!isPasswordValid(req.body?.password)) {
    return res.status(400).json({ message: INVALID_PASSWORD_MESSAGE });
  }

  if (!emailExpression.test(req.body.email)) {
    return res.status(400).json({ message: "Invalid email address." });
  }
  if (!phoneExpression.test(req.body.mobile_no)) {
    return res.status(400).json({ message: "Mobile number must be 10 digits." });
  }
  con.query(
    `SELECT * FROM doctor_details WHERE email_id = ?`,
    [req.body.email],
    function (err, result) {
      if (err) {
        console.log(err);
        res.status(401).json({
          message: "Adding Doctor failed!",
        });
      } else {
        if (result.length > 0) {
          res.status(401).json({
            message: "Registration could not be completed with these details.",
          });
        } else {
          bcrypt.hash(req.body.password, 11).then((hash) => {
            var sql = `INSERT INTO doctor_details (fname, lname, dob, mstatus, religion, mobile, educational_details, years_exp, registration_no, doc_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
            con.query(
              sql,
              [
                req.body.fname,
                req.body.lname,
                req.body.dob,
                req.body.m_status,
                req.body.religion,
                req.body.mobile_no,
                req.body.edu_details,
                req.body.yrs_exp,
                req.body.reg_no,
                req.body.doc_type,
              ],
              function (err, result) {
                if (err) {
                  console.log(err);
                  res.status(401).json({
                    message: "Adding Patient failed!",
                  });
                } else {
                  var updated_sql = `UPDATE doctor_details SET adhaar= ?, email_id = ?, hashed_pwd = ?, validated = '0' WHERE doctor_id = ?`;

                  con.query(
                    updated_sql,
                    [req.body.adhaar, req.body.email, hash, result.insertId],
                    function (err, result) {
                      if (err) {
                        res.status(401).json({
                          message: "Adding Patient failed!",
                        });
                      } else {
                        console.log(result);
                        res.status(201).json({
                          message: "Patient addeded successfully",
                        });
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
});

router.post("/login", (req, res) => {
  (async () => {
    const identifierKeys = createLoginLockKeys({ identifier: req.body?.email, identifierType: "email" });
    if (await isLoginLocked(con, identifierKeys)) {
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    const result = await new Promise((resolve, reject) => {
      con.query("SELECT * FROM doctor_details WHERE email_id = ?", [req.body?.email], (err, rows) => err ? reject(err) : resolve(rows));
    });
    if (result.length <= 0) {
      await comparePasswordOrDummy(req.body?.password, undefined, 11);
      await recordLoginFailure(con, identifierKeys);
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    const user = result[0];
    const lockKeys = createLoginLockKeys({ identifier: req.body?.email, role: "doctor", accountId: user.doctor_id });
    if (await isLoginLocked(con, lockKeys)) {
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    const eligible = user.validated == 1;
    const authResult = await comparePasswordOrDummy(req.body?.password, eligible ? user.hashed_pwd : undefined, 11);
    if (!eligible || !authResult) {
      await recordLoginFailure(con, lockKeys);
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    if (await isLoginLocked(con, lockKeys)) {
      return res.status(401).json({ message: "Invalid Authentication Credentials!" });
    }
    await clearLoginFailures(con, lockKeys);
    const token = jwt.sign(
      { email: user.email_id, userId: user.doctor_id, role: "doctor" },
      "" + process.env.JWT_SECRET_DOC,
      { expiresIn: "1h" },
    );
    const csrfToken = generateCsrfToken();
    res.cookie("auth_token", token, authCookieOptions());
    res.cookie(CSRF_COOKIE, csrfToken, csrfCookieOptions());
    return res.status(200).json({
      expiresIn: 3600,
      userId: +user.doctor_id,
      userEmail: "" + user.email_id,
      userName: user.fname + " " + user.lname,
    });
  })().catch(error => {
    console.error("Doctor login failed safely:", error);
    if (!res.headersSent) res.status(503).json({ message: "Unable to authenticate right now." });
  });
});

router.post("/createMeeting", doctorSession, function (req, res, next) {
  console.log("Doc Email:", req.body.docEmail);
  // console.log("id:", req.body.id);
  var responseData;
  console.log("topic:", "req.body.topic");

  const payload = {
    iss: process.env.ZOOM_API_KEY,
    exp: new Date().getTime() + 5000,
  };

  const token = jwt.sign(payload, process.env.ZOOM_API_SECRET);
  //zoomUserId = 'wizztechweb@gmail.com'; // this user will later be the email id of the doctor|| but before that admin have to create a user with the doctors email id
  // let options = {
  //     headers: {'User-Agent': 'Zoom-api-Jwt-Request', 'Content-Type': 'application/json', 'Authorization' : 'Bearer '+token}
  // };
  // zoomUserId = `${process.env.ZOOM_USER_ID}`;
  // axios.post(`https://api.zoom.us/v2/users/${zoomUserId}/meetings`, {
  //     "topic": "AIMS2Health Video Consultation"
  //   }, options)
  //   .then((response) => {
  //     console.log(response);
  //     console.log("Join URL:" , response.data.join_url);
  //     console.log("Start URL: ", response.data.start_url);
  //     res.status(200).json({
  //         message: 'Meeting Created Successfully',
  //         join_url: response.data.join_url,
  //         start_url: response.data.start_url
  //     });
  //   }, (error) => {
  //     console.log(error);
  //     res.status(401).json({
  //         message: 'Cannot Create Meeting!'
  //     });
  //   }).catch(err => {
  //       console.log(err);
  //   });
  //new way of creating meeting
  // zoomUserId = `${process.env.ZOOM_USER_ID}`;
  // var options = {
  //     method: "POST",
  //     uri: "https://api.zoom.us/v2/users/" + zoomUserId + "/meetings",
  //     body: {
  //       topic: "AIMS2Health Video Consultation", //meeting title
  //       type: 1,
  //       settings: {
  //         host_video: "true",
  //         participant_video: "true",
  //       },
  //     },
  //     auth: {
  //       bearer: token,
  //     },
  //     headers: {
  //       "User-Agent": "Zoom-api-Jwt-Request",
  //       "content-type": "application/json",
  //     },
  //     json: true, //Parse the JSON string in the response
  // };
  //   requestPromise(options)
  //     .then(function (response) {
  //       console.log("response is: ", response);
  //       console.log(response);
  //       console.log("Join URL:" , response.join_url);
  //       console.log("Start URL: ", response.start_url);
  //       res.status(200).json({
  //           message: 'Meeting Created Successfully',
  //           join_url: response.join_url,
  //           start_url: response.start_url
  //       });
  //       //res.send("create meeting result: " + JSON.stringify(response));
  //     })
  //     .catch(function (err) {
  //       // API call failed...
  //       console.log("API call failed, reason ", err);
  //       res.status(401).json({
  //         message: 'Cannot Create Meeting!'
  //       });
  //     });
  //way to create the Zoom API token using outh server to server
  const response = axios({
    url: `https://zoom.us/oauth/token?grant_type=account_credentials&account_id=${process.env.ZOOM_AC_ID}`,
    method: "post",
    data: "grant_type=client_credentials",
    auth: {
      username: process.env.ZOOM_OAUTH_CLIENT_ID,
      password: process.env.ZOOM_OAUTH_CLIENT_SECRET,
    },
  }).then(function (response) {
    let access_token = response.data.access_token;
    //new way of creating meeting
    zoomUserId = `${process.env.ZOOM_USER_ID}`;
    axios
      .post(
        "https://api.zoom.us/v2/users/" + zoomUserId + "/meetings",
        {
          topic: "Tele Cure Video Consultation", //meeting title
          type: 1,
          settings: {
            host_video: true,
            participant_video: true,
          },
        },
        {
          headers: {
            Authorization: `Bearer ${access_token}`,
            "User-Agent": "Zoom-api-Jwt-Request",
            "content-type": "application/json",
          },
        },
      )
      .then(function (response) {
        console.log("Join URL:", response.data.join_url);
        console.log("Start URL: ", response.data.start_url);
        res.status(200).json({
          message: "Meeting Created Successfully",
          join_url: response.data.join_url,
          start_url: response.data.start_url,
        });
      })
      .catch(function (err) {
        // API call failed...
        console.log("API call failed, reason ", err);
        res.status(401).json({
          message: "Cannot Create Meeting!",
        });
      });
  });
});
router.post("/sendSmsLink", doctorAppointment, async function (req, res, next) {
  console.log("Request body:", req.body);
  const {
    emailId,
    meetingJoinUrl,
    phoneNumber,
    countryCode,
    username = "Patient",
    appointmentId,
  } = { ...req.body, emailId: req.authorizedPatient.email_id, phoneNumber: req.authorizedPatient.mobile_no, countryCode: req.authorizedPatient.countryCode };
  // Common variables
  const whatsappNumber = `${countryCode}${phoneNumber}`; // e.g., 916394965974 (without +)
  try {
    // 1. Send Email via ZeptoMail — services.netxcell.com:8081 (the
    // previous provider) is unreachable. VAPT L1 Finding 15 / L2 Finding
    // 18, "Broken Functionality".
    await zeptomail.sendMail({
      to: emailId,
      toName: username || "Patient",
      subject: "Aims2health Appointment",
      html: `<p>Dear ${username},</p><p>Your AIMS2Health Video-Consultation link is: <a href="${meetingJoinUrl}">${meetingJoinUrl}</a></p><p>Kindly join the meeting within 3 minutes.</p><p>Appointment Request No: ${appointmentId}</p><p>Thank you,<br>AIMS2Health Team</p>`,
    });
    console.log("Video-consultation link email sent successfully");
    // 2. Send WhatsApp via Converge API
    const whatsappPayload = {
      messaging_product: "whatsapp",
      to: whatsappNumber,
      recipient_type: "individual",
      type: "template",
      template: {
        namespace: "264eb977_11b5_4bde_af0f_c2869b76016d",
        name: "aims2health_appointment_link",
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
                text: meetingJoinUrl, // This will be injected into {{text1}} in the template
              },
            ],
          },
        ],
      },
    };
    const whatsappResponse = await needle(
      "post",
      "https://convergenow.ai/whatsapp-api/messaging_api/?client_id=917439937931",
      JSON.stringify(whatsappPayload),
      { headers: { "Content-Type": "application/json" } },
    );

    if (
      whatsappResponse.statusCode !== 200 &&
      whatsappResponse.statusCode !== 201
    ) {
      throw new Error(
        `WhatsApp API failed with status: ${whatsappResponse.statusCode}`,
      );
    }
    console.log("WhatsApp message sent successfully:", whatsappResponse.body);

    // Both succeeded
    res.status(200).json({
      message: "Meeting link sent successfully via Email and WhatsApp",
    });
  } catch (error) {
    console.error("Error sending messages:", error.message || error);
    res.status(500).json({
      message: "Failed to send meeting link via Email or WhatsApp",
      error: error.message,
    });
  }
});

router.get(
  "/listdoctorspayments/:doctorId",
  doctorSession,
  function (req, res, next) {
    // console.log("id:", req.body.id);
    var responseData;
    // console.log("Reguest body param:", req.params.doctorId);

    //    var sql = `SELECT doctor_id, email_id, fname, lname, dob, mobile, educational_details, years_exp, registration_no, doc_type, ehr_id, validated FROM doctor_details`;
    var sql = `SELECT * FROM doctor_calendar WHERE (doctor_id=? AND patient_count>0 AND date < CURDATE()) ORDER BY calendar_id DESC`;

    con.query(sql, [req.userData.userId], function (err, result) {
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
  },
);

router.post("/updateAppointmentState", doctorAppointment, function (req, res, next) {
  var sql = `SELECT status FROM appointments WHERE appointment_id = ? AND calendar_id IN (SELECT calendar_id FROM doctor_calendar WHERE doctor_id = ?)`;

  con.query(sql, [req.body.appointmentId, req.userData.userId], function (err, result) {
    if (err) {
      console.log("Error:", err);
      res.status(401).json({
        message: "Cannot find the appointment Id!",
      });
    } else {
      let updatedStatus;
      if (!result.length) return res.status(404).json({ message: "Resource not found." });
      if (result[0].status == 0) {
        updatedStatus = 1;
      } else {
        updatedStatus = 0;
      }

      var sqlUpdated = `UPDATE appointments SET status = ? WHERE appointment_id =? AND calendar_id IN (SELECT calendar_id FROM doctor_calendar WHERE doctor_id = ?)`;

      con.query(
        sqlUpdated,
        [updatedStatus, req.body.appointmentId, req.userData.userId],
        function (err, result) {
          if (err) {
            //console.log("EHR Error:", err);
            res.status(401).json({
              message: "Updating Appointment status failed!",
            });
          } else {
            if (!result.affectedRows) return res.status(404).json({ message: "Resource not found." });
            console.log(result);
            res.status(201).json({
              message: "Appointment status updated!",
            });
          }
        },
      );
    }
  });
});

router.post("/sendVSData", doctorPatient(req => req.body.patientId), function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  console.log("topic:", req.body);

  var get_patient_ehr_id = `SELECT ehr_id FROM patient_details WHERE patient_id = ?`;
  var get_doc_ehr_id = `SELECT ehr_id FROM doctor_details WHERE doctor_id = ?`;

  con.query(get_doc_ehr_id, [req.userData.userId], function (err, result) {
    if (err) {
      console.log("Error:", err);
      res.status(401).json({
        message: "Getting doc ehr id from local failed!",
      });
    } else {
      if (result[0].ehr_id == "-1") {
        res.status(201).json({
          message: "vs_logins data addeded successfully to EHR",
        });
      } else {
        var doc_ehr_id = result[0].ehr_id;
        con.query(
          get_patient_ehr_id,
          [req.body.patientId],
          function (err, result) {
            if (err) {
              console.log("Error:", err);
              res.status(401).json({
                message: "Getting patient ehr id from local failed!",
              });
            } else {
              var p_ehr_id = result[0].ehr_id;
              console.log(
                "patient ehr id: " +
                  p_ehr_id +
                  " ; doctor ehr id: " +
                  doc_ehr_id,
              );

              var casesheet_sql = `INSERT INTO vs_logins (doc_num, admno) VALUES (?, ?)`;
              if (process.env.EHR_CONNECT == "true") {
                con_ehr.query(
                  casesheet_sql,
                  [doc_ehr_id, p_ehr_id],
                  function (err, result) {
                    if (err) {
                      console.log("EHR Error:", err);
                      res.status(401).json({
                        message: "Adding data to vs_logins in EHR failed!",
                      });
                    } else {
                      console.log("vs_logins data Updated in EHR");
                      console.log(result);
                      res.status(201).json({
                        message: "vs_logins data addeded successfully to EHR",
                      });
                    }
                  },
                );
              }
            }
          },
        );
      }
    }
  });
});

router.post(
  "/uploadprescription",
  doctorSession,
  multer({ storage: storage }).single("image"),
  doctorConsultation,
  (req, res, next) => {
    console.log(req.body);

    const baseUrl =
      process.env.PUBLIC_URL ||
      process.env.BACKEND_PROTOCOL_PROD + "://" + req.get("host");

    // ✅ handle null for file
    const imagePath = req.file
      ? baseUrl + "/images/" + req.file.filename
      : null;

    const creator = req.userData.userId;
    console.log("image path: ", imagePath);

    const post = {
      title: req.body.title ?? null,
      content: req.body.content ?? null,
      imagePath: imagePath,
      creator: req.userData.userId,
    };

    var sql = `INSERT INTO prescriptions (patient_id, calendar_id, report_title, content, filePath) SELECT ?, ?, ?, ?, ? FROM appointments a JOIN doctor_calendar dc ON dc.calendar_id = a.calendar_id WHERE a.patient_id = ? AND a.calendar_id = ? AND dc.doctor_id = ? LIMIT 1`;

    con.query(
      sql,
      [
        req.body.patientId ?? null,
        req.body.calendarId ?? null,
        req.body.title ?? null,
        req.body.content ?? null,
        imagePath,
        req.body.patientId,
        req.body.calendarId,
        req.userData.userId,
      ],
      function (err, result) {
        if (err) {
          console.log(err);
          res.status(500).json({
            message: "Adding A Medical Record Failed!",
          });
        } else if (!result.affectedRows) {
          if (req.file) fs.unlink(req.file.path, () => {});
          return res.status(404).json({ message: "Resource not found." });
        } else {
          res.status(201).json({
            message: "Medical Record addeded successfully",
            post: result,
          });
        }
      },
    );
  },
);

router.post("/listprescriptions", doctorConsultation, function (req, res, next) {
  // console.log(req.body);
  // console.log("id:", req.body.id);
  var responseData;
  console.log("Get Prescription body:", req.body);

  var sql = `SELECT * FROM prescriptions WHERE patient_id= ? AND calendar_id= ?`;
  con.query(
    sql,
    [req.body.patientId, req.body.calendarId],
    function (err, result) {
      if (err) {
        console.log(err);
        res.status(500).json({
          message: "Adding A Medical Record Failed!",
        });
      } else {
        console.log("Prescriptions:", result);
        res.status(201).json({
          message: "Received Prescriptions successfully",
          post: result,
        });
      }
      console.log("Prescriptions:", result);
    },
  );
});

router.post("/forgetpwd", (req, res, next) => {
  //var sql = `SELECT * FROM patient_details WHERE email_id= '${req.body.email}'`;
  var sql = `SELECT * FROM doctor_details WHERE email_id= ?`;

  //console.log(req.body)
  con.query(sql, [req.body.email], function (err, result, fields) {
    if (err) {
      res.status(500).json({ message: "Unable to process the password recovery request." });
    } else {
      if (result.length <= 0) {
        res.status(200).json({
          message: "If the account is eligible, password reset instructions will be sent.",
        });
      } else {
        const secret =
          "" +
          process.env.JWT_SECRET_DOC +
          result[0].email_id +
          result[0].hashed_pwd;

        const token = jwt.sign(
          {
            email: result[0].email_id,
            userId: result[0].doctor_id,
          },
          secret,
          { expiresIn: "10m" },
        );

        const link = `${process.env.FRONTEND_URL}/dresetpwd/${result[0].doctor_id}/${token}`;

        const msg = {
          to: result[0].email_id, // Change to your recipient
          from: process.env.SENDGRID_FROM_ADDRESS, // Change to your verified sender
          subject: "Virtual Sathi Login Password Reset",
          text: `Dear Doctor! Your Virtual Sathi login password reset link is ${link} , this link will be valid for only 10mins.`,
          html: `Dear Doctor! Your Virtual Sathi login password reset link is ${link} , this link will be valid for only 10mins.`,
        };

        sgMail
          .send(msg)
          .then(() => {
            console.log(
              "Email sent for password reset for Doctor-id:",
              result[0].doctor_id,
            );
            res.status(200).json({
              message: "If the account is eligible, password reset instructions will be sent.",
            });
          })
          .catch((error) => {
            console.error("Doctor password reset delivery failed.");
            res.status(200).json({
              message: "If the account is eligible, password reset instructions will be sent.",
            });
          });

        //res.status(200).json(result[0].email);
      }
    }
  });
});

router.post("/forgetpwdresetpwd", (req, res, next) => {
  if (!isPasswordValid(req.body?.password)) {
    return res.status(400).json({ message: INVALID_PASSWORD_MESSAGE });
  }
  //var sql = `SELECT * FROM patient_details WHERE email_id= '${req.body.email}'`;
  var sql = `SELECT * FROM doctor_details WHERE doctor_id= ?`;

  //console.log(req.body)
  con.query(sql, [req.body.doc_id], function (err, result, fields) {
    if (err) {
      res.status(401).json({
        message: "Invalid or expired reset link.",
      });
    } else {
      if (result.length <= 0) {
        res.status(401).json({
          message: "Invalid or expired reset link.",
        });
      } else {
        const secret =
          "" +
          process.env.JWT_SECRET_DOC +
          result[0].email_id +
          result[0].hashed_pwd;

        try {
          const payload = jwt.verify(req.body.token, secret);

          bcrypt
            .hash("" + req.body.password, 11)
            .then((hash) => {
              if (hash == result[0].hashed_pwd) {
                res.status(401).json({
                  message:
                    "The old password and the new password cannot be the same!",
                });
              } else {
                var sql = `UPDATE doctor_details SET hashed_pwd = ? WHERE doctor_id = ?`;
                con.query(sql, [hash, req.body.doc_id], function (err, result) {
                  if (err) {
                    console.log(err);
                    res.status(401).json({
                      message: "Updating Doctor Password failed!",
                    });
                  } else {
                    console.log(result);

                    res.status(201).json({
                      message: "Doctor password updated successfully",
                    });
                  }
                });
              }
            })
            .catch((err) => {
              res.status(401).json({
                message: "Invalid or expired reset link.",
              });
            });
        } catch (error) {
          res.status(401).json({
            message: "Invalid or expired reset link.",
          });
        }

        //res.status(200).json(result[0].email);
      }
    }
  });
});

// router.delete('/:id', (req, res, next) =>{
//     console.log(req.params.id);

//     var sql = `DELETE FROM patient WHERE doctor_id = '${req.params.id}'`;
//     con.query(sql, function (err, result) {
//         if (err){
//             console.log(err)
//         }
//         console.log("Number of records deleted: " + result.affectedRows);
//         res.status(200).json({message: 'Patient deleted!'});
//     });

// })

const { blacklistToken } = require("../middleware/token-blacklist");
router.post("/logout", doctorSession, (req, res) => {
  blacklistToken(req.userData.token);
  res.clearCookie("auth_token", clearCookieOptions());
  res.clearCookie(CSRF_COOKIE, csrfClearCookieOptions());
  res.status(200).json({ message: "Logged out successfully." });
});

module.exports = router;
