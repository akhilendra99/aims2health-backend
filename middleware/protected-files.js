const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const createAuthorization = require('../utils/authorization');

// Check database references before serving bytes, including HEAD and ranges.
module.exports = function protectedFiles() {
  const pool = mysql.createPool({
    host: process.env.DBHOST, user: process.env.DBUSER,
    password: process.env.DBPWD, database: process.env.DBNAME,
  }).promise();
  const access = createAuthorization(async (sql, values) => (await pool.query(sql, values))[0]);
  const router = express.Router();
  router.use(access.guard(['patient', 'helper', 'doctor', 'admin']));
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    if (!['GET', 'HEAD'].includes(req.method)) return res.status(405).json({ message: 'Method not allowed.' });
    next();
  });
  router.get('/:filename', access.guard(['patient', 'helper', 'doctor', 'admin'], (req, auth) => {
    const name = req.params.filename;
    return !/[\\/\x00]/.test(name) && !name.startsWith('.') && auth.file(req.userData, name);
  }), (req, res, next) => {
    res.sendFile(req.params.filename, { root: path.join(__dirname, '..', 'images'), dotfiles: 'deny', cacheControl: false }, err => {
      if (!err) return;
      if (res.headersSent) return next(err);
      res.status(err.status === 404 ? 404 : 500).json({ message: 'File unavailable.' });
    });
  });
  router.use((req, res) => res.status(404).json({ message: 'Resource not found.' }));
  return router;
};
