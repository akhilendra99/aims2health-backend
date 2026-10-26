const authenticate = require('../middleware/authenticate');
const fs = require('fs');
const { validId } = authenticate;

// All identifiers are values, never SQL fragments from the client. This layer
// is shared by callback connections and promise pools via an injected query.
function createAuthorization(query) {
  async function identity(user) {
    const tables = { patient: ['patient_details', 'patient_id'], helper: ['helper_details', 'helper_id'], doctor: ['doctor_details', 'doctor_id'], admin: ['admin_details', 'admin_id'] };
    if (!tables[user.role] || !validId(user.userId)) return false;
    const [table, key] = tables[user.role];
    const rows = await query(`SELECT ${key} FROM ${table} WHERE ${key} = ? AND email_id <=> ?${user.role === 'doctor' ? ' AND validated = 1' : ''} LIMIT 1`, [user.userId, user.email ?? null]);
    return rows.length > 0;
  }
  function patientScope(user, alias = 'pd') {
    if (user.role === 'admin') return { sql: '1 = 1', values: [] };
    if (user.role === 'patient') return { sql: `(${alias}.patient_id = ? OR (${alias}.parent_id = ? AND (${alias}.helper_id IS NULL OR ${alias}.helper_id = -1)))`, values: [user.userId, user.userId] };
    if (user.role === 'helper') return { sql: `${alias}.helper_id = ?`, values: [user.userId] };
    if (user.role === 'doctor') return { sql: `EXISTS (SELECT 1 FROM appointments az JOIN doctor_calendar dz ON dz.calendar_id = az.calendar_id WHERE az.patient_id = ${alias}.patient_id AND dz.doctor_id = ?)`, values: [user.userId] };
    return { sql: '1 = 0', values: [] };
  }
  async function patient(user, id) {
    if (!validId(id)) return false;
    const scope = patientScope(user);
    const rows = await query(`SELECT pd.patient_id, pd.email_id, pd.mobile_no, pd.countryCode FROM patient_details pd WHERE pd.patient_id = ? AND ${scope.sql} LIMIT 1`, [id, ...scope.values]);
    return rows[0] || false;
  }
  async function calendar(user, id) {
    if (!validId(id)) return false;
    const rows = await query(`SELECT calendar_id FROM doctor_calendar WHERE calendar_id = ?${user.role === 'admin' ? '' : ' AND doctor_id = ?'} LIMIT 1`, user.role === 'admin' ? [id] : [id, user.userId]);
    return rows.length > 0;
  }
  async function appointment(user, id) {
    if (!validId(id)) return false;
    const rows = await query('SELECT a.patient_id, pd.email_id, pd.mobile_no, pd.countryCode FROM appointments a JOIN doctor_calendar dc ON dc.calendar_id = a.calendar_id JOIN patient_details pd ON pd.patient_id = a.patient_id WHERE a.appointment_id = ? AND dc.doctor_id = ? LIMIT 1', [id, user.userId]);
    return rows[0] || false;
  }
  async function consultation(user, patientId, calendarId) {
    if (!validId(patientId) || !validId(calendarId)) return false;
    const rows = await query('SELECT a.appointment_id FROM appointments a JOIN doctor_calendar dc ON dc.calendar_id = a.calendar_id WHERE a.patient_id = ? AND a.calendar_id = ? AND dc.doctor_id = ? LIMIT 1', [patientId, calendarId, user.userId]);
    return rows.length > 0;
  }
  async function report(user, id, patientId) {
    if (!validId(id) || (patientId !== undefined && !validId(patientId))) return false;
    const scope = patientScope(user);
    const rows = await query(`SELECT r.patient_id, r.imagePath, r.mediaType, r.mediaSize FROM patient_med_reports r JOIN patient_details pd ON pd.patient_id = r.patient_id WHERE r.report_id = ? AND ${scope.sql}${patientId === undefined ? '' : ' AND r.patient_id = ?'} LIMIT 1`, [id, ...scope.values, ...(patientId === undefined ? [] : [patientId])]);
    return rows[0] || false;
  }
  async function file(user, filename) {
    const scope = patientScope(user);
    const reports = await query(`SELECT r.report_id AS id FROM patient_med_reports r JOIN patient_details pd ON pd.patient_id = r.patient_id WHERE SUBSTRING_INDEX(r.imagePath, '/', -1) = ? AND ${scope.sql} LIMIT 1`, [filename, ...scope.values]);
    if (reports.length) return true;
    const prescriptions = await query(`SELECT p.patient_id AS id FROM prescriptions p JOIN patient_details pd ON pd.patient_id = p.patient_id JOIN doctor_calendar dc ON dc.calendar_id = p.calendar_id WHERE SUBSTRING_INDEX(p.filePath, '/', -1) = ? AND ${user.role === 'doctor' ? 'dc.doctor_id = ?' : scope.sql} LIMIT 1`, [filename, ...(user.role === 'doctor' ? [user.userId] : scope.values)]);
    if (prescriptions.length) return true;
    // The patient booking screen links approved doctors' published biodata.
    // This catalog reference grants access to that file, not patient records.
    const catalogViewer = ['patient', 'helper'].includes(user.role);
    if (!catalogViewer && !['doctor', 'admin'].includes(user.role)) return false;
    const bio = await query(`SELECT da.doctor_id FROM doctor_additional da JOIN doctor_details dd ON dd.doctor_id = da.doctor_id WHERE SUBSTRING_INDEX(da.bio_data_url, '/', -1) = ?${catalogViewer ? ' AND dd.validated = 1' : user.role === 'admin' ? '' : ' AND da.doctor_id = ?'} LIMIT 1`, catalogViewer || user.role === 'admin' ? [filename] : [filename, user.userId]);
    return bio.length > 0;
  }
  function guard(roles, policy) {
    const auth = authenticate(roles);
    return (req, res, next) => auth(req, res, async () => {
      const discardUpload = () => { if (req.file?.path) fs.unlink(req.file.path, () => {}); };
      try {
        if (!await identity(req.userData)) {
          discardUpload();
          return res.status(401).json({ message: 'Session account is no longer valid.' });
        }
        if (policy && !await policy(req, api)) {
          discardUpload();
          return res.status(404).json({ message: 'Resource not found.' });
        }
        next();
      } catch (err) {
        discardUpload();
        console.error('Authorization lookup failed:', err.code || err.message);
        return res.status(500).json({ message: 'Unable to authorize request.' });
      }
    });
  }
  const api = { identity, patientScope, patient, calendar, appointment, consultation, report, file, guard };
  return api;
}
module.exports = createAuthorization;
