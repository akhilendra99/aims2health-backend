const jwt = require('jsonwebtoken');
const { isBlacklisted } = require('./token-blacklist');

const secrets = { patient: 'JWT_SECRET_PATIENT', helper: 'JWT_SECRET_PATIENT', doctor: 'JWT_SECRET_DOC', admin: 'JWT_SECRET_ADMIN' };
const validId = value => ['string', 'number'].includes(typeof value) && /^(?:[1-9]\d*)$/.test(String(value)) && Number.isSafeInteger(Number(value));

// Keep legacy sessions valid, but distinguish helper_id from userId. Roles
// come from the verified token and its signing domain, never request fields.
function authenticate(roles, { cookieOnly = false } = {}) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    const token = cookieOnly
      ? req.cookies?.auth_token
      : header && header.startsWith('Bearer ')
        ? header.slice(7)
        : req.cookies?.auth_token;
    if (!token || isBlacklisted(token)) return res.status(401).json({ message: 'You are not authenticated!' });
    const configured = ['patient', 'doctor', 'admin'].map(role => process.env[secrets[role]]);
    if (configured.some(secret => !secret) || new Set(configured).size !== configured.length) {
      return res.status(500).json({ message: 'Authentication signing domains are misconfigured.' });
    }
    let authenticated = false;
    for (const role of ['patient', 'helper', 'doctor', 'admin']) {
      try {
        const claims = jwt.verify(token, process.env[secrets[role]], { algorithms: ['HS256'] });
        if (claims.userId !== undefined && claims.helper_id !== undefined) continue;
        const helper = validId(claims.helper_id) && claims.userId === undefined;
        if ((role === 'helper') !== helper || !validId(helper ? claims.helper_id : claims.userId)) continue;
        if (claims.role && claims.role !== role) continue;
        authenticated = true;
        if (!roles.includes(role)) continue;
        req.userData = { userId: helper ? claims.helper_id : claims.userId, email: helper ? claims.email_id : claims.email, role, token };
        return next();
      } catch { /* Try the next existing signing domain. */ }
    }
    return res.status(authenticated ? 403 : 401).json({ message: authenticated ? 'Forbidden.' : 'You are not authenticated!' });
  };
}
module.exports = authenticate;
module.exports.cookieOnly = roles => authenticate(roles, { cookieOnly: true });
module.exports.validId = validId;
