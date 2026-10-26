// Shared SELECT * responses must never serialize authentication or bank data.
const privateFields = new Set(['hashed_pwd', 'password', 'bank_ifsc', 'bank_ac_no', 'bank_ac_name']);
module.exports = function publicRecord(record) {
  return Object.fromEntries(Object.entries(record).filter(([key]) => !privateFields.has(key)));
};
