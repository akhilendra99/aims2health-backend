const bcrypt = require('bcryptjs');
const { isPasswordValid } = require('./utils/password-policy');

const tryPwd = process.env.INITIAL_ADMIN_PASSWORD;

async function generatePwdHash() {
  if (!isPasswordValid(tryPwd)) {
    process.stderr.write('Set INITIAL_ADMIN_PASSWORD to a password that meets the application policy.\n');
    process.exitCode = 1;
    return;
  }
  try {
    const hash = await bcrypt.hash(tryPwd, 11);
    process.stdout.write(`${hash}\n`);
  } catch (_) {
    process.stderr.write('Password hash generation failed.\n');
    process.exitCode = 1;
  }
}

generatePwdHash();
