const axios = require("axios");

// ZeptoMail transactional email — replaces the unreachable netxcell email
// API (VAPT L2 Finding 18 / L1 Finding 15, "Broken Functionality").
// Docs: https://www.zoho.com/zeptomail/help/api/email-sending.html
async function sendMail({ to, toName, subject, text, html }) {
  const payload = {
    from: {
      address: process.env.ZEPTOMAIL_FROM_ADDRESS,
      name: process.env.ZEPTOMAIL_FROM_NAME || "Aims2health",
    },
    to: [
      {
        email_address: {
          address: to,
          name: toName || "User",
        },
      },
    ],
    subject,
    htmlbody: html || `<pre>${text}</pre>`,
  };
  if (text) {
    payload.textbody = text;
  }

  // ZeptoMail's dashboard copy-paste value sometimes already includes the
  // "Zoho-enczapikey " scheme prefix and sometimes doesn't, depending on
  // where it's copied from -- handle both so a credential rotation can't
  // silently double up the prefix and break auth.
  const rawToken = process.env.ZEPTOMAIL_TOKEN || "";
  const authHeader = rawToken.startsWith("Zoho-enczapikey ")
    ? rawToken
    : `Zoho-enczapikey ${rawToken}`;

  return axios.post(process.env.ZEPTOMAIL_API_URL, payload, {
    headers: {
      Authorization: authHeader,
      "Content-Type": "application/json",
    },
    timeout: 10000,
  });
}

module.exports = { sendMail };
