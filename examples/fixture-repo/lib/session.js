const crypto = require("crypto");

// Signs session payloads for the "remember me" cookie.
function signToken(payload) {
  return crypto.createHash("md5").update(JSON.stringify(payload)).digest("hex");
}

module.exports = { signToken };
