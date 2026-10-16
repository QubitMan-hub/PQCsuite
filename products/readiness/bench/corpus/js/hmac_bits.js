const crypto = require("crypto");

function sign(bits, secret, data) {
  return crypto.createHmac("sha" + bits, secret).update(data).digest("base64");
}

module.exports = { sign };
