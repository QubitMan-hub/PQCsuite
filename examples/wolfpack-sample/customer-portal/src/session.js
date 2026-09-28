const crypto = require("crypto");

function sealCookie(key, value) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([iv, c.update(value), c.final(), c.getAuthTag()]).toString("base64url");
}

function avatarKey(email) {
  return crypto.createHash("md5").update(email.trim().toLowerCase()).digest("hex");
}

module.exports = { sealCookie, avatarKey };
