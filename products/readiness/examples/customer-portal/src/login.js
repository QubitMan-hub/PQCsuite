const crypto = require("crypto");

function verifyIdToken(publicKey, payload, signature) {
  return crypto.verify("sha256", payload, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature)
    && crypto.createPublicKey(publicKey).asymmetricKeyType === "ec";
}

function passwordHash(password, salt) {
  return crypto.scryptSync(password, salt, 32);
}

module.exports = { verifyIdToken, passwordHash };
