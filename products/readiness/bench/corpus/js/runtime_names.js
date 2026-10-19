const crypto = require('crypto');

function signer(bits) {
  return crypto.createSign('RSA-SHA' + bits);
}

function digest(bits, data) {
  return crypto.createHash('sha' + bits).update(data).digest('hex');
}

module.exports = { signer, digest };
