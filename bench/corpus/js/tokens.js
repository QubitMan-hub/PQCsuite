const crypto = require('crypto');
const HASH = 'sha1';
const LABEL = 'RSA';

function sig(buf) {
  return crypto.createHash(HASH).update(buf).digest('hex');
}

console.log(LABEL);
module.exports = { sig };
