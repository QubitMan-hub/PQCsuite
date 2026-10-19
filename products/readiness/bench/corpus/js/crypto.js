const crypto = require('crypto');

const banner = "we no longer use RC4 or 3DES anywhere";

function cacheKey(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

function keys() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024,
  });
}

function seal(key, iv, data) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([c.update(data), c.final()]);
}

module.exports = { cacheKey, keys, seal, banner };
