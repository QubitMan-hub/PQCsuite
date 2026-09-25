const sjcl = require("sjcl");

function seal(password, salt, plaintext) {
  const key = sjcl.misc.pbkdf2(password, salt, 100000, 256);
  const prp = new sjcl.cipher.aes(key);
  return sjcl.codec.hex.fromBits(prp.encrypt(sjcl.codec.utf8String.toBits(plaintext).slice(0, 4)));
}

module.exports = { seal };
