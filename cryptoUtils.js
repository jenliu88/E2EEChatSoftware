const crypto = require('crypto');

function ECDHkeyPair() {
  //ECDH key pair using prime256v1 curve
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}
//AES key(128 bit) from shared secret
function AESKey(sharedSecret) {
  const hash = crypto.createHash('sha256').update(sharedSecret).digest();
  return hash.slice(0, 16);
}
//encrypt messages using AES-GCM
function encryptMessage(message, key) {
  const iv = crypto.randomBytes(12); 
  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  //combine iv + encrypted + tag
  const combined = Buffer.concat([iv, encrypted, tag]);

  return combined.toString('base64');
}

function decryptMessage(encryptedBase64, key) {
  const data = Buffer.from(encryptedBase64, 'base64');

  //iv(first 12), tag (last 16), encrypted(middle)
  const iv = data.slice(0, 12);
  const tag = data.slice(data.length - 16);
  const encrypted = data.slice(12, data.length - 16);

  //decipher using AES-GCM
  const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  //auth tag
  decipher.setAuthTag(tag); 

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

function decodePublicKey(base64Key) {
  return Buffer.from(base64Key, 'base64');
}

module.exports = {
  ECDHkeyPair,
  AESKey,
  encryptMessage,
  decryptMessage,
  decodePublicKey
};