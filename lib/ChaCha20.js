'use strict';

const sodium = require('sodium').api,
      crypto = require('crypto');

class ChaCha20 {
  
  constructor() {
    
  }

  static encrypt(...args) {
    let plain, encoding, nonce, key;
    
    switch (args.length) {
      case 4:
        plain = args[0];
        encoding = args[1];
        nonce = args[2];
        key = args[3];
        break;
      case 3:
        plain = args[0];
        encoding = 'utf8';
        nonce = args[1];
        key = args[2];
        break;
      default:
        return undefined;
    }

    let type = typeof plain,
        isBuffer = plain instanceof Buffer;
    
    if (!isBuffer) {
      plain = type === 'object' || Array.isArray(plain)
        ? JSON.stringify(plain)
        : plain;

      plain = new Buffer(plain, encoding);
    }
    
    return sodium.crypto_aead_chacha20poly1305_encrypt(plain, null, nonce, key);
  }
  
  static decrypt(...args) {
    let cipher, encoding, nonce, key;
    
    switch (args.length) {
      case 4:
        cipher = args[0];
        encoding = args[1];
        nonce = args[2];
        key = args[3];
        break;
      case 3:
        cipher = args[0];
        encoding = 'base64';
        nonce = args[1];
        key = args[2];
        break;
      default:
        return undefined;
    }

    let isBuffer = cipher instanceof Buffer;

    cipher = !isBuffer
      ? new Buffer(cipher, encoding)
      : cipher;

    let decrypted = sodium.crypto_aead_chacha20poly1305_decrypt(cipher, null, nonce, key);

    let isJSON = false,
        parsed = null;
    try {
      parsed = JSON.parse(decrypted);
      isJSON = true;
    } catch (e) {}

    return (isJSON && parsed) ? parsed : decrypted;
  }

  static getNonce() {
    let nonce = new Buffer(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
    sodium.randombytes(nonce);
    return nonce;
  }

  static getNonceIncrement(...args) {
    let nonce, encoding;

    switch (args.length) {
      case 2:
        nonce = args[0];
        encoding = args[1];
        break;
      case 1:
        nonce = args[0];
        encoding = 'base64';
        break;
      default:
        return undefined;
    }

    let isBuffer = nonce instanceof Buffer;

    nonce = !isBuffer
      ? new Buffer(nonce, encoding)
      : nonce;

    sodium.increment(nonce);

    return nonce;
  }
  
  static getKey(...args) {
    let secret, encoding, salt;

    switch (args.length) {
      case 3:
        secret = args[0];
        encoding = args[1];
        salt = args[2];
        break;
      case 2:
        secret = args[0];
        encoding = 'base64';
        salt = args[1];
        break;
      case 1:
        secret = args[0];
        encoding = 'base64';
        salt = new Buffer(0);
        break;
      default:
        secret = new Buffer(sodium.crypto_aead_chacha20poly1305_KEYBYTES);
        salt = new Buffer(sodium.crypto_aead_chacha20poly1305_KEYBYTES);
        sodium.randombytes(secret);
        sodium.randombytes(salt);
        break;
    }

    let isBuffer = secret instanceof Buffer;

    secret = !isBuffer
      ? new Buffer(secret, encoding)
      : secret;
    
    return crypto.pbkdf2Sync(secret, salt, 100, sodium.crypto_aead_chacha20poly1305_KEYBYTES, 'sha512');
  }
}

module.exports = ChaCha20;