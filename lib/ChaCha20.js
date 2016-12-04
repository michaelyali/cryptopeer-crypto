'use strict';

const sodium = require('sodium').api,
      crypto = require('crypto');

const NPUBBYTES = sodium.crypto_aead_chacha20poly1305_NPUBBYTES,
      KEYBYTES = sodium.crypto_aead_chacha20poly1305_KEYBYTES;

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
        throw new Error(`Key and nonce can't be empty`);
    }

    let isBuffer = plain instanceof Buffer;

    plain = !isBuffer
      ? new Buffer(plain, encoding)
      : plain;
    
    return sodium.crypto_aead_chacha20poly1305_encrypt(plain, null, nonce, key);
  }

  static encryptAsync(...args) {
    return new Promise(resolve => {
      let result = ChaCha20.encrypt.apply(ChaCha20, args);
      resolve(result);
    });
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
        throw new Error(`Key and nonce can't be empty`);
    }

    let isBuffer = cipher instanceof Buffer;

    cipher = !isBuffer
      ? new Buffer(cipher, encoding)
      : cipher;

    return sodium.crypto_aead_chacha20poly1305_decrypt(cipher, null, nonce, key);
  }

  static decryptAsync(...args) {
    return new Promise(resolve => {
      let result = ChaCha20.decrypt.apply(ChaCha20, args);
      resolve(result);
    });
  }

  static getNonce() {
    let nonce = new Buffer(NPUBBYTES);
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
        throw new Error(`Nonce can't be empty`);
    }

    let isBuffer = nonce instanceof Buffer;
    
    nonce = !isBuffer
      ? new Buffer(nonce, encoding)
      : new Buffer(nonce);
    
    if (nonce.length != NPUBBYTES) {
      throw new Error('Nonce has wrong buffer length');
    } else {
      sodium.increment(nonce);
      return nonce;
    }
  }
  
  static getNonceIncrementAsync(...args) {
    return new Promise(resolve => {
      let result = ChaCha20.getNonceIncrement.apply(ChaCha20, args);
      resolve(result);
    });
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
        secret = new Buffer(KEYBYTES);
        salt = new Buffer(KEYBYTES);
        sodium.randombytes(secret);
        sodium.randombytes(salt);
        break;
    }

    let isBuffer = secret instanceof Buffer;

    secret = !isBuffer
      ? new Buffer(secret, encoding)
      : secret;
    
    return crypto.pbkdf2Sync(secret, salt, KEYBYTES * 10, KEYBYTES, 'sha512');
  }
  
  static getKeyAsync(...args) {
    return new Promise(resolve => {
      let result = ChaCha20.getKey.apply(ChaCha20, args);
      resolve(result);
    });
  }
}

module.exports = ChaCha20;