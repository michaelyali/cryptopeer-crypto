const sodium = require('sodium').api;
const crypto = require('crypto');

const NPUBBYTES = sodium.crypto_aead_chacha20poly1305_NPUBBYTES;
const KEYBYTES = sodium.crypto_aead_chacha20poly1305_KEYBYTES;

/**
 * ChaCha20
 */
class ChaCha20 {

  /**
   * Encrypt
   * @param args
   * @returns {*}
   */
  static encrypt(...args) {
    let plain = null;
    let encoding = null;
    let nonce = null;
    let key = null;

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
        throw new Error('Key and nonce can\'t be empty');
    }

    const isBuffer = plain instanceof Buffer;

    plain = !isBuffer
      ? new Buffer(plain, encoding)
      : plain;

    return sodium.crypto_aead_chacha20poly1305_encrypt(plain, null, nonce, key);
  }

  /**
   * Encrypt with Promise
   * @param args
   * @returns {Promise}
   */
  static encryptAsync(...args) {
    return new Promise(resolve => resolve(ChaCha20.encrypt.apply(ChaCha20, args)));
  }

  /**
   * Decrypt
   * @param args
   * @returns {*}
   */
  static decrypt(...args) {
    let cipher = null;
    let encoding = null;
    let nonce = null;
    let key = null;

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
        throw new Error('Key and nonce can\'t be empty');
    }

    const isBuffer = cipher instanceof Buffer;

    cipher = !isBuffer
      ? new Buffer(cipher, encoding)
      : cipher;

    return sodium.crypto_aead_chacha20poly1305_decrypt(cipher, null, nonce, key);
  }

  /**
   * Decrypt with Promise
   * @param args
   * @returns {Promise}
   */
  static decryptAsync(...args) {
    return new Promise(resolve => resolve(ChaCha20.decrypt.apply(ChaCha20, args)));
  }

  /**
   * Create nonce
   * @returns {Buffer}
   */
  static getNonce() {
    const nonce = new Buffer(NPUBBYTES);
    sodium.randombytes(nonce);
    return nonce;
  }

  /**
   * Increment nonce
   * @param args
   * @returns {Buffer|*}
   */
  static getNonceIncrement(...args) {
    let nonce = null;
    let encoding = null;

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
        throw new Error('Nonce can\'t be empty');
    }

    const isBuffer = nonce instanceof Buffer;

    nonce = !isBuffer
      ? new Buffer(nonce, encoding)
      : new Buffer(nonce);

    if (nonce.length !== NPUBBYTES) {
      throw new Error('Nonce has wrong buffer length');
    } else {
      sodium.increment(nonce);
      return nonce;
    }
  }

  /**
   * Increment nonce with Promise
   * @param args
   * @returns {Promise}
   */
  static getNonceIncrementAsync(...args) {
    return new Promise(resolve => resolve(ChaCha20.getNonceIncrement.apply(ChaCha20, args)));
  }

  /**
   * Generate key
   * @param args
   */
  static getKey(...args) {
    let secret = null;
    let encoding = null;
    let salt = null;

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

    const isBuffer = secret instanceof Buffer;

    secret = !isBuffer
      ? new Buffer(secret, encoding)
      : secret;

    return crypto.pbkdf2Sync(secret, salt, KEYBYTES * 10, KEYBYTES, 'sha512');
  }

  /**
   * Generate key with Promise
   * @param args
   * @returns {Promise}
   */
  static getKeyAsync(...args) {
    return new Promise(resolve => resolve(ChaCha20.getKey.apply(ChaCha20, args)));
  }
}

module.exports = ChaCha20;
