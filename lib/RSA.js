const Rsa = require('node-rsa');
const KeyPair = require('./KeyPair');

/**
 * RSA
 */
class RSA extends KeyPair {

  /**
   * Constructor
   * @param keyLength
   */
  constructor(keyLength) {
    super();

    const keyLengthFinal = typeof keyLength === 'number'
      ? keyLength
      : 512;

    this._rsa = new Rsa({ b: keyLengthFinal });
    this._privateKey = this._rsa.exportKey('private-der');
    this._publicKey = this._rsa.exportKey('public-der');
  }

  /**
   * Set key
   * @param key
   * @param encoding
   * @param type
   * @returns {Buffer|*}
   * @private
   */
  _setKey(key, encoding, type) {
    const keyFinal = key instanceof Buffer
      ? key
      : new Buffer(key, encoding || 'base64');

    this._rsa.importKey(keyFinal, type);

    if (type === 'private-der') {
      this._privateKey = keyFinal;
    } else {
      this._publicKey = keyFinal;
    }

    return keyFinal;
  }

  /**
   * Set privateKey
   * @param key
   * @param encoding
   * @returns {Buffer|*}
   */
  setPrivateKey(key, encoding) {
    return this._setKey(key, encoding, 'private-der');
  }

  /**
   * Set privateKey with Promise
   * @param key
   * @param encoding
   * @returns {Promise}
   */
  setPrivateKeyAsync(key, encoding) {
    return new Promise(resolve => resolve(this.setPrivateKey(key, encoding)));
  }

  /**
   * Set publicKey
   * @param key
   * @param encoding
   * @returns {Buffer|*}
   */
  setPublicKey(key, encoding) {
    return this._setKey(key, encoding, 'public-der');
  }

  /**
   * Set publicKey with Promise
   * @param key
   * @param encoding
   * @returns {Promise}
   */
  setPublicKeyAsync(key, encoding) {
    return new Promise(resolve => resolve(this.setPublicKey(key, encoding)));
  }

  /**
   * Encrypt
   * @param plain
   * @param encoding
   * @returns {string|Buffer}
   */
  encrypt(plain, encoding) {
    const type = typeof plain;
    const encodingFinal = encoding || 'base64';

    let plainFinal = type === 'undefined'
      ? ''
      : plain;

    plainFinal = type === 'object' || Array.isArray(plainFinal)
      ? JSON.stringify(plainFinal)
      : plainFinal;

    return this._rsa.encrypt(plainFinal, encodingFinal);
  }

  /**
   * Encrypt with Promise
   * @param plain
   * @param encoding
   * @returns {Promise}
   */
  encryptAsync(plain, encoding) {
    return new Promise(resolve => resolve(this.encrypt(plain, encoding)));
  }

  /**
   * Decrypt
   * @param hash
   * @param encoding
   * @returns {Buffer|Object|string}
   */
  decrypt(hash, encoding) {
    const encodingFinal = encoding || 'utf8';
    const decrypted = this._rsa.decrypt(hash, encodingFinal);

    let isJSON = false;
    let parsed = null;

    try {
      parsed = JSON.parse(decrypted);
      isJSON = true;
    } catch (e) {} /* eslint no-empty: 0 */

    return (isJSON && parsed) ? parsed : decrypted;
  }

  /**
   * Decrypt with Promise
   * @param hash
   * @param encoding
   * @returns {Promise}
   */
  decryptAsync(hash, encoding) {
    return new Promise(resolve => resolve(this.decrypt(hash, encoding)));
  }
}

module.exports = RSA;
