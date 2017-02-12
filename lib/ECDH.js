const sodium = require('sodium').api;
const KeyPair = require('./KeyPair');

/**
 * ECDH
 */
class ECDH extends KeyPair {

  /**
   * Constructor
   * @param skipKeys
   */
  constructor(skipKeys) {
    super();

    if (!skipKeys) {
      const keys = sodium.crypto_box_keypair();
      this._privateKey = keys.secretKey;
      this._publicKey = keys.publicKey;
    }
  }

  /**
   * Create instance from privateKey
   * @param privateKey
   * @param encoding
   * @returns {ECDH}
   */
  static fromPrivateKey(privateKey, encoding) {
    const privateKeyFinal = privateKey instanceof Buffer
      ? privateKey
      : new Buffer(privateKey, encoding || 'base64');

    const publicKey = sodium.crypto_scalarmult_base(privateKeyFinal);

    const ecdh = new ECDH(true);
    ecdh._privateKey = privateKeyFinal;
    ecdh._publicKey = publicKey;

    return ecdh;
  }

  /**
   * Create instance from privateKey with Promise
   * @param privateKey
   * @param encoding
   * @returns {Promise}
   */
  static fromPrivateKeyAsync(privateKey, encoding) {
    return new Promise(resolve => resolve(ECDH.fromPrivateKey(privateKey, encoding)));
  }

  /**
   * Compute secret
   * @param publicKey
   * @param inputEncoding
   * @param outputEncoding
   * @returns {*}
   */
  computeSecret(publicKey, inputEncoding, outputEncoding) {
    if (this._privateKey) {
      const outputEncodingFinal = (publicKey instanceof Buffer) && inputEncoding
        ? inputEncoding
        : outputEncoding;

      const publicKeyFinal = publicKey instanceof Buffer
        ? publicKey
        : new Buffer(publicKey, inputEncoding || 'base64');

      const sharedSecret = sodium.crypto_scalarmult(this._privateKey, publicKeyFinal);

      return outputEncodingFinal
        ? sharedSecret.toString(outputEncodingFinal)
        : sharedSecret;
    }
    return null;
  }

  /**
   * Compute secret with Promise
   * @param args
   * @returns {Promise}
   */
  computeSecretAsync(...args) {
    return new Promise(resolve => resolve(this.computeSecret.apply(this, args)));
  }
}

module.exports = ECDH;
