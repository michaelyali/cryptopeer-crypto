/**
 * KeyPair
 */
class KeyPair {

  /**
   * Constructor
   */
  constructor() {
    this._privateKey = null;
    this._publicKey = null;
  }

  /**
   * Get publicKey
   * @returns {*}
   */
  get publicKey() {
    return this._publicKey
      ? this._publicKey.toString('base64')
      : null;
  }

  /**
   * Get privateKey
   * @returns {*}
   */
  get privateKey() {
    return this._privateKey
      ? this._privateKey.toString('base64')
      : null;
  }

  /**
   * Get publicKeyBuffer
   * @returns {null}
   */
  get publicKeyBuffer() {
    return this._publicKey;
  }

  /**
   * Get privateKeyBuffer
   * @returns {null}
   */
  get privateKeyBuffer() {
    return this._privateKey;
  }

  /**
   * Encode publicKey
   * @param encoding
   * @returns {*}
   */
  publicKeyTo(encoding) {
    return this._publicKey
      ? this._publicKey.toString(encoding || 'base64')
      : null;
  }

  /**
   * Encode privateKey
   * @param encoding
   * @returns {*}
   */
  privateKeyTo(encoding) {
    return this._privateKey
      ? this._privateKey.toString(encoding || 'base64')
      : null;
  }
}

module.exports = KeyPair;
