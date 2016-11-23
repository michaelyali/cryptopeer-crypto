'use strict';

class KeyPair {
  
  constructor() {
    this._privateKey = null;
    this._publicKey = null;
  }

  get publicKey() {
    return this._publicKey
      ? this._publicKey.toString('base64')
      : null;
  }

  get privateKey() {
    return this._privateKey
      ? this._privateKey.toString('base64')
      : null;
  }

  get publicKeyBuffer() {
    return this._publicKey;
  }

  get privateKeyBuffer() {
    return this._privateKey;
  }

  publicKeyTo(encoding) {
    return this._publicKey
      ? this._publicKey.toString(encoding ? encoding : 'base64')
      : null;
  }

  privateKeyTo(encoding) {
    return this._privateKey
      ? this._privateKey.toString(encoding ? encoding : 'base64')
      : null;
  }
}

module.exports = KeyPair;