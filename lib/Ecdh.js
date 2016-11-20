'use strict';

const sodium = require('sodium').api;

class Ecdh {
  
  constructor(skipKeys) {
    if (skipKeys) {
      this._privateKey = null;
      this._publicKey = null;
    } else {
      let keys = sodium.crypto_box_keypair();
      this._privateKey = keys.secretKey;
      this._publicKey = keys.publicKey;
    }
  }
  
  static fromPrivateKey(privateKey, encoding) {
    privateKey = privateKey instanceof Buffer
      ? privateKey
      : new Buffer(privateKey, encoding ? encoding : 'base64');
    
    let publicKey = sodium.crypto_scalarmult_base(privateKey);
    
    let ecdh = new Ecdh(true);
    ecdh._privateKey = privateKey;
    ecdh._publicKey = publicKey;
    
    return ecdh;
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
  
  computeSecret(publicKey, inputEncoding, outputEncoding) {
    if (this._privateKey) {
      outputEncoding = (publicKey instanceof Buffer) && inputEncoding
        ? inputEncoding
        : outputEncoding;
      
      publicKey = publicKey instanceof Buffer
        ? publicKey
        : new Buffer(publicKey, inputEncoding ? inputEncoding : 'base64');

      let sharedSecret = sodium.crypto_scalarmult(this._privateKey, publicKey);
      
      return outputEncoding
        ? sharedSecret.toString(outputEncoding)
        : sharedSecret;
    } else {
      return null;
    }
  }
}

module.exports = Ecdh;