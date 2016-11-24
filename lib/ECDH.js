'use strict';

const sodium = require('sodium').api,
      KeyPair = require('./KeyPair');

class ECDH extends KeyPair {
  
  constructor(skipKeys) {
    super();
    
    if (!skipKeys) {
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
    
    let ecdh = new ECDH(true);
    ecdh._privateKey = privateKey;
    ecdh._publicKey = publicKey;
    
    return ecdh;
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

module.exports = ECDH;