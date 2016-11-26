'use strict';

const rsa = require('node-rsa'),
      KeyPair = require('./KeyPair');

class RSA extends KeyPair {
  
  constructor(keyLength) {
    super();

    keyLength = typeof keyLength === 'number'
      ? keyLength
      : 512;
    
    this._rsa =new rsa({b: keyLength});
    this._privateKey = this._rsa.exportKey('private-der')
    this._publicKey = this._rsa.exportKey('public-der')
  }
  
  _setKey(key, encoding, type) {
    key = key instanceof Buffer
      ? key
      : new Buffer(key, encoding ? encoding : 'base64');

    this._rsa.importKey(key, type);
    
    if (type === 'private-der') {
      this._privateKey = key;
    } else {
      this._publicKey = key;
    }
  }
  
  setPrivateKey(key, encoding) {
    this._setKey(key, encoding, 'private-der');
  }
  
  setPublicKey(key, encoding) {
    this._setKey(key, encoding, 'public-der');
  }

  encrypt(plain, encoding) {
    let type = typeof plain;
    encoding = encoding || 'base64';
    
    plain = type === 'undefined'
      ? ''
      : plain;
    
    plain = type === 'object' || Array.isArray(plain)
      ? JSON.stringify(plain)
      : plain;

    return this._rsa.encrypt(plain, encoding);
  }

  decrypt(hash, encoding) {
    encoding = encoding || 'utf8';

    let decrypted = this._rsa.decrypt(hash, encoding);
    
    let isJSON = false,
        parsed = null;
    try {
      parsed = JSON.parse(decrypted);
      isJSON = true;
    } catch (e) {}

    return (isJSON && parsed) ? parsed : decrypted;
  }
}

module.exports = RSA;