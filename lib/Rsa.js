'use strict';

const rsa = require('node-rsa'),
      KeyPair = require('./KeyPair');

class Rsa extends KeyPair {
  
  constructor(keyLength) {
    super();
    
    this._rsa = keyLength ? new rsa({b: keyLength}) : new rsa();
    this._privateKey = this._rsa.exportKey('private-der');
    this._publicKey = this._rsa.exportKey('public-der');
  }
}