'use strict';

const chai = require('chai'),
      expect = chai.expect;

const lib = require('../lib'),
      ChaCha20 = lib.ChaCha20,
      sodium = require('sodium').api;

const NPUBBYTES = sodium.crypto_aead_chacha20poly1305_NPUBBYTES,
      KEYBYTES = sodium.crypto_aead_chacha20poly1305_KEYBYTES;

describe('ChaCha20', () => {
  
  it('should exist', () => {
    expect(lib).to.exist;
    expect(ChaCha20).to.exist;
    expect(ChaCha20).to.be.a('function');
  });
  
  describe('getNonce', () => {
    
    it('should exist', () => {
      expect(ChaCha20).to.have.property('getNonce');
      expect(ChaCha20.getNonce).to.be.a('function');
    });

    it('should return a nonce buffer', () => {
      let nonce = ChaCha20.getNonce();
      
      expect(nonce).to.be.an.instanceof(Buffer);
      expect(nonce).to.have.lengthOf(NPUBBYTES);
    });
  });

  describe('getNonceIncrement', () => {

    it('should exist', () => {
      expect(ChaCha20).to.have.property('getNonceIncrement');
      expect(ChaCha20.getNonceIncrement).to.be.a('function');
    });

    it('should return incremented nonce buffer from buffer', () => {
      let nonce = ChaCha20.getNonce(),
          inonce = ChaCha20.getNonceIncrement(nonce);
      
      expect(inonce).to.be.an.instanceof(Buffer);
      expect(inonce).to.have.lengthOf(NPUBBYTES);
      expect(inonce.compare(nonce)).equal(1);
    });

    it('should return incremented nonce buffer from encoded string', () => {
      let nonce = ChaCha20.getNonce(),
          nonceString = nonce.toString('base64'),
          inonce = ChaCha20.getNonceIncrement(nonceString);
      
      expect(nonceString).to.be.a('string');
      expect(inonce).to.be.an.instanceof(Buffer);
      expect(inonce).to.have.lengthOf(NPUBBYTES);
      expect(inonce.compare(nonce)).equal(1);

      nonceString = nonce.toString('hex');
      inonce = ChaCha20.getNonceIncrement(nonceString, 'hex');

      expect(nonceString).to.be.a('string');
      expect(inonce).to.be.an.instanceof(Buffer);
      expect(inonce).to.have.lengthOf(NPUBBYTES);
      expect(inonce.compare(nonce)).equal(1);
    });
    
    it('should not pass with invalid params', () => {
      let nonce = ChaCha20.getNonce();
      
      expect(ChaCha20.getNonceIncrement.bind(ChaCha20, nonce.toString('hex'), 'base64')).to.throw(Error);
      expect(ChaCha20.getNonceIncrement.bind(ChaCha20, nonce.toString('hex'), 'invalidEncoding')).to.throw(Error);
      expect(ChaCha20.getNonceIncrement.bind(ChaCha20, 'invalidNonce')).to.throw(Error);
      expect(ChaCha20.getNonceIncrement.bind(ChaCha20, new Buffer(9))).to.throw(Error);
      expect(ChaCha20.getNonceIncrement.bind(ChaCha20)).to.throw(Error);
    });
  });
  
  describe('getNonceIncrementAsync', ()=> {

    it('should exist', () => {
      expect(ChaCha20).to.have.property('getNonceIncrementAsync');
      expect(ChaCha20.getNonceIncrementAsync).to.be.a('function');
    });

    it('should return incremented nonce buffer from buffer', done => {
      let nonce = ChaCha20.getNonce();
      ChaCha20
        .getNonceIncrementAsync(nonce)
        .then(inonce => {
          expect(inonce).to.be.an.instanceof(Buffer);
          expect(inonce).to.have.lengthOf(NPUBBYTES);
          expect(inonce.compare(nonce)).equal(1);
          done();
        })
        .catch(err => {
          throw err;
        });
    });
    
    it('should return incremented nonce buffer from encoded string, 1/2', done => {
      let nonce = ChaCha20.getNonce(),
          nonceString = nonce.toString('base64');
      ChaCha20
        .getNonceIncrementAsync(nonce)
        .then(inonce => {
          expect(nonceString).to.be.a('string');
          expect(inonce).to.be.an.instanceof(Buffer);
          expect(inonce).to.have.lengthOf(NPUBBYTES);
          expect(inonce.compare(nonce)).equal(1);
          done();
        })
        .catch(err => {
          throw err;
        });
    });

    it('should return incremented nonce buffer from encoded string, 2/2', done => {
      let nonce = ChaCha20.getNonce(),
          nonceString = nonce.toString('hex');
      ChaCha20
        .getNonceIncrementAsync(nonce, 'hex')
        .then(inonce => {
          expect(nonceString).to.be.a('string');
          expect(inonce).to.be.an.instanceof(Buffer);
          expect(inonce).to.have.lengthOf(NPUBBYTES);
          expect(inonce.compare(nonce)).equal(1);
          done();
        })
        .catch(err => {
          throw err;
        });
    });
    
    it('should not pass with invalid params, 1/5', done => {
      let nonce = ChaCha20.getNonce();
      ChaCha20
        .getNonceIncrementAsync(nonce.toString('hex'), 'base64')
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        })
    });
    
    it('should not pass with invalid params, 2/5', done => {
      let nonce = ChaCha20.getNonce();
      ChaCha20
        .getNonceIncrementAsync(nonce.toString('hex'), 'invalidEncoding')
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        })
    });
    
    it('should not pass with invalid params, 3/5', done => {
      ChaCha20
        .getNonceIncrementAsync('invalidNonce')
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        })
    });
    
    it('should not pass with invalid params, 4/5', done => {
      ChaCha20
        .getNonceIncrementAsync(new Buffer(9))
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        })
    });
    
    it('should not pass with invalid params, 5/5', done => {
      ChaCha20
        .getNonceIncrementAsync()
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        })
    });
  });
  
  describe('getKey', () => {

    it('should exist', () => {
      expect(ChaCha20).to.have.property('getKey');
      expect(ChaCha20.getKey).to.be.a('function');
    });
    
    it('should return a random key from empty params', () => {
      let key = ChaCha20.getKey();
      
      expect(key).to.be.an.instanceof(Buffer);
      expect(key).to.have.lengthOf(KEYBYTES);
    });
    
    it('should return a key with secret param only', () => {
      let key = ChaCha20.getKey('SuperSecretKey');
      
      expect(key).to.be.an.instanceof(Buffer);
      expect(key).to.have.lengthOf(KEYBYTES);

      key = ChaCha20.getKey(new Buffer('SuperSecretKey'));

      expect(key).to.be.an.instanceof(Buffer);
      expect(key).to.have.lengthOf(KEYBYTES);
    });
    
    it('should return a key with secret and salt params', () => {
      let key = ChaCha20.getKey('SuperSecretKey', 'SuperRandomSalt');

      expect(key).to.be.an.instanceof(Buffer);
      expect(key).to.have.lengthOf(KEYBYTES);

      key = ChaCha20.getKey(new Buffer('SuperSecretKey'), new Buffer('SuperRandomSalt'));

      expect(key).to.be.an.instanceof(Buffer);
      expect(key).to.have.lengthOf(KEYBYTES);
    });
    
    it('should return a key with secret, salt and encoding params', () => {
      let key = ChaCha20.getKey(new Buffer('SuperSecretKey').toString('hex'), 'hex', 'SuperRandomSalt');

      expect(key).to.be.an.instanceof(Buffer);
      expect(key).to.have.lengthOf(KEYBYTES);
    });

    it('should not pass with invalid params', ()=> {
      expect(ChaCha20.getKey.bind(ChaCha20, false)).to.throw(Error);
      expect(ChaCha20.getKey.bind(ChaCha20, true)).to.throw(Error);
      expect(ChaCha20.getKey.bind(ChaCha20, null)).to.throw(Error);
      expect(ChaCha20.getKey.bind(ChaCha20, {})).to.throw(Error);
      expect(ChaCha20.getKey.bind(ChaCha20, new Buffer('SuperSecretKey').toString('hex'), 'invalidEncoding', 'SuperRandomSalt')).to.throw(Error);
      expect(ChaCha20.getKey.bind(ChaCha20, 'SuperSecretKey', false)).to.throw(Error);
      expect(ChaCha20.getKey.bind(ChaCha20, 'SuperSecretKey', true)).to.throw(Error);
      expect(ChaCha20.getKey.bind(ChaCha20, 'SuperSecretKey', null)).to.throw(Error);
      expect(ChaCha20.getKey.bind(ChaCha20, 'SuperSecretKey', {})).to.throw(Error);
    });
  });
  
  describe('getKeyAsync', ()=> {

    it('should exist', () => {
      expect(ChaCha20).to.have.property('getKeyAsync');
      expect(ChaCha20.getKeyAsync).to.be.a('function');
    });
    
    it('should return a random key from empty params', done => {
      ChaCha20
        .getKeyAsync()
        .then(key => {
          expect(key).to.be.an.instanceof(Buffer);
          expect(key).to.have.lengthOf(KEYBYTES);
          done();
        })
        .catch(err => {
          throw err;
        });
    });
    
    it('should return a key with secret param only, 1/2', done => {
      ChaCha20
        .getKeyAsync('SuperSecretKey')
        .then(key => {
          expect(key).to.be.an.instanceof(Buffer);
          expect(key).to.have.lengthOf(KEYBYTES);
          done();
        })
        .catch(err => {
          throw err;
        });
    });

    it('should return a key with secret param only, 2/2', done => {
      ChaCha20
        .getKeyAsync(new Buffer('SuperSecretKey'))
        .then(key => {
          expect(key).to.be.an.instanceof(Buffer);
          expect(key).to.have.lengthOf(KEYBYTES);
          done();
        })
        .catch(err => {
          throw err;
        });
    });

    it('should return a key with secret and salt params, 1/2', done => {
      ChaCha20
        .getKeyAsync('SuperSecretKey', 'SuperRandomSalt')
        .then(key => {
          expect(key).to.be.an.instanceof(Buffer);
          expect(key).to.have.lengthOf(KEYBYTES);
          done();
        })
        .catch(err => {
          throw err;
        });
    });

    it('should return a key with secret and salt params, 2/2', done => {
      ChaCha20
        .getKeyAsync(new Buffer('SuperSecretKey'), new Buffer('SuperRandomSalt'))
        .then(key => {
          expect(key).to.be.an.instanceof(Buffer);
          expect(key).to.have.lengthOf(KEYBYTES);
          done();
        })
        .catch(err => {
          throw err;
        });
    });
    
    it('should return a key with secret, salt and encoding params', done => {
      ChaCha20
        .getKeyAsync(new Buffer('SuperSecretKey').toString('hex'), 'hex', 'SuperRandomSalt')
        .then(key => {
          expect(key).to.be.an.instanceof(Buffer);
          expect(key).to.have.lengthOf(KEYBYTES);
          done();
        })
        .catch(err => {
          throw err;
        });
    });
    
    it('should not pass with invalid params, 1/9', done => {
      ChaCha20
        .getKeyAsync(false)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 2/9', done => {
      ChaCha20
        .getKeyAsync(true)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 3/9', done => {
      ChaCha20
        .getKeyAsync(null)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 4/9', done => {
      ChaCha20
        .getKeyAsync({})
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
    
    it('should not pass with invalid params, 5/9', done => {
      ChaCha20
        .getKeyAsync(new Buffer('SuperSecretKey').toString('hex'), 'invalidEncoding', 'SuperRandomSalt')
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
    
    it('should not pass with invalid params, 6/9', done => {
      ChaCha20
        .getKeyAsync('SuperSecretKey', false)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
    
    it('should not pass with invalid params, 7/9', done => {
      ChaCha20
        .getKeyAsync('SuperSecretKey', true)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 8/9', done => {
      ChaCha20
        .getKeyAsync('SuperSecretKey', null)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 9/9', done => {
      ChaCha20
        .getKeyAsync('SuperSecretKey', {})
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
  });

  let plainText = 'Test message from Alice',
      nonce = new Buffer('SUxfjOvrEyA=', 'base64'),
      key = new Buffer('GXu9CCjQHiQm5MUzdmxby6Nec2lPZzLiDY8OvygUg/c=', 'base64'),
      encrypted = 'padkGdmrymqLRNruHWrf9ArfqZEP4dR+s42EPZK/ojoQQGEMe1Zr';

  describe('encrypt', ()=> {
    
    it('should exist', () => {
      expect(ChaCha20).to.have.property('encrypt');
      expect(ChaCha20.encrypt).to.be.a('function');
    });
    
    it('should encrypt with plain buffer', ()=> {
      let enc = ChaCha20.encrypt(new Buffer(plainText, 'utf8'), nonce, key);
      
      expect(enc).to.be.an.instanceof(Buffer);
      expect(enc.toString('base64')).equal(encrypted);
    });
    
    it('should encrypt with plain string', ()=> {
      let enc = ChaCha20.encrypt(plainText, 'utf8', nonce, key);
      
      expect(enc).to.be.an.instanceof(Buffer);
      expect(enc.toString('base64')).equal(encrypted);

      enc = ChaCha20.encrypt(plainText, nonce, key);

      expect(enc).to.be.an.instanceof(Buffer);
      expect(enc.toString('base64')).equal(encrypted);
    });

    it('should not pass with invalid params', () => {
      expect(ChaCha20.encrypt.bind(ChaCha20)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, plainText)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, plainText, 'secondRandomParam')).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, plainText, 'hex', nonce, key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, plainText, 'invalidEncoding', nonce, key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, false, nonce, key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, true, nonce, key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, null, nonce, key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, {}, nonce, key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, 0, nonce, key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, 128, nonce, key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, plainText, nonce.toString('base64'), key)).to.throw(Error);
      expect(ChaCha20.encrypt.bind(ChaCha20, plainText, nonce, key.toString('base64'))).to.throw(Error);
    });
  });
  
  describe('encryptAsync', ()=> {
    
    it('should exist', () => {
      expect(ChaCha20).to.have.property('encryptAsync');
      expect(ChaCha20.encryptAsync).to.be.a('function');
    });
    
    it('should encrypt with plain buffer', done => {
      ChaCha20
        .encryptAsync(new Buffer(plainText, 'utf8'), nonce, key)
        .then(enc => {
          expect(enc).to.be.an.instanceof(Buffer);
          expect(enc.toString('base64')).equal(encrypted);
          done();
        })
        .catch(err => {
          throw err;
        });
    });
    
    it('should encrypt with plain string, 1/2', done => {
      ChaCha20
        .encryptAsync(plainText, 'utf8', nonce, key)
        .then(enc => {
          expect(enc).to.be.an.instanceof(Buffer);
          expect(enc.toString('base64')).equal(encrypted);
          done();
        })
        .catch(err => {
          throw err;
        });
    });

    it('should encrypt with plain string, 2/2', done => {
      ChaCha20
        .encryptAsync(plainText, nonce, key)
        .then(enc => {
          expect(enc).to.be.an.instanceof(Buffer);
          expect(enc.toString('base64')).equal(encrypted);
          done();
        })
        .catch(err => {
          throw err;
        });
    });
    
    it('should not pass with invalid params, 1/13', done => {
      ChaCha20
        .encryptAsync()
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 2/13', done => {
      ChaCha20
        .encryptAsync(plainText)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 3/13', done => {
      ChaCha20
        .encryptAsync(plainText, 'secondRandomParam')
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
    
    it('should not pass with invalid params, 4/13', done => {
      ChaCha20
        .encryptAsync(plainText, 'hex', nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
    
    it('should not pass with invalid params, 5/13', done => {
      ChaCha20
        .encryptAsync(plainText, 'invalidEncoding', nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
    
    it('should not pass with invalid params, 6/13', done => {
      ChaCha20
        .encryptAsync(false, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 7/13', done => {
      ChaCha20
        .encryptAsync(true, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 8/13', done => {
      ChaCha20
        .encryptAsync(null, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 9/13', done => {
      ChaCha20
        .encryptAsync({}, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 10/13', done => {
      ChaCha20
        .encryptAsync(0, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 11/13', done => {
      ChaCha20
        .encryptAsync(128, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 12/13', done => {
      ChaCha20
        .encryptAsync(plainText, nonce.toString('base64'), key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 13/13', done => {
      ChaCha20
        .encryptAsync(plainText, nonce, key.toString('base64'))
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
  });

  describe('decrypt', ()=> {

    it('should exist', () => {
      expect(ChaCha20).to.have.property('decrypt');
      expect(ChaCha20.decrypt).to.be.a('function');
    });
    
    it('should decrypt with cipher buffer', () => {
      let dec = ChaCha20.decrypt(new Buffer(encrypted, 'base64'), nonce, key);

      expect(dec).to.be.an.instanceof(Buffer);
      expect(dec.toString('utf8')).equal(plainText);
    });

    it('should decrypt with cipher base64', () => {
      let dec = ChaCha20.decrypt(encrypted, 'base64', nonce, key);

      expect(dec).to.be.an.instanceof(Buffer);
      expect(dec.toString('utf8')).equal(plainText);

      dec = ChaCha20.decrypt(encrypted, nonce, key);

      expect(dec).to.be.an.instanceof(Buffer);
      expect(dec.toString('utf8')).equal(plainText);
    });
    
    it('should not pass with invalid params', () => {
      expect(ChaCha20.decrypt.bind(ChaCha20)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, encrypted)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, encrypted, 'secondRandomParam')).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, encrypted, 'hex', nonce, key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, encrypted, 'invalidEncoding', nonce, key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, false, nonce, key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, true, nonce, key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, null, nonce, key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, {}, nonce, key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, 0, nonce, key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, 128, nonce, key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, encrypted, nonce.toString('base64'), key)).to.throw(Error);
      expect(ChaCha20.decrypt.bind(ChaCha20, encrypted, nonce, key.toString('base64'))).to.throw(Error);
    });
  });
  
  describe('decryptAsync', ()=> {

    it('should exist', () => {
      expect(ChaCha20).to.have.property('decryptAsync');
      expect(ChaCha20.decryptAsync).to.be.a('function');
    });
    
    it('should decrypt with cipher buffer', done => {
      ChaCha20
        .decryptAsync(new Buffer(encrypted, 'base64'), nonce, key)
        .then(dec => {
          expect(dec).to.be.an.instanceof(Buffer);
          expect(dec.toString('utf8')).equal(plainText);
          done();
        })
        .catch(err => {
          throw err;
        });
    });
    
    it('should decrypt with cipher base64, 1/2', done => {
      ChaCha20
        .decryptAsync(encrypted, 'base64', nonce, key)
        .then(dec => {
          expect(dec).to.be.an.instanceof(Buffer);
          expect(dec.toString('utf8')).equal(plainText);
          done();
        })
        .catch(err => {
          throw err;
        });
    });

    it('should decrypt with cipher base64, 2/2', done => {
      ChaCha20
        .decryptAsync(encrypted, nonce, key)
        .then(dec => {
          expect(dec).to.be.an.instanceof(Buffer);
          expect(dec.toString('utf8')).equal(plainText);
          done();
        })
        .catch(err => {
          throw err;
        });
    });

    it('should not pass with invalid params, 1/13', done => {
      ChaCha20
        .decryptAsync()
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 2/13', done => {
      ChaCha20
        .decryptAsync(encrypted)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 3/13', done => {
      ChaCha20
        .decryptAsync(encrypted, 'secondRandomParam')
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 4/13', done => {
      ChaCha20
        .decryptAsync(encrypted, 'hex', nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 5/13', done => {
      ChaCha20
        .decryptAsync(encrypted, 'invalidEncoding', nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 6/13', done => {
      ChaCha20
        .decryptAsync(false, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 7/13', done => {
      ChaCha20
        .decryptAsync(true, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 8/13', done => {
      ChaCha20
        .decryptAsync(null, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 9/13', done => {
      ChaCha20
        .decryptAsync({}, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 10/13', done => {
      ChaCha20
        .decryptAsync(0, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 11/13', done => {
      ChaCha20
        .decryptAsync(128, nonce, key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 12/13', done => {
      ChaCha20
        .decryptAsync(encrypted, nonce.toString('base64'), key)
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 13/13', done => {
      ChaCha20
        .decryptAsync(encrypted, nonce, key.toString('base64'))
        .then(ok => {
          throw new Error();
        })
        .catch(err => {
          expect(err).to.be.an('error');
          done();
        });
    });
  });
});