'use strict';

const chai = require('chai'),
      expect = chai.expect;

const lib = require('../lib'),
      RSA = lib.RSA;

describe('RSA', () => {

  it('should exist', () => {
    expect(lib).to.exist;
    expect(RSA).to.exist;
    expect(RSA).to.be.a('function');
  });
  
  describe('new RSA', () => {

    let rsaWithKeyLength = new RSA(),
        rsaWithoutKeyLength = new RSA(512);

    it('should create with keys', () => {
      expect(rsaWithKeyLength).to.be.ok;
      expect(rsaWithKeyLength).to.be.an.instanceof(RSA);
    });

    it('should create without keys', () => {
      expect(rsaWithoutKeyLength).to.be.ok;
      expect(rsaWithoutKeyLength).to.be.an.instanceof(RSA);
    });

    it('should have _privateKey', () => {
      expect(rsaWithKeyLength).to.have.property('_privateKey');
      expect(rsaWithoutKeyLength).to.have.property('_privateKey');
      expect(rsaWithKeyLength._privateKey).to.be.an.instanceof(Buffer);
      expect(rsaWithoutKeyLength._privateKey).to.be.an.instanceof(Buffer);
    });

    it('should have _publicKey', () => {
      expect(rsaWithKeyLength).to.have.property('_publicKey');
      expect(rsaWithoutKeyLength).to.have.property('_publicKey');
      expect(rsaWithKeyLength._publicKey).to.be.an.instanceof(Buffer);
      expect(rsaWithoutKeyLength._publicKey).to.be.an.instanceof(Buffer);
    });

    it('should have privateKey', () => {
      expect(rsaWithKeyLength).to.have.property('privateKey');
      expect(rsaWithoutKeyLength).to.have.property('privateKey');
      expect(rsaWithKeyLength.privateKey).to.be.a('string');
      expect(rsaWithoutKeyLength.privateKey).to.be.a('string');
    });

    it('should have publicKey', () => {
      expect(rsaWithKeyLength).to.have.property('publicKey');
      expect(rsaWithoutKeyLength).to.have.property('publicKey');
      expect(rsaWithKeyLength.publicKey).to.be.a('string');
      expect(rsaWithoutKeyLength.publicKey).to.be.a('string');
    });

    it('should have privateKeyBuffer', () => {
      expect(rsaWithKeyLength).to.have.property('privateKeyBuffer');
      expect(rsaWithoutKeyLength).to.have.property('privateKeyBuffer');
      expect(rsaWithKeyLength.privateKeyBuffer).to.be.an.instanceof(Buffer);
      expect(rsaWithoutKeyLength.privateKeyBuffer).to.be.an.instanceof(Buffer);
    });

    it('should have publicKeyBuffer', () => {
      expect(rsaWithKeyLength).to.have.property('publicKeyBuffer');
      expect(rsaWithoutKeyLength).to.have.property('publicKeyBuffer');
      expect(rsaWithKeyLength.publicKeyBuffer).to.be.an.instanceof(Buffer);
      expect(rsaWithoutKeyLength.publicKeyBuffer).to.be.an.instanceof(Buffer);
    });
    
    it('should have publicKeyTo', () => {
      expect(rsaWithKeyLength).to.have.property('publicKeyTo');
      expect(rsaWithoutKeyLength).to.have.property('publicKeyTo');
      expect(rsaWithKeyLength.publicKeyTo).to.be.a('function');
      expect(rsaWithoutKeyLength.publicKeyTo).to.be.a('function');
    });

    it('should have privateKeyTo', () => {
      expect(rsaWithKeyLength).to.have.property('privateKeyTo');
      expect(rsaWithoutKeyLength).to.have.property('privateKeyTo');
      expect(rsaWithKeyLength.privateKeyTo).to.be.a('function');
      expect(rsaWithoutKeyLength.privateKeyTo).to.be.a('function');
    });

    it('should have _setKey', () => {
      expect(rsaWithKeyLength).to.have.property('_setKey');
      expect(rsaWithoutKeyLength).to.have.property('_setKey');
      expect(rsaWithKeyLength._setKey).to.be.a('function');
      expect(rsaWithoutKeyLength._setKey).to.be.a('function');
    });
    
    it('should have setPrivateKey', () => {
      expect(rsaWithKeyLength).to.have.property('setPrivateKey');
      expect(rsaWithoutKeyLength).to.have.property('setPrivateKey');
      expect(rsaWithKeyLength.setPrivateKey).to.be.a('function');
      expect(rsaWithoutKeyLength.setPrivateKey).to.be.a('function');
    });

    it('should have setPrivateKeyAsync', () => {
      expect(rsaWithKeyLength).to.have.property('setPrivateKeyAsync');
      expect(rsaWithoutKeyLength).to.have.property('setPrivateKeyAsync');
      expect(rsaWithKeyLength.setPrivateKeyAsync).to.be.a('function');
      expect(rsaWithoutKeyLength.setPrivateKeyAsync).to.be.a('function');
    });
    
    it('should have setPublicKey', () => {
      expect(rsaWithKeyLength).to.have.property('setPublicKey');
      expect(rsaWithoutKeyLength).to.have.property('setPublicKey');
      expect(rsaWithKeyLength.setPublicKey).to.be.a('function');
      expect(rsaWithoutKeyLength.setPublicKey).to.be.a('function');
    });

    it('should have setPublicKeyAsync', () => {
      expect(rsaWithKeyLength).to.have.property('setPublicKeyAsync');
      expect(rsaWithoutKeyLength).to.have.property('setPublicKeyAsync');
      expect(rsaWithKeyLength.setPublicKeyAsync).to.be.a('function');
      expect(rsaWithoutKeyLength.setPublicKeyAsync).to.be.a('function');
    });
    
    it('should have encrypt', () => {
      expect(rsaWithKeyLength).to.have.property('encrypt');
      expect(rsaWithoutKeyLength).to.have.property('encrypt');
      expect(rsaWithKeyLength.encrypt).to.be.a('function');
      expect(rsaWithoutKeyLength.encrypt).to.be.a('function');
    });

    it('should have encryptAsync', () => {
      expect(rsaWithKeyLength).to.have.property('encryptAsync');
      expect(rsaWithoutKeyLength).to.have.property('encryptAsync');
      expect(rsaWithKeyLength.encryptAsync).to.be.a('function');
      expect(rsaWithoutKeyLength.encryptAsync).to.be.a('function');
    });
    
    it('should have decrypt', () => {
      expect(rsaWithKeyLength).to.have.property('decrypt');
      expect(rsaWithoutKeyLength).to.have.property('decrypt');
      expect(rsaWithKeyLength.decrypt).to.be.a('function');
      expect(rsaWithoutKeyLength.decrypt).to.be.a('function');
    });

    it('should have decryptAsync', () => {
      expect(rsaWithKeyLength).to.have.property('decryptAsync');
      expect(rsaWithoutKeyLength).to.have.property('decryptAsync');
      expect(rsaWithKeyLength.decryptAsync).to.be.a('function');
      expect(rsaWithoutKeyLength.decryptAsync).to.be.a('function');
    });

    describe('setPublicKey', () => {

      let publicKey = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMHDFWJUuXOx9W5DgaJgLJ+ybUV+plLz1WDAC3TpeH9niFCqZr88MsbhQRloZ' +
          'LDqPFCbcdQ0K12f4uzj7xA4ZQMCAwEAAQ==',
          alice = new RSA(512);

      it('should import publicKey base64', () => {
        alice.setPublicKey(publicKey);
        expect(alice.publicKey).equal(publicKey);
      });

      it('should import publicKey buffer', () => {
        let publicKeyBuffer = new Buffer(publicKey, 'base64');
        alice.setPublicKey(publicKeyBuffer);
        expect(alice.publicKeyBuffer).equal(publicKeyBuffer);
      });
      
      it('should not pass with invalid params', () => {
        expect(alice.setPublicKey.bind(alice, 'invalidBuffer')).to.throw(Error);
        expect(alice.setPublicKey.bind(alice, publicKey, 'invalidEncoding')).to.throw(Error);
      });
    });
    
    describe('setPublicKeyAsync', ()=> {

      let publicKey = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMHDFWJUuXOx9W5DgaJgLJ+ybUV+plLz1WDAC3TpeH9niFCqZr88MsbhQRloZ' +
          'LDqPFCbcdQ0K12f4uzj7xA4ZQMCAwEAAQ==',
          alice = new RSA(512);
      
      it('should import publicKey base64', done => {
        alice
          .setPublicKeyAsync(publicKey)
          .then(ok => {
            expect(alice.publicKey).equal(publicKey);
            done();
          })
          .catch(err => {
            throw err;
          });
      });

      it('should import publicKey buffer', done => {
        let publicKeyBuffer = new Buffer(publicKey, 'base64');
        alice
          .setPublicKeyAsync(publicKeyBuffer)
          .then(ok => {
            expect(alice.publicKeyBuffer).equal(publicKeyBuffer);
            done();
          })
          .catch(err => {
            throw err;
          });
      });

      it('should not pass with invalid params, 1/2', done => {
        alice
          .setPublicKeyAsync('invalidBuffer')
          .then(ok => {
            throw new Error();
          })
          .catch(err => {
            expect(err).to.be.an('error');
            done();
          });
      });

      it('should not pass with invalid params, 2/2', done => {
        alice
          .setPublicKeyAsync(publicKey, 'invalidEncoding')
          .then(ok => {
            throw new Error();
          })
          .catch(err => {
            expect(err).to.be.an('error');
            done();
          });
      });
    });

    describe('setPrivateKey', () => {

      let privateKey = 'MIIBOQIBAAJBAKlAad4bmmByKbwV/jI2pQMx+VNghqXdf0/rpO6d9fVQu6cbs6gPo+piJDTc3Uau7qV43WaPk4dvtu3D/' +
        'j5q2DkCAwEAAQJATMgG/xbgou5HlqcXiWoW0+tA450/mFFypywMx59rbFz0z64KVrrv2NkIE2ExPhuCtS9oMeQCLa7BtEhRVhitsQIhAOcR' +
        '1R/arpKNesuyx2g1H+BBjh9Cdg8RMQLH2NMvwVRlAiEAu4MpD2z/vxu23nnbwuWNbi9orV+snFdyEiP0iiyipUUCIAREJgUyimqWRiAgquH' +
        'XqUEAtNkK5xccICWG/w/XH+CpAiBoOUf6TgB87d+gGyV+V+9bnjhVnYcowyYhVSDYKGUi7QIgGTjlN4hZF3C5TJPiNjE0CAWWoQCpWWRRln' +
        '0TdS4SuoE=',
          alice = new RSA(512);

      it('should import privateKey base64', () => {
        alice.setPrivateKey(privateKey);
        expect(alice.privateKey).equal(privateKey);
      });

      it('should import privateKey buffer', () => {
        let privateKeyBuffer = new Buffer(privateKey, 'base64');
        alice.setPrivateKey(privateKeyBuffer);
        expect(alice.privateKeyBuffer).equal(privateKeyBuffer);
      });

      it('should not pass with invalid params', () => {
        expect(alice.setPrivateKey.bind(alice, 'invalidBuffer')).to.throw(Error);
        expect(alice.setPrivateKey.bind(alice, privateKey, 'invalidEncoding')).to.throw(Error);
      });
    });
    
    describe('setPrivateKeyAsync', ()=> {

      let privateKey = 'MIIBOQIBAAJBAKlAad4bmmByKbwV/jI2pQMx+VNghqXdf0/rpO6d9fVQu6cbs6gPo+piJDTc3Uau7qV43WaPk4dvtu3D/' +
          'j5q2DkCAwEAAQJATMgG/xbgou5HlqcXiWoW0+tA450/mFFypywMx59rbFz0z64KVrrv2NkIE2ExPhuCtS9oMeQCLa7BtEhRVhitsQIhAOcR' +
          '1R/arpKNesuyx2g1H+BBjh9Cdg8RMQLH2NMvwVRlAiEAu4MpD2z/vxu23nnbwuWNbi9orV+snFdyEiP0iiyipUUCIAREJgUyimqWRiAgquH' +
          'XqUEAtNkK5xccICWG/w/XH+CpAiBoOUf6TgB87d+gGyV+V+9bnjhVnYcowyYhVSDYKGUi7QIgGTjlN4hZF3C5TJPiNjE0CAWWoQCpWWRRln' +
          '0TdS4SuoE=',
          alice = new RSA(512);
      
      it('should import privateKey base64', done => {
        alice
          .setPrivateKeyAsync(privateKey)
          .then(ok => {
            expect(alice.privateKey).equal(privateKey);
            done();
          })
          .catch(err => {
            throw err;
          });
      });
      
      it('should import privateKey buffer', done => {
        let privateKeyBuffer = new Buffer(privateKey, 'base64');
        alice
          .setPrivateKeyAsync(privateKeyBuffer)
          .then(ok => {
            expect(alice.privateKeyBuffer).equal(privateKeyBuffer);
            done();
          })
          .catch(err => {
            throw err;
          });
      });
      
      it('should not pass with invalid params, 1/2', done => {
        alice
          .setPrivateKeyAsync('invalidBuffer')
          .then(ok => {
            throw new Error();
          })
          .catch(err => {
            expect(err).to.be.an('error');
            done();
          });
      });

      it('should not pass with invalid params, 2/2', done => {
        alice
          .setPrivateKeyAsync(privateKey, 'invalidEncoding')
          .then(ok => {
            throw new Error();
          })
          .catch(err => {
            expect(err).to.be.an('error');
            done();
          });
      });
    });
    
    describe('cryptography', () => {

      let alice = new RSA(512),
          bob = new RSA(512),
          plainString = 'Microphone checka!',
          plainNumber = 1024,
          plainObject = {
            foo: 'Bar'
          },
          plainArray = [true, null, 'String', 69, { foo: 'Bar' }],
          encryptedString,
          encryptedNumber,
          encryptedObject,
          encryptedArray,
          encryptedNull,
          encryptedUndefined;

      describe('encrypt', () => {

        alice.setPublicKey(bob.publicKey);
        
        it('should encrypt a string', () => {
          encryptedString = alice.encrypt(plainString);
          expect(encryptedString).to.be.a('string');
        });

        it('should encrypt a number', () => {
          encryptedNumber = alice.encrypt(plainNumber);
          expect(encryptedNumber).to.be.a('string');
        });

        it('should encrypt an object', () => {
          encryptedObject = alice.encrypt(plainObject);
          expect(encryptedObject).to.be.a('string');
        });

        it('should encrypt an array', () => {
          encryptedArray = alice.encrypt(plainArray);
          expect(encryptedArray).to.be.a('string');
        });

        it('should encrypt null', () => {
          encryptedNull = alice.encrypt(null);
          expect(encryptedNull).to.be.a('string');
        });

        it('should encrypt with empty params', () => {
          encryptedUndefined = alice.encrypt();
          expect(encryptedUndefined).to.be.a('string');
        });

        it('should not pass true, false', () => {
          expect(alice.encrypt.bind(alice, true)).to.throw(Error);
          expect(alice.encrypt.bind(alice, false)).to.throw(Error);
        });
      });
      
      describe('encryptAsync', ()=> {

        alice.setPublicKey(bob.publicKey);
        
        it('should encrypt a string', done => {
          alice
            .encryptAsync(plainString)
            .then(en => {
              encryptedString = en;
              expect(encryptedString).to.be.a('string');
              done();
            })
            .catch(err => {
              throw err;
            });
        });
        
        it('should encrypt a number', done => {
          alice
            .encryptAsync(plainNumber)
            .then(en => {
              encryptedNumber = en;
              expect(encryptedNumber).to.be.a('string');
              done();
            })
            .catch(err => {
              throw err;
            });
        });

        it('should encrypt an object', done => {
          alice
            .encryptAsync(plainObject)
            .then(en => {
              encryptedObject = en;
              expect(encryptedObject).to.be.a('string');
              done();
            })
            .catch(err => {
              throw err;
            });
        });

        it('should encrypt an array', done => {
          alice
            .encryptAsync(plainArray)
            .then(en => {
              encryptedArray = en;
              expect(encryptedArray).to.be.a('string');
              done();
            })
            .catch(err => {
              throw err;
            });
        });

        it('should encrypt null', done => {
          alice
            .encryptAsync(null)
            .then(en => {
              encryptedNull = en;
              expect(encryptedNull).to.be.a('string');
              done();
            })
            .catch(err => {
              throw err;
            });
        });
        
        it('should encrypt with empty params', done => {
          alice
            .encryptAsync()
            .then(en => {
              encryptedUndefined = en;
              expect(encryptedUndefined).to.be.a('string');
              done();
            })
            .catch(err => {
              throw err;
            });
        });
        
        it('should not pass true, false, 1/2', done => {
          alice
            .encryptAsync(true)
            .then(ok => {
              throw new Error();
            })
            .catch(err => {
              expect(err).to.be.an('error');
              done();
            })
        });
        
        it('should not pass true, false, 2/2', done => {
          alice
            .encryptAsync(true)
            .then(ok => {
              throw new Error();
            })
            .catch(err => {
              expect(err).to.be.an('error');
              done();
            })
        });
      });
      
      describe('decrypt', () => {
        
        it('should decrypt to strings', () => {
          let decrypted = bob.decrypt(encryptedString);
          expect(decrypted).equal(plainString);
        });

        it('should decrypt to numbers', () => {
          let decrypted = bob.decrypt(encryptedNumber);
          expect(decrypted).equal(plainNumber);
        });
        
        it('should decrypt to object', () => {
          let decrypted = bob.decrypt(encryptedObject);
          expect(decrypted).to.be.an('object');
          expect(decrypted).to.have.property('foo');
          expect(decrypted.foo).equal(plainObject.foo);
        });

        it('should decrypt to array', () => {
          let decrypted = bob.decrypt(encryptedArray);
          expect(decrypted).to.be.an('array');
          expect(decrypted[0]).equal(plainArray[0]);
          expect(decrypted[1]).equal(plainArray[1]);
          expect(decrypted[2]).equal(plainArray[2]);
          expect(decrypted[3]).equal(plainArray[3]);
          expect(decrypted[4]).to.be.an('object');
          expect(decrypted[4]).to.have.property('foo');
          expect(decrypted[4].foo).equal(plainObject.foo);
        });
        
        it('should decrypt null to string null', () => {
          let decrypted = bob.decrypt(encryptedNull);
          expect(decrypted).equal('null');
        });

        it('should decrypt empty params to an empty string', () => {
          let decrypted = bob.decrypt(encryptedUndefined);
          expect(decrypted).equal('');
        });
      });
      
      describe('decryptAsync', ()=> {
        
        it('should decrypt to strings', done => {
          bob
            .decryptAsync(encryptedString)
            .then(decrypted => {
              expect(decrypted).equal(plainString);
              done();
            })
            .catch(err => {
              throw err;
            });
        });

        it('should decrypt to numbers', done => {
          bob
            .decryptAsync(encryptedNumber)
            .then(decrypted => {
              expect(decrypted).equal(plainNumber);
              done();
            })
            .catch(err => {
              throw err;
            });
        });

        it('should decrypt to object', done => {
          bob
            .decryptAsync(encryptedObject)
            .then(decrypted => {
              expect(decrypted).to.be.an('object');
              expect(decrypted).to.have.property('foo');
              expect(decrypted.foo).equal(plainObject.foo);
              done();
            })
            .catch(err => {
              throw err;
            });
        });

        it('should decrypt to array', done => {
          bob
            .decryptAsync(encryptedArray)
            .then(decrypted => {
              expect(decrypted).to.be.an('array');
              expect(decrypted[0]).equal(plainArray[0]);
              expect(decrypted[1]).equal(plainArray[1]);
              expect(decrypted[2]).equal(plainArray[2]);
              expect(decrypted[3]).equal(plainArray[3]);
              expect(decrypted[4]).to.be.an('object');
              expect(decrypted[4]).to.have.property('foo');
              expect(decrypted[4].foo).equal(plainObject.foo);
              done();
            })
            .catch(err => {
              throw err;
            });
        });
        
        it('should decrypt null to string null', done => {
          bob
            .decryptAsync(encryptedNull)
            .then(decrypted => {
              expect(decrypted).equal('null');
              done();
            })
            .catch(err => {
              throw err;
            });
        });

        it('should decrypt empty params to an empty string', done => {
          bob
            .decryptAsync(encryptedUndefined)
            .then(decrypted => {
              expect(decrypted).equal('');
              done();
            })
            .catch(err => {
              throw err;
            });
        });
      });
    });
  });
});