/* eslint no-unused-expressions: 0 */

const chai = require('chai');
const lib = require('../lib');

const expect = chai.expect;
const ECDH = lib.ECDH;

describe('ECDH', () => {
  const privateKeyBase64 = 'd05yp7dX+X9FW9KkiunJ+qSp8/RDrFpiQ02EasZre9E=';
  const privateKeyBuffer = new Buffer(privateKeyBase64, 'base64');

  it('should exist', () => {
    expect(lib).to.exist;
    expect(ECDH).to.exist;
    expect(ECDH).to.be.a('function');
  });

  describe('new ECDH', () => {
    const ecdhWithKeys = new ECDH();
    const ecdhWithoutKeys = new ECDH(true);

    it('should create with keys', () => {
      expect(ecdhWithKeys).to.be.ok;
      expect(ecdhWithKeys).to.be.an.instanceof(ECDH);
    });

    it('should create without keys', () => {
      expect(ecdhWithoutKeys).to.be.ok;
      expect(ecdhWithoutKeys).to.be.an.instanceof(ECDH);
    });

    it('should have _privateKey', () => {
      expect(ecdhWithKeys).to.have.property('_privateKey');
      expect(ecdhWithoutKeys).to.have.property('_privateKey');
      expect(ecdhWithKeys._privateKey).to.be.an.instanceof(Buffer);
      expect(ecdhWithoutKeys._privateKey).to.be.a('null');
    });

    it('should have _publicKey', () => {
      expect(ecdhWithKeys).to.have.property('_publicKey');
      expect(ecdhWithoutKeys).to.have.property('_publicKey');
      expect(ecdhWithKeys._publicKey).to.be.an.instanceof(Buffer);
      expect(ecdhWithoutKeys._publicKey).to.be.a('null');
    });

    it('should have privateKey', () => {
      expect(ecdhWithKeys).to.have.property('privateKey');
      expect(ecdhWithoutKeys).to.have.property('privateKey');
      expect(ecdhWithKeys.privateKey).to.be.a('string');
      expect(ecdhWithoutKeys.privateKey).to.be.a('null');
    });

    it('should have publicKey', () => {
      expect(ecdhWithKeys).to.have.property('publicKey');
      expect(ecdhWithoutKeys).to.have.property('publicKey');
      expect(ecdhWithKeys.publicKey).to.be.a('string');
      expect(ecdhWithoutKeys.publicKey).to.be.a('null');
    });

    it('should have privateKeyBuffer', () => {
      expect(ecdhWithKeys).to.have.property('privateKeyBuffer');
      expect(ecdhWithoutKeys).to.have.property('privateKeyBuffer');
      expect(ecdhWithKeys.privateKeyBuffer).to.be.an.instanceof(Buffer);
      expect(ecdhWithoutKeys.privateKeyBuffer).to.be.a('null');
    });

    it('should have publicKeyBuffer', () => {
      expect(ecdhWithKeys).to.have.property('publicKeyBuffer');
      expect(ecdhWithoutKeys).to.have.property('publicKeyBuffer');
      expect(ecdhWithKeys.publicKeyBuffer).to.be.an.instanceof(Buffer);
      expect(ecdhWithoutKeys.publicKeyBuffer).to.be.a('null');
    });

    it('should have computeSecret', () => {
      expect(ecdhWithKeys).to.have.property('computeSecret');
      expect(ecdhWithoutKeys).to.have.property('computeSecret');
      expect(ecdhWithKeys.computeSecret).to.be.a('function');
      expect(ecdhWithoutKeys.computeSecret).to.be.a('function');
    });

    it('should have computeSecretAsync', () => {
      expect(ecdhWithKeys).to.have.property('computeSecretAsync');
      expect(ecdhWithoutKeys).to.have.property('computeSecretAsync');
      expect(ecdhWithKeys.computeSecretAsync).to.be.a('function');
      expect(ecdhWithoutKeys.computeSecretAsync).to.be.a('function');
    });

    it('should have publicKeyTo', () => {
      expect(ecdhWithKeys).to.have.property('publicKeyTo');
      expect(ecdhWithoutKeys).to.have.property('publicKeyTo');
      expect(ecdhWithKeys.publicKeyTo).to.be.a('function');
      expect(ecdhWithoutKeys.publicKeyTo).to.be.a('function');
    });

    it('should have privateKeyTo', () => {
      expect(ecdhWithKeys).to.have.property('privateKeyTo');
      expect(ecdhWithoutKeys).to.have.property('privateKeyTo');
      expect(ecdhWithKeys.privateKeyTo).to.be.a('function');
      expect(ecdhWithoutKeys.privateKeyTo).to.be.a('function');
    });

    describe('computeSecret', () => {
      const alice = new ECDH();
      const bob = new ECDH();
      let aliceShared = null;
      let bobShared = null;


      it('should return null if privateKey is null', () => {
        const tuBeNull = ecdhWithoutKeys.computeSecret();
        expect(tuBeNull).to.be.null;
      });

      it('should compute equal ECDH secrets buffers', () => {
        aliceShared = alice.computeSecret(bob.publicKeyBuffer);
        bobShared = bob.computeSecret(alice.publicKeyBuffer);
        expect(aliceShared).to.be.an.instanceof(Buffer);
        expect(bobShared).to.be.an.instanceof(Buffer);
        expect(aliceShared.toString('base64')).to.equal(bobShared.toString('base64'));
      });

      it('should compute equal ECDH secrets base64, 1/2', () => {
        aliceShared = alice.computeSecret(bob.publicKey, 'base64');
        bobShared = bob.computeSecret(alice.publicKey, 'base64');
        expect(aliceShared).to.be.an.instanceof(Buffer);
        expect(bobShared).to.be.an.instanceof(Buffer);
        expect(aliceShared.toString('base64')).to.equal(bobShared.toString('base64'));
      });

      it('should compute equal ECDH secrets base64, 2/2', () => {
        aliceShared = alice.computeSecret(bob.publicKey, 'base64', 'base64');
        bobShared = bob.computeSecret(alice.publicKey, 'base64', 'base64');
        expect(aliceShared).to.be.a('string');
        expect(bobShared).to.be.a('string');
        expect(aliceShared).to.equal(bobShared);
      });

      it('should not pass with invalid params', () => {
        expect(alice.computeSecret.bind(alice, 'invalidBuffer')).to.throw(Error);
        expect(alice.computeSecret.bind(alice, bob.publicKey, 'invalidEncoding')).to.throw(Error);
        expect(alice.computeSecret.bind(alice, bob.publicKey, 'base64', 'invalidEncoding')).to.throw(Error);
      });
    });

    describe('computeSecretAsync', () => {
      const alice = new ECDH();
      const bob = new ECDH();

      it('should return null if privateKey is null', (done) => {
        ecdhWithoutKeys
          .computeSecretAsync()
          .then((tuBeNull) => {
            expect(tuBeNull).to.be.null;
            done();
          })
          .catch((err) => {
            throw err;
          });
      });

      it('should compute equal ECDH secrets buffers', (done) => {
        let aliceShared = null;
        let bobShared = null;

        alice
          .computeSecretAsync(bob.publicKeyBuffer)
          .then((_aliceShared) => {
            aliceShared = _aliceShared;
            return bob.computeSecretAsync(alice.publicKeyBuffer);
          })
          .then((_bobShared) => {
            bobShared = _bobShared;

            expect(aliceShared).to.be.an.instanceof(Buffer);
            expect(bobShared).to.be.an.instanceof(Buffer);
            expect(aliceShared.toString('base64')).to.equal(bobShared.toString('base64'));
            done();
          })
          .catch((err) => {
            throw err;
          });
      });

      it('should compute equal ECDH secrets base64, 1/2', (done) => {
        let aliceShared = null;
        let bobShared = null;

        alice
          .computeSecretAsync(bob.publicKey, 'base64')
          .then((_aliceShared) => {
            aliceShared = _aliceShared;
            return bob.computeSecretAsync(alice.publicKey, 'base64');
          })
          .then((_bobShared) => {
            bobShared = _bobShared;

            expect(aliceShared).to.be.an.instanceof(Buffer);
            expect(bobShared).to.be.an.instanceof(Buffer);
            expect(aliceShared.toString('base64')).to.equal(bobShared.toString('base64'));
            done();
          })
          .catch((err) => {
            throw err;
          });
      });

      it('should compute equal ECDH secrets base64, 2/2', (done) => {
        let aliceShared = null;
        let bobShared = null;

        alice
          .computeSecretAsync(bob.publicKey, 'base64', 'base64')
          .then((_aliceShared) => {
            aliceShared = _aliceShared;
            return bob.computeSecretAsync(alice.publicKey, 'base64', 'base64');
          })
          .then((_bobShared) => {
            bobShared = _bobShared;

            expect(aliceShared).to.be.a('string');
            expect(bobShared).to.be.a('string');
            expect(aliceShared).to.equal(bobShared);
            done();
          })
          .catch((err) => {
            throw err;
          });
      });

      it('should not pass with invalid params, 1/3', (done) => {
        alice
          .computeSecretAsync('invalidBuffer')
          .then(() => {
            throw new Error();
          })
          .catch((err) => {
            expect(err).to.be.an('error');
            done();
          });
      });

      it('should not pass with invalid params, 2/3', (done) => {
        alice
          .computeSecretAsync(bob.publicKey, 'invalidEncoding')
          .then(() => {
            throw new Error();
          })
          .catch((err) => {
            expect(err).to.be.an('error');
            done();
          });
      });

      it('should not pass with invalid params, 3/3', (done) => {
        alice
          .computeSecretAsync(bob.publicKey, 'base64', 'invalidEncoding')
          .then(() => {
            throw new Error();
          })
          .catch((err) => {
            expect(err).to.be.an('error');
            done();
          });
      });
    });

    describe('publicKeyTo', () => {
      const ecdhWithKeyslocal = new ECDH();
      const ecdhWithoutKeysLocal = new ECDH(true);

      it('should return null if publicKey is null', () => {
        const tuBeNull = ecdhWithoutKeysLocal.publicKeyTo();
        expect(tuBeNull).to.be.null;
      });

      it('should return encoded string', () => {
        const str = ecdhWithKeyslocal.publicKeyTo();
        const str2 = ecdhWithKeyslocal.publicKeyTo('base64');
        const str3 = ecdhWithKeyslocal.publicKeyTo('hex');

        expect(str).to.be.a('string');
        expect(str2).to.be.a('string');
        expect(str3).to.be.a('string');
      });

      it('should not pass with invalid params', () => {
        expect(ecdhWithKeyslocal.publicKeyTo.bind(ecdhWithKeyslocal, 'invalidEncoding')).to.throw(Error);
      });
    });

    describe('privateKeyTo', () => {
      const ecdhWithKeyslocal = new ECDH();
      const ecdhWithoutKeysLocal = new ECDH(true);

      it('should return null if privateKey is null', () => {
        const tuBeNull = ecdhWithoutKeysLocal.privateKeyTo();
        expect(tuBeNull).to.be.null;
      });

      it('should return encoded string', () => {
        const str = ecdhWithKeyslocal.privateKeyTo();
        const str2 = ecdhWithKeyslocal.privateKeyTo('base64');
        const str3 = ecdhWithKeyslocal.privateKeyTo('hex');

        expect(str).to.be.a('string');
        expect(str2).to.be.a('string');
        expect(str3).to.be.a('string');
      });

      it('should not pass with invalid params', () => {
        expect(ecdhWithKeyslocal.privateKeyTo.bind(ecdhWithKeyslocal, 'invalidEncoding')).to.throw(Error);
      });
    });
  });

  describe('fromPrivateKey', () => {
    it('should exist', () => {
      expect(ECDH.fromPrivateKey).to.be.ok;
      expect(ECDH.fromPrivateKey).to.be.a('function');
    });

    it('should create new ECDH from privateKey base64', () => {
      const ecdh = ECDH.fromPrivateKey(privateKeyBase64);
      expect(ecdh).to.be.ok;
      expect(ecdh).to.be.an.instanceof(ECDH);

      const ecdh2 = ECDH.fromPrivateKey(privateKeyBase64, 'base64');
      expect(ecdh2).to.be.ok;
      expect(ecdh2).to.be.an.instanceof(ECDH);
    });

    it('should create new ECDH from privateKey Buffer', () => {
      const ecdh = ECDH.fromPrivateKey(privateKeyBuffer);
      expect(ecdh).to.be.ok;
      expect(ecdh).to.be.an.instanceof(ECDH);
    });

    it('should not pass with invalid params', () => {
      expect(ECDH.fromPrivateKey.bind(ECDH, 'invalidKey')).to.throw(Error);
      expect(ECDH.fromPrivateKey.bind(ECDH, privateKeyBase64, 'invalidEncoding')).to.throw(Error);
    });
  });

  describe('fromPrivateKeyAsync', () => {
    it('should exist', () => {
      expect(ECDH.fromPrivateKeyAsync).to.be.ok;
      expect(ECDH.fromPrivateKeyAsync).to.be.a('function');
    });

    it('should create new ECDH from privateKey base64, 1/2', (done) => {
      ECDH
        .fromPrivateKeyAsync(privateKeyBase64)
        .then((ecdh) => {
          expect(ecdh).to.be.ok;
          expect(ecdh).to.be.an.instanceof(ECDH);
          done();
        })
        .catch((e) => {
          throw e;
        });
    });

    it('should create new ECDH from privateKey base64, 2/2', (done) => {
      ECDH
        .fromPrivateKeyAsync(privateKeyBase64, 'base64')
        .then((ecdh) => {
          expect(ecdh).to.be.ok;
          expect(ecdh).to.be.an.instanceof(ECDH);
          done();
        })
        .catch((e) => {
          throw e;
        });
    });

    it('should create new ECDH from privateKey Buffer', (done) => {
      ECDH
        .fromPrivateKeyAsync(privateKeyBuffer)
        .then((ecdh) => {
          expect(ecdh).to.be.ok;
          expect(ecdh).to.be.an.instanceof(ECDH);
          done();
        })
        .catch((e) => {
          throw e;
        });
    });

    it('should not pass with invalid params, 1/2', (done) => {
      ECDH
        .fromPrivateKeyAsync('invalidKey')
        .then(() => {
          throw new Error();
        })
        .catch((err) => {
          expect(err).to.be.an('error');
          done();
        });
    });

    it('should not pass with invalid params, 2/2', (done) => {
      ECDH
        .fromPrivateKeyAsync(privateKeyBase64, 'invalidEncoding')
        .then(() => {
          throw new Error();
        })
        .catch((err) => {
          expect(err).to.be.an('error');
          done();
        });
    });
  });
});
