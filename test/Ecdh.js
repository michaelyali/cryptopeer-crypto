'use strict';

const chai = require('chai'),
      expect = chai.expect;

const lib = require('../lib'),
      Ecdh = lib.Ecdh;

describe('Ecdh', () => {

  let privateKeyBase64 = 'd05yp7dX+X9FW9KkiunJ+qSp8/RDrFpiQ02EasZre9E=',
      privateKeyBuffer = new Buffer(privateKeyBase64, 'base64');

  it('should exist', () => {
    expect(lib).to.exist;
    expect(Ecdh).to.exist;
    expect(Ecdh).to.be.a('function');
  });

  describe('new Ecdh', () => {
    
    let ecdhWithKeys = new Ecdh(),
        ecdhWithoutKeys = new Ecdh(true);
    
    it('should create with keys', () => {
      expect(ecdhWithKeys).to.be.ok;
      expect(ecdhWithKeys).to.be.an.instanceof(Ecdh);
    });

    it('should create without keys', () => {
      expect(ecdhWithoutKeys).to.be.ok;
      expect(ecdhWithoutKeys).to.be.an.instanceof(Ecdh);
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

    it('should have publicKeyTo', () => {
      expect(ecdhWithKeys).to.have.property('publicKeyTo');
      expect(ecdhWithoutKeys).to.have.property('publicKeyTo');
      expect(ecdhWithKeys.computeSecret).to.be.a('function');
      expect(ecdhWithoutKeys.computeSecret).to.be.a('function');
    });
    
    describe('computeSecret', () => {

      let alice = new Ecdh(),
          bob = new Ecdh(),
          aliceShared = null,
          bobShared = null;


      it('should return null if privateKey is null', () => {
        let tuBeNull = ecdhWithoutKeys.computeSecret();
        expect(tuBeNull).to.be.null;
      });

      it('should compute equal Ecdh secrets buffers', () => {
        aliceShared = alice.computeSecret(bob.publicKeyBuffer);
        bobShared = bob.computeSecret(alice.publicKeyBuffer);
        expect(aliceShared).to.be.an.instanceof(Buffer);
        expect(bobShared).to.be.an.instanceof(Buffer);
        expect(aliceShared.toString('base64')).to.equal(bobShared.toString('base64'));
      });

      it('should compute equal Ecdh secrets base64, 1/2', () =>{

        aliceShared = alice.computeSecret(bob.publicKey, 'base64');
        bobShared = bob.computeSecret(alice.publicKey, 'base64');
        expect(aliceShared).to.be.an.instanceof(Buffer);
        expect(bobShared).to.be.an.instanceof(Buffer);
        expect(aliceShared.toString('base64')).to.equal(bobShared.toString('base64'));
      });
      
      it('should compute equal Ecdh secrets base64, 2/2', () => {
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
    describe('publicKeyTo', () => {

      let ecdhWithKeys = new Ecdh(),
          ecdhWithoutKeys = new Ecdh(true);

      it('should return null if publicKey is null', () => {
        let tuBeNull = ecdhWithoutKeys.publicKeyTo();
        expect(tuBeNull).to.be.null;
      });

      it('should return encoded string', () => {
        let str = ecdhWithKeys.publicKeyTo();
        let str2 = ecdhWithKeys.publicKeyTo('base64');
        let str3 = ecdhWithKeys.publicKeyTo('hex');

        expect(str).to.be.a('string');
        expect(str2).to.be.a('string');
        expect(str3).to.be.a('string');
      });

      it('should not pass with invalid params', () => {
        expect(ecdhWithKeys.publicKeyTo.bind(ecdhWithKeys, 'invalidEncoding')).to.throw(Error);
      });
    });

    describe('privateKeyTo', () => {

      let ecdhWithKeys = new Ecdh(),
          ecdhWithoutKeys = new Ecdh(true);

      it('should return null if privateKey is null', () => {
        let tuBeNull = ecdhWithoutKeys.privateKeyTo();
        expect(tuBeNull).to.be.null;
      });

      it('should return encoded string', () => {
        let str = ecdhWithKeys.privateKeyTo();
        let str2 = ecdhWithKeys.privateKeyTo('base64');
        let str3 = ecdhWithKeys.privateKeyTo('hex');

        expect(str).to.be.a('string');
        expect(str2).to.be.a('string');
        expect(str3).to.be.a('string');
      });

      it('should not pass with invalid params', () => {
        expect(ecdhWithKeys.privateKeyTo.bind(ecdhWithKeys, 'invalidEncoding')).to.throw(Error);
      });
    });
  });

  describe('fromPrivateKey', () => {
    
    it('should exist', () => {
      expect(Ecdh.fromPrivateKey).to.be.ok;
      expect(Ecdh.fromPrivateKey).to.be.a('function');
    });
    
    it('should create new Ecdh from privateKey base64', () => {
      let ecdh = Ecdh.fromPrivateKey(privateKeyBase64);
      expect(ecdh).to.be.ok;
      expect(ecdh).to.be.an.instanceof(Ecdh);

      let ecdh2 = Ecdh.fromPrivateKey(privateKeyBase64, 'base64');
      expect(ecdh2).to.be.ok;
      expect(ecdh2).to.be.an.instanceof(Ecdh);
    });
    
    it('should create new Ecdh from privateKey Buffer', () => {
      let ecdh = Ecdh.fromPrivateKey(privateKeyBuffer);
      expect(ecdh).to.be.ok;
      expect(ecdh).to.be.an.instanceof(Ecdh);
    });
    
    it('should not pass with invalid params', () => {
      expect(Ecdh.fromPrivateKey.bind(Ecdh, 'invalidKey')).to.throw(Error);
      expect(Ecdh.fromPrivateKey.bind(Ecdh, privateKeyBase64, 'invalidEncoding')).to.throw(Error);
    });
  });
});