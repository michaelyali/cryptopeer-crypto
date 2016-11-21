'use strict';

const chai = require('chai'),
      expect = chai.expect;

const lib = require('../lib'),
      Rsa = lib.Rsa;

describe('Rsa', () => {

  it('should exist', () => {
    expect(lib).to.exist;
    expect(Rsa).to.exist;
    expect(Rsa).to.be.a('function');
  });
  
  describe('new Rsa', () => {
    
  });
});