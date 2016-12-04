'use strict';

module.exports = require('./lib');

const ECDH = require('./lib').ECDH;

let alice = new ECDH(),
    bob = new ECDH;