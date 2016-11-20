[![Build Status](https://travis-ci.org/zMotivat0r/cryptopeer-crypto.svg?branch=develop)](https://travis-ci.org/zMotivat0r/cryptopeer-crypto)

## Introduction

CryptoPeer-Crypto is a crypto library for Node.js built on top of [sodium](https://github.com/paixaop/node-sodium) and [node-rsa](https://github.com/rzcoder/node-rsa)

## Install

```sh
$ npm install cryptopeer-crypto
```

## Usage

#### ECDH

##### With new `privateKey` and `publicKey`

```js
const crypto = require('cryptopeer-crypto');

let alice = new crypto.ECDH();
let bob = new crypto.ECDH();

let aliceShared = alice.computeSecret(bob.publicKey, 'base64');
let bobShared = bob.computeSecret(alice.publicKey, 'base64');

console.log(aliceShared.toString('base64') === bobShared.toString('base64'));

aliceShared = alice.computeSecret(bob.publicKeyBuffer);
bobShared = bob.computeSecret(alice.publicKeyBuffer);

console.log(aliceShared.toString('base64') === bobShared.toString('base64'));

aliceShared = alice.computeSecret(bob.publicKeyBuffer, 'base64');
bobShared = bob.computeSecret(alice.publicKeyBuffer, 'base64');

console.log(aliceShared === bobShared);
```

##### From existing `privateKey`

```js
const crypto = require('cryptopeer-crypto');

let alice = new crypto.ECDH();

let mallory = crypto.ECDH.fromPrivateKey(alice.privateKey, 'base64');

console.log(alice.publicKey === mallory.publicKey);

mallory = crypto.ECDH.fromPrivateKey(alice.privateKeyBuffer);

console.log(alice.publicKey === mallory.publicKey);
```

## TODO

- AES256 encrypt/decrypt
- ChaCha20 encrypt/decrypt
- RSA encrypt/decrypt

## Test

```sh
npm test
```

## Thanks

Thanks to [ecdh-sodium](https://github.com/kwolfy/ecdh-sodium) for inspiration.

## License

The MIT License (MIT)

Copyright (c) 2016 Michael Yali

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
