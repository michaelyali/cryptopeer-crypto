[![Build Status](https://travis-ci.org/zMotivat0r/cryptopeer-crypto.svg?branch=master)](https://travis-ci.org/zMotivat0r/cryptopeer-crypto)

## Introduction

**cryptopeer-crypto** is an ECMA2015 (ES6) crypto library for Node.js built on top of [sodium](https://github.com/paixaop/node-sodium) and [node-rsa](https://github.com/rzcoder/node-rsa)

## Install

```sh
$ npm install cryptopeer-crypto
```

## Usage

```js
const crypto = require('cryptopeer-crypto');
```

### Ecdh with new keys

```js
let alice = new crypto.Ecdh(),
    bob = new crypto.Ecdh();

let aliceShared = alice.computeSecret(bob.publicKeyBuffer, 'base64'),
    bobShared = bob.computeSecret(alice.publicKeyBuffer, 'base64');

console.log(aliceShared === bobShared);
```

### Ecdh from existing privateKey

```js
let alice = new crypto.Ecdh(),
    mallory = crypto.Ecdh.fromPrivateKey(alice.privateKey, 'base64');

console.log(alice.publicKey === mallory.publicKey);
```

### Rsa

```js
let alice = new crypto.Rsa(512),
    bob = new crypto.Rsa(), // keyLength 512 is set to defalult
    plainText = 'Hello Bob!';

alice.setPublicKey(bob.publicKey);

let encrypted = alice.encrypt(plainText),
    decrypted = bob.decrypt(encrypted);

console.log(decrypted === plainText);
```

Method **encrypt** expects `String`, `Number`, `Object`, `Array`, `null` or can be empty.

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
