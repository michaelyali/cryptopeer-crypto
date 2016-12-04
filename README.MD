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

### ECDH with new keys

```js
let alice = new crypto.ECDH(),
    bob = new crypto.ECDH();

let aliceShared = alice.computeSecret(bob.publicKeyBuffer, 'base64'),
    bobShared = bob.computeSecret(alice.publicKeyBuffer, 'base64');

console.log(aliceShared === bobShared);
```

### ECDH from existing privateKey

```js
let alice = new crypto.ECDH(),
    mallory = crypto.ECDH.fromPrivateKey(alice.privateKey, 'base64');

console.log(alice.publicKey === mallory.publicKey);
```

### RSA

```js
let alice = new crypto.RSA(512),
    bob = new crypto.RSA(), // keyLength 512 is set to defalult
    message = 'Hello Bob!';

alice.setPublicKey(bob.publicKey);

let encrypted = alice.encrypt(message),
    decrypted = bob.decrypt(encrypted);

console.log(decrypted === message);
```

Method **encrypt** expects `String`, `Number`, `Object`, `Array`, `null` or can be empty.

### ChaCha20

```js
const ChaCha20 = crypto.ChaCha20;

let message = 'Super secret message',
    key = ChaCha20.getKey(),
    nonce = ChaCha20.getNonce();

let encrypted = ChaCha20.encrypt(message, nonce, key),
    decrypted = ChaCha20.decrypt(encrypted, nonce, key).toString('utf8');

console.log(decrypted === message);
```

### ChaCha20 with ECDH

```js
const ChaCha20 = crypto.ChaCha20,
      ECDH = crypto.ECDH;

let message = 'Hello Bob!';

let aliceSecret = alice.computeSecret(bob.publicKey),
    aliceKey = ChaCha20.getKey(aliceSecret),
    nonce = ChaCha20.getNonce();

let encrypted = ChaCha20.encrypt(message, nonce, aliceKey);

let bobSecret = bob.computeSecret(alice.publicKey),
    bobKey = ChaCha20.getKey(bobSecret);

let decrypted = ChaCha20.decrypt(encrypted, nonce, bobKey).toString('utf8');

console.log(decrypted === message);
```

Method **encrypt** expects `Buffer`, `String`.
Method **decrypt** expects `Buffer`, encoded `String`.

### With Promises

All methods has been promisified already. You can call them with `*Async` ending.
e.g. `alice.computeSecretAsync()`, `ChaCha20.encryptAsync()` and so on.

## TODO

- AES256 encrypt/decrypt

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
