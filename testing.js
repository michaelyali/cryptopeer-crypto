'use strict';

const lib = require('./index'),
      ECDH = lib.ECDH,
      ChaCha20 = lib.ChaCha20;

let alice = new ECDH(),
    bob = new ECDH();

let aliceShared = alice.computeSecret(bob.publicKey),
    bobShared = bob.computeSecret(alice.publicKey);

let aliceKey = ChaCha20.getKey(aliceShared),
    bobKey = ChaCha20.getKey(bobShared);

let nonce = ChaCha20.getNonce();

let encrypted = ChaCha20.encrypt('Test message from Alice to Bob', nonce, aliceKey);
let decrypted = ChaCha20.decrypt(encrypted, nonce, bobKey).toString();

console.log(decrypted);