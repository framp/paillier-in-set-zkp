## paillier-in-set-zkp

Encrypt a value and generates a Zero Knowledge Proof that can be used to verify that the encrypted value is inside a set of known values.

Based on [this paper](https://paillier.daylightingsociety.org/Paillier_Zero_Knowledge_Proof.pdf).

### Installation
```
npm i paillier-in-set-zkp --save
```

### Usage

```
const { encryptWithProof, verifyProof } = require('paillier-in-set-zkp')
const paillier = require('paillier-js')

const bits = 512

const {publicKey, privateKey} = paillier.generateRandomKeys(bits)
const validScores = [0,15,30,60]
const secretScore = 30

const [cipher, proof] = encryptWithProof(publicKey, secretScore, validScores, bits)

// Transmit cipher, proof and publicKey

const result = verifyProof(publicKey, cipher, proof, validScores, bits) // true
```

### Contributions

Bug reports highly appreciated

PRs super welcome

### Tests
Tests live in the index file in the shape of a bunch of asserts.

Tests get removed automatically at `postinstall` using `sed`.

### License
MIT
