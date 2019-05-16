# 3ID Resolver

This library is intended to resolve 3ID DID documents. 3ID is a thin identity protocol that uses ipfs and ethereum to publish and rotate the cryptographic keys used by an identity.

It supports the proposed [Decentralized Identifiers](https://w3c-ccg.github.io/did-spec/) spec from the [W3C Credentials Community Group](https://w3c-ccg.github.io).

It requires the `did-resolver` library, which is the primary interface for resolving DIDs.

## Resolving a DID document

The resolver presents a simple `resolver()` function that returns a ES6 Promise returning the DID document.

```js
import resolve from 'did-resolver'
import registerResolver from '3id-resolver'

registerResolver(ipfs)

resolve('did:3:QmRhjfL4HLdB8LovGf1o43NJ8QnbfqmpdnTuBvZTewnuBV').then(doc => console.log)

// You can also use ES7 async/await syntax
const doc = await resolve('did:muport:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf')
```
Result:
```js
{
  '@context': 'https://w3id.org/did/v1',
  id: 'did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf',
  publicKeys: [ {
    id: 'did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#signingKey',
    type: 'Secp256k1VerificationKey2018',
    publicKeyHex: '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
  }, {
    id: 'did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#encryptionKey',
    type: 'Curve25519EncryptionPublicKey',
    publicKeyBase64: 'fake encryptionKey'
  }, {
    id: 'did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#managementKey',
    type: 'Secp256k1VerificationKey2018',
    ethereumAddress: 'fake eth addr'
  }],
  authentication: [{
    type: 'Secp256k1SignatureAuthentication2018',
    publicKey: 'did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#signingKey'
  }]
}
```

