import resolve from 'did-resolver'
import register from '../register'
import DidDocument from 'ipfs-did-document'
import base64url from 'base64url'
import { SimpleSigner } from 'did-jwt'
import SignerAlgorithm from 'did-jwt/lib/SignerAlgorithm'
import IPFS from 'ipfs'

const PRIV_KEY = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const PUB_KEY = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'


describe('3ID Resolver', () => {
  let ipfs, ipfsd

  beforeAll(async () => {
    ipfs = await initIPFS()
    register(ipfs)
  })

  afterAll(async () => {
    await ipfs.stop()
  })

  describe('resolve 3ID', () => {
    let rootCid

    describe('root 3ID', async () => {
      let doc

      beforeEach(async () => {
        doc = new DidDocument(ipfs, '3')
      })

      it('throws on invalid document', async () => {
        doc.addPublicKey('signingKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', 'not a pub key')
        await doc.commit({ noTimestamp: true })
        await expect(resolve(doc.DID)).rejects.toEqual(new Error('Invalid 3ID'))
      })

      it('resolves valid document', async () => {
        doc.addPublicKey('signingKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', PUB_KEY)
        doc.addPublicKey('encryptionKey', 'Curve25519EncryptionPublicKey', 'publicKeyBase64', 'fake encryptionKey')
        doc.addPublicKey('managementKey', 'Secp256k1VerificationKey2018', 'ethereumAddress', 'fake eth addr')
        doc.addAuthentication('Secp256k1SignatureAuthentication2018', 'signingKey')
        const cid = await doc.commit({ noTimestamp: true })
        const rawDoc = await DidDocument.cidToDocument(ipfs, cid)
        await expect(resolve(doc.DID)).resolves.toEqual(rawDoc)
        rootCid = cid
      })
    })

    describe('sub 3ID', () => {
      let doc

      beforeEach(async () => {
        doc = new DidDocument(ipfs, '3')
      })

      it('throws on invalid proof', async () => {
        doc.addPublicKey('subSigningKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', 'fake subSigningKey')
        doc.addPublicKey('subEncryptionKey', 'Curve25519EncryptionPublicKey', 'publicKeyBase64', 'fake subEncryptionKey')
        doc.addAuthentication('Secp256k1SignatureAuthentication2018', 'subSigningKey')
        doc.addCustomProperty('space', 'a space name')
        doc.addCustomProperty('root', rootCid)
        const signature = base64url.encode('obviously invalid signature')
        doc.addCustomProperty('proof', { alg: 'ES256K', signature })
        await doc.commit({ noTimestamp: true })

        await expect(resolve(doc.DID)).rejects.toEqual(new Error('Invalid 3ID'))
      })

      it('resolves on valid sub document', async () => {
        doc.addPublicKey('subSigningKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', 'fake subSigningKey')
        doc.addPublicKey('subEncryptionKey', 'Curve25519EncryptionPublicKey', 'publicKeyBase64', 'fake subEncryptionKey')
        doc.addAuthentication('Secp256k1SignatureAuthentication2018', 'subSigningKey')
        doc.addCustomProperty('space', 'a space name')
        doc.addCustomProperty('root', rootCid)
        const dataToSign = `fake subSigningKeyfake subEncryptionKeya space name${rootCid}`
        const signer = new SimpleSigner(PRIV_KEY)
        const sign = data => SignerAlgorithm('ES256K')(data, signer)
        const signature = await sign(dataToSign)
        doc.addCustomProperty('proof', { alg: 'ES256K', signature })
        await doc.commit({ noTimestamp: true })

        await expect(resolve(doc.DID)).resolves.toMatchSnapshot()
      })
    })
  })
})

const initIPFS = async () => {
  return new Promise((resolve, reject) => {
    let ipfs = new IPFS({
      repo: './.ipfs',
      config: { Addresses: {}, Discovery: {}, Bootstrap: [] }
    })
    ipfs.on('error', reject)
    ipfs.on('ready', () => resolve(ipfs))
  })
}

      //const pubkeys = this._keyrings[spaceName].getPublicKeys()
    //}
