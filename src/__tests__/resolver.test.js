import { Resolver } from 'did-resolver'
import base64url from 'base64url'
import { getResolver } from '../resolver'
import DidDocument from 'ipfs-did-document'
import { SimpleSigner, createJWT } from 'did-jwt'
import IPFS from 'ipfs'

const PRIV_KEY = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const PUB_KEY = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'

describe('3ID Resolver', () => {
  let ipfs, resolver

  beforeAll(async () => {
    ipfs = await IPFS.create({
      repo: './.ipfs',
      config: { Addresses: {}, Discovery: {}, Bootstrap: [] }
    })
  })

  beforeEach(() => {
    const threeIdResolver = getResolver(ipfs)
    resolver = new Resolver(threeIdResolver)
  })

  afterAll(async () => {
    await ipfs.stop()
  })

  describe('resolve 3ID', () => {
    let rootDID, rootCID

    describe('root 3ID', async () => {
      let doc

      beforeEach(async () => {
        doc = new DidDocument(ipfs, '3')
      })

      it('throws on invalid document', async () => {
        doc.addPublicKey('signingKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', 'not a pub key')
        await doc.commit({ noTimestamp: true })
        await expect(resolver.resolve(doc.DID)).rejects.toEqual(new Error('Invalid 3ID'))
      })

      it('resolves valid document', async () => {
        doc.addPublicKey('signingKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', PUB_KEY)
        doc.addPublicKey('encryptionKey', 'Curve25519EncryptionPublicKey', 'publicKeyBase64', 'fake encryptionKey')
        doc.addPublicKey('managementKey', 'Secp256k1VerificationKey2018', 'ethereumAddress', 'fake eth addr')
        doc.addAuthentication('Secp256k1SignatureAuthentication2018', 'signingKey')
        const cid = await doc.commit({ noTimestamp: true })
        const rawDoc = await DidDocument.cidToDocument(ipfs, cid)
        await expect(resolver.resolve(doc.DID)).resolves.toEqual(rawDoc)
        rootDID = doc.DID
        rootCID = cid
        await expect(ipfs.pin.ls(cid).next()).rejects.toMatchSnapshot()
      })

      it('should pin DID document if option given', async () => {
        const threeIdResolverPin = getResolver(ipfs, { pin: true })
        const resolver2 = new Resolver(threeIdResolverPin)
        await resolver2.resolve(rootDID)
        const pinnedCid = (await ipfs.pin.ls(rootCID).next()).value.cid
        expect(pinnedCid.toString()).toEqual(rootCID.toString())
        await ipfs.pin.rm(rootCID)
      })
    })

    describe('sub 3ID', () => {
      let doc, subDID, subCID

      beforeEach(async () => {
        doc = new DidDocument(ipfs, '3')
      })

      it('throws on invalid proof', async () => {
        doc.addPublicKey('subSigningKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', 'fake subSigningKey')
        doc.addPublicKey('subEncryptionKey', 'Curve25519EncryptionPublicKey', 'publicKeyBase64', 'fake subEncryptionKey')
        doc.addAuthentication('Secp256k1SignatureAuthentication2018', 'subSigningKey')
        doc.addCustomProperty('space', 'a space name')
        doc.addCustomProperty('root', rootDID)
        const signature = base64url.encode('obviously invalid signature')
        doc.addCustomProperty('proof', { alg: 'ES256K', signature })
        await doc.commit({ noTimestamp: true })

        await expect(resolver.resolve(doc.DID)).rejects.toEqual(new Error('Invalid 3ID'))
      })

      it('resolves on valid sub document', async () => {
        const subSigningKey = 'fake subSigningKey'
        const subEncryptionKey = 'fake subEncryptionKey'
        const space = 'a space name'
        doc.addPublicKey('subSigningKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', subSigningKey)
        doc.addPublicKey('subEncryptionKey', 'Curve25519EncryptionPublicKey', 'publicKeyBase64', subEncryptionKey)
        doc.addAuthentication('Secp256k1SignatureAuthentication2018', 'subSigningKey')
        doc.addCustomProperty('space', space)
        doc.addCustomProperty('root', rootDID)
        const payload = {
          subSigningKey,
          subEncryptionKey,
          space,
          iat: null
        }
        const signer = new SimpleSigner(PRIV_KEY)
        const jwt = await createJWT(payload, {
          issuer: rootDID,
          signer,
          alg: 'ES256K'
        })
        const signature = jwt.split('.')[2]
        doc.addCustomProperty('proof', { alg: 'ES256K', signature })
        const cid = await doc.commit({ noTimestamp: true })
        subDID = doc.DID
        subCID = cid

        await expect(resolver.resolve(doc.DID)).resolves.toMatchSnapshot()
        await expect(ipfs.pin.ls(cid).next()).rejects.toMatchSnapshot()
      })

      it('should pin DID document if option given', async () => {
        const threeIdResolverPin = getResolver(ipfs, { pin: true })
        const resolver2 = new Resolver(threeIdResolverPin)
        await resolver2.resolve(subDID)
        const pinnedCid1 = (await ipfs.pin.ls(rootCID).next()).value.cid
        expect(pinnedCid1.toString()).toEqual(rootCID.toString())
        const pinnedCid2 = (await ipfs.pin.ls(subCID).next()).value.cid
        expect(pinnedCid2.toString()).toEqual(subCID.toString())
      })
    })
  })
})
