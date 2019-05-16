import VerifierAlgorithm from 'did-jwt/lib/VerifierAlgorithm'
import DidDocument from 'ipfs-did-document'
import { registerMethod } from 'did-resolver'

const PUBKEY_IDS = ['signingKey', 'managementKey', 'encryptionKey']
const SUB_PUBKEY_IDS = ['subSigningKey', 'subEncryptionKey']

function register (ipfs, opts = {}) {
  registerMethod('3', (_, { id }) => resolve(ipfs, id))
}

async function resolve (ipfs, cid, isRoot) {
  let doc
  try {
    doc = await DidDocument.cidToDocument(ipfs, cid)
    validateDoc(doc)
    if (doc.root) {
      if (isRoot) throw new Error('Only one layer subDoc allowed')
      const rootDoc = await resolve(ipfs, doc.root, true)
      verifyProof(rootDoc, doc)
      doc = mergeDocuments(rootDoc, doc)
    }
  } catch (e) {
    try {
      await ipfs.pin.rm(cid)
    } catch (e) {}
    throw new Error('Invalid 3ID')
  }
  return doc
}

function validateDoc (doc) {
  let pubKeyIds = PUBKEY_IDS
  if (!doc || !doc.publicKeys || !doc.authentication) {
    throw new Error('Not a valid 3ID')
  }
  if (doc.root) {
    pubKeyIds = SUB_PUBKEY_IDS
    if (!doc.space) throw new Error('Not a valid 3ID')
  }
  doc.publicKeys.map(entry => {
    const id = entry.id.split('#')[1]
    if (!pubKeyIds.includes(id)) throw new Error('Not a valid 3ID')
  })
}

function verifyProof (rootDoc, subDoc) {
  const signingKey = subDoc.publicKeys.find(entry => entry.id.includes(SUB_PUBKEY_IDS[0])).publicKeyHex
  const encryptionKey = subDoc.publicKeys.find(entry => entry.id.includes(SUB_PUBKEY_IDS[1])).publicKeyBase64
  const data = `${signingKey}${encryptionKey}${subDoc.space}${subDoc.root}`
  const verify = VerifierAlgorithm(subDoc.proof.alg)
  verify(data, subDoc.proof.signature, rootDoc.publicKeys)
}

function mergeDocuments (doc, subDoc) {
  subDoc.publicKeys = doc.publicKeys.concat(subDoc.publicKeys)
  subDoc.authentication = doc.authentication.concat(subDoc.authentication)
  return subDoc
}

module.exports = register
