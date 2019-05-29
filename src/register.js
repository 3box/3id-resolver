import { verifyJWT } from 'did-jwt'
import DidDocument from 'ipfs-did-document'
import base64url from 'base64url'
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
      const rootDoc = await resolve(ipfs, doc.root.split(':')[2], true)
      await verifyProof(doc)
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
  if (!doc || !doc.publicKey || !doc.authentication) {
    throw new Error('Not a valid 3ID')
  }
  if (doc.root) {
    pubKeyIds = SUB_PUBKEY_IDS
    if (!doc.space) throw new Error('Not a valid 3ID')
  }
  doc.publicKey.map(entry => {
    const id = entry.id.split('#')[1]
    if (!pubKeyIds.includes(id)) throw new Error('Not a valid 3ID')
  })
}

function encodeSection (data) {
  return base64url.encode(JSON.stringify(data))
}

async function verifyProof (subDoc) {
  const subSigningKey = subDoc.publicKey.find(entry => entry.id.includes(SUB_PUBKEY_IDS[0])).publicKeyHex
  const subEncryptionKey = subDoc.publicKey.find(entry => entry.id.includes(SUB_PUBKEY_IDS[1])).publicKeyBase64
  const payload = encodeSection({
    iat: null,
    subSigningKey,
    subEncryptionKey,
    space: subDoc.space,
    iss: subDoc.root
  })
  const header = encodeSection({ typ: 'JWT', alg: subDoc.proof.alg })
  const jwt = `${header}.${payload}.${subDoc.proof.signature}`
  await verifyJWT(jwt)
}

function mergeDocuments (doc, subDoc) {
  subDoc.publicKey = doc.publicKey.concat(subDoc.publicKey)
  return subDoc
}

module.exports = register
