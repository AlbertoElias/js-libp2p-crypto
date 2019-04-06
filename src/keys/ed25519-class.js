'use strict'

const multihashing = require('multihashing-async')
const protobuf = require('protons')
const bs58 = require('bs58')
const nextTick = require('async/nextTick')

const crypto = require('./ed25519')
const pbm = protobuf(require('./keys.proto'))
const keyComposer = require('crypto-key-composer')
const randomBytes = require('../random-bytes')

class Ed25519PublicKey {
  constructor (key) {
    this._key = ensureKey(key, crypto.publicKeyLength)
  }

  verify (data, sig, callback) {
    ensure(callback)
    crypto.hashAndVerify(this._key, sig, data, callback)
  }

  marshal () {
    return Buffer.from(this._key)
  }

  get bytes () {
    return pbm.PublicKey.encode({
      Type: pbm.KeyType.Ed25519,
      Data: this.marshal()
    })
  }

  equals (key) {
    return this.bytes.equals(key.bytes)
  }

  hash (callback) {
    ensure(callback)
    multihashing(this.bytes, 'sha2-256', callback)
  }
}

class Ed25519PrivateKey {
  // key       - 64 byte Uint8Array or Buffer containing private key
  // publicKey - 32 byte Uint8Array or Buffer containing public key
  // seed      - 32 byte Uint8Array or Buffer containing the __optional__ seed
  constructor (key, publicKey, seed) {
    this._key = ensureKey(key, crypto.privateKeyLength)
    this._publicKey = ensureKey(publicKey, crypto.publicKeyLength)
    this._seed = ensureKey(seed, 32)
  }

  sign (message, callback) {
    ensure(callback)
    crypto.hashAndSign(this._key, message, callback)
  }

  get public () {
    if (!this._publicKey) {
      throw new Error('public key not provided')
    }

    return new Ed25519PublicKey(this._publicKey)
  }

  marshal () {
    return Buffer.concat([Buffer.from(this._key), Buffer.from(this._publicKey)])
  }

  get bytes () {
    return pbm.PrivateKey.encode({
      Type: pbm.KeyType.Ed25519,
      Data: this.marshal()
    })
  }

  equals (key) {
    return this.bytes.equals(key.bytes)
  }

  hash (callback) {
    ensure(callback)
    multihashing(this.bytes, 'sha2-256', callback)
  }

  /**
   * Gets the ID of the key.
   *
   * The key id is the base58 encoding of the SHA-256 multihash of its public key.
   * The public key is a protobuf encoding containing a type and the DER encoding
   * of the PKCS SubjectPublicKeyInfo.
   *
   * @param {function(Error, id)} callback
   * @returns {undefined}
   */
  id (callback) {
    this.public.hash((err, hash) => {
      if (err) {
        return callback(err)
      }
      callback(null, bs58.encode(hash))
    })
  }

  /**
   * Exports the key into a password protected PEM format
   *
   * @param {string} [format] - Defaults to 'pkcs-8'.
   * @param {string} password - The password to read the encrypted PEM
   * @param {function(Error, KeyInfo)} callback
   * @returns {undefined}
   */
  export (format, password, callback) {
    if (typeof password === 'function') {
      callback = password
      password = format
      format = 'pkcs-8'
    }

    ensure(callback)

    nextTick(() => {
      let err = null
      let pem = null
      try {
        if (format === 'pkcs-8') {
          pem = keyComposer.composePrivateKey({
            format: 'pkcs8-pem',
            keyAlgorithm: {
              id: 'ed25519'
            },
            keyData: {
              seed: this._seed
            },
            encryptionAlgorithm: {
              keyDerivationFunc: {
                id: 'pbkdf2',
                iterationCount: 10000,  // The number of iterations
                keyLength: 32, // Automatic, based on the `encryptionScheme`
                prf: 'hmac-with-sha512'  // The pseudo-random function
              },
              encryptionScheme: {
                id: 'aes256-cbc'
              }
            }
          }, {password})
        } else {
          err = new Error(`Unknown export format '${format}'`)
        }
      } catch (_err) {
        err = _err
      }

      // Leaving the RSA example here
      // try {
      //   const buffer = new forge.util.ByteBuffer(this.marshal())
      //   const asn1 = forge.asn1.fromDer(buffer)
      //   const privateKey = forge.pki.privateKeyFromAsn1(asn1)
      //   if (format === 'pkcs-8') {
      //     const options = {
      //       algorithm: 'aes256',
      //       count: 10000,
      //       saltSize: 128 / 8,
      //       prfAlgorithm: 'sha512'
      //     }
      //     pem = forge.pki.encryptRsaPrivateKey(privateKey, password, options)
      //   } else {
      //     err = new Error(`Unknown export format '${format}'`)
      //   }
      // } catch (_err) {
      //   err = _err
      // }

      callback(err, pem)
    })
  }
}

function unmarshalEd25519PrivateKey (bytes, callback) {
  try {
    bytes = ensureKey(bytes, crypto.privateKeyLength + crypto.publicKeyLength)
  } catch (err) {
    return callback(err)
  }
  const privateKeyBytes = bytes.slice(0, crypto.privateKeyLength)
  const publicKeyBytes = bytes.slice(crypto.privateKeyLength, bytes.length)
  callback(null, new Ed25519PrivateKey(privateKeyBytes, publicKeyBytes))
}

function unmarshalEd25519PublicKey (bytes) {
  bytes = ensureKey(bytes, crypto.publicKeyLength)
  return new Ed25519PublicKey(bytes)
}

function generateKeyPair (_bits, cb) {
  if (cb === undefined && typeof _bits === 'function') {
    cb = _bits
  }

  const seed = randomBytes(32)

  return generateKeyPairFromSeed(seed, _bits, cb)
}

function generateKeyPairFromSeed (seed, _bits, cb) {
  if (cb === undefined && typeof _bits === 'function') {
    cb = _bits
  }

  crypto.generateKeyFromSeed(seed, (err, keys) => {
    if (err) {
      return cb(err)
    }
    let privkey
    try {
      privkey = new Ed25519PrivateKey(keys.secretKey, keys.publicKey, seed)
    } catch (err) {
      cb(err)
      return
    }

    cb(null, privkey)
  })
}

function importPEM (pem, password, callback) {

}

function ensure (cb) {
  if (typeof cb !== 'function') {
    throw new Error('callback is required')
  }
}

function ensureKey (key, length) {
  if (Buffer.isBuffer(key)) {
    key = new Uint8Array(key)
  }
  if (!(key instanceof Uint8Array) || key.length !== length) {
    throw new Error('Key must be a Uint8Array or Buffer of length ' + length)
  }
  return key
}

module.exports = {
  Ed25519PublicKey,
  Ed25519PrivateKey,
  unmarshalEd25519PrivateKey,
  unmarshalEd25519PublicKey,
  generateKeyPair,
  generateKeyPairFromSeed,
  import: importPEM
}
