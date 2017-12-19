const crypto = require('crypto')

function isArrayBufferOrTypedArray (input) {
  return (typeof input.byteLength === 'number' && typeof input.slice === 'function')
}

function hmac (hash, key, input) {
  return crypto.createHmac(hash, key).update(input).digest()
}

const hashLengths = {
  sha256: 32,
  sha384: 48,
  sha512: 64
}

module.exports = function hkdf (salt, input, info, keylen, digest) {
  if (!isArrayBufferOrTypedArray(salt)) throw new TypeError('Expected "salt" to be an ArrayBuffer, Uint8Array or Buffer')
  if (!isArrayBufferOrTypedArray(input)) throw new TypeError('Expected "input" to be an ArrayBuffer, Uint8Array or Buffer')
  if (!isArrayBufferOrTypedArray(info)) throw new TypeError('Expected "info" to be an ArrayBuffer, Uint8Array or Buffer')
  if (digest !== 'SHA-256' && digest !== 'SHA-384' && digest !== 'SHA-512') throw new TypeError('Expected "digest" to be one of "SHA-256", "SHA-384" or "SHA-512"')

  salt = Buffer.from(salt)
  input = Buffer.from(input)
  info = Buffer.from(info)
  digest = digest.replace('SHA-', 'sha')

  const hashLength = hashLengths[digest]
  const iterations = Math.ceil(keylen / hashLength)

  if (iterations > 0xff) {
    throw new RangeError('Key length "keylen" exceeds maximum key length for this "digest" parameter')
  }

  return Promise.resolve().then(function () {
    const prk = hmac(digest, salt, input)
    const parts = [Buffer.from('')]

    for (let i = 0; i < iterations; i++) {
      parts.push(hmac(digest, prk, Buffer.concat([parts[i], info, Buffer.from([i + 1])])))
    }

    const result = Buffer.concat(parts).slice(0, keylen)

    return result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength)
  })
}
