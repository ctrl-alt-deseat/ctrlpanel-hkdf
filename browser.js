/* global crypto */

function isArrayBufferOrTypedArray (input) {
  return (typeof input.byteLength === 'number' && typeof input.slice === 'function')
}

function isTypedArray (input) {
  return (typeof input.byteOffset === 'number' && typeof input.buffer === 'object')
}

module.exports = function hkdf (salt, input, info, keylen, digest) {
  if (!isArrayBufferOrTypedArray(salt)) throw new TypeError('Expected "salt" to be an ArrayBuffer, Uint8Array or Buffer')
  if (!isArrayBufferOrTypedArray(input)) throw new TypeError('Expected "input" to be an ArrayBuffer, Uint8Array or Buffer')
  if (!isArrayBufferOrTypedArray(info)) throw new TypeError('Expected "info" to be an ArrayBuffer, Uint8Array or Buffer')
  if (digest !== 'SHA-256' && digest !== 'SHA-384' && digest !== 'SHA-512') throw new TypeError('Expected "digest" to be one of "SHA-256", "SHA-384" or "SHA-512"')

  if (isTypedArray(salt)) salt = salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength)
  if (isTypedArray(input)) input = input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength)
  if (isTypedArray(info)) info = info.buffer.slice(info.byteOffset, info.byteOffset + info.byteLength)

  return Promise.resolve()
    .then(() => crypto.subtle.importKey('raw', input, { name: 'HKDF' }, false, ['deriveBits']))
    .then(key => crypto.subtle.deriveBits({ name: 'HKDF', salt, info, hash: digest }, key, keylen << 3))
}
