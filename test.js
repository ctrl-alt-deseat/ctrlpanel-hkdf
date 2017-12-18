/* eslint-env mocha */

const assert = require('assert')

const arrayBufferToHex = require('array-buffer-to-hex')
const hexToArrayBuffer = require('hex-to-array-buffer')

const hkdf = require('./')

describe('hkdf', () => {
  it('Appendix A. Test Case 1', () => {
    const input = hexToArrayBuffer('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
    const salt = hexToArrayBuffer('000102030405060708090a0b0c')
    const info = hexToArrayBuffer('f0f1f2f3f4f5f6f7f8f9')
    const expected = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'

    return hkdf(salt, input, info, 42, 'SHA-256').then((actual) => {
      assert.strictEqual(arrayBufferToHex(actual), expected)
    })
  })

  it('Appendix A. Test Case 2', () => {
    const input = hexToArrayBuffer('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f')
    const salt = hexToArrayBuffer('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')
    const info = hexToArrayBuffer('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    const expected = 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'

    return hkdf(salt, input, info, 82, 'SHA-256').then((actual) => {
      assert.strictEqual(arrayBufferToHex(actual), expected)
    })
  })

  it('Appendix A. Test Case 3', () => {
    const input = hexToArrayBuffer('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
    const salt = hexToArrayBuffer('')
    const info = hexToArrayBuffer('')
    const expected = '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'

    return hkdf(salt, input, info, 42, 'SHA-256').then((actual) => {
      assert.strictEqual(arrayBufferToHex(actual), expected)
    })
  })

  it('SHA-256', () => {
    const input = hexToArrayBuffer('0b0c0d0e0f101112')
    const salt = hexToArrayBuffer('15161718191a1b1c')
    const info = hexToArrayBuffer('1f20212223242526')
    const expected = 'be7775069fd8d8619494618c4c93af71b66a33230d83a1e18620e9c66410507189bf080640456d0f91575ae4ffc0b2e636ecc4168031a6183ede03bed99d8ce8273632'

    return hkdf(salt, input, info, 67, 'SHA-256').then((actual) => {
      assert.strictEqual(arrayBufferToHex(actual), expected)
    })
  })

  it('SHA-384', () => {
    const input = hexToArrayBuffer('0b0c0d0e0f101112')
    const salt = hexToArrayBuffer('15161718191a1b1c')
    const info = hexToArrayBuffer('1f20212223242526')
    const expected = 'deff2a4f344fa4ed14f5fa7a7558136b2a2a100df7c2645ab7688f7b0428a96f66c9942d5d9b6311be26cad007d29c3774'

    return hkdf(salt, input, info, 49, 'SHA-384').then((actual) => {
      assert.strictEqual(arrayBufferToHex(actual), expected)
    })
  })

  it('SHA-512', () => {
    const input = hexToArrayBuffer('0b0c0d0e0f101112')
    const salt = hexToArrayBuffer('15161718191a1b1c')
    const info = hexToArrayBuffer('1f20212223242526')
    const expected = '19a1a1e86990f83d1c68b8f030a794d8b96cd4da105aac0247d3e811140ca45f'

    return hkdf(salt, input, info, 32, 'SHA-512').then((actual) => {
      assert.strictEqual(arrayBufferToHex(actual), expected)
    })
  })
})
