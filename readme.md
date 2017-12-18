# HKDF for Node.js and Browsers

Small package exporting a HKDF function that works both in Node.js and in browsers.

## Installation

```sh
npm install --save @ctrlpanel/hkdf
```

## Usage

```js
const hkdf = require('@ctrlpanel/hkdf')

const salt = Buffer.from('salt')
const password = Buffer.from('super secret')
const info = Buffer.from('@ctrlpanel/hkdf')

hkdf(salt, password, info, 32, 'SHA-512').then((result) => {
  console.log(result)
  //=> ArrayBuffer { byteLength: 32 }
})
```

## API

### `hkdf(salt, input, info, keylen, digest) => ArrayBuffer`

- salt: `ArrayBuffer | Uint8Array | Buffer` - The salt used when deriving, a non-secret random value
- input: `ArrayBuffer | Uint8Array | Buffer` - The input key material to base the derivation on
- info: `ArrayBuffer | Uint8Array | Buffer` - Context and application specific information
- keylen: `number` - Byte length of output key
- digest: `'SHA-256' | 'SHA-384' | 'SHA-512'` - Hash algorithm to use

Derive a key from `input`, and return it as an `ArrayBuffer`.
