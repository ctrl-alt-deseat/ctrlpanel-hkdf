type Digest = 'SHA-256' | 'SHA-384' | 'SHA-512'
declare function hkdf (salt: ArrayBuffer | Uint8Array, input: ArrayBuffer | Uint8Array, info: ArrayBuffer | Uint8Array, keylen: number, digest: Digest): Promise<ArrayBuffer>

export = hkdf
