/**
 * Node-side SHA3-256 with a pure-JS fallback.
 *
 * Real Node links OpenSSL, which provides "sha3-256". The dsh desktop host
 * runs inside Electron (BoringSSL), where `createHash('sha3-256')` throws
 * "Digest method not supported"; there every digest falls back to the pure-JS
 * Keccak shared with the browser half, so fingerprints, verifiers and the
 * shipped-file integrity check keep working instead of failing the import.
 * The capability is probed once at module load; both paths are byte-identical.
 * @module dsh-encrypt/infrastructure/crypto/sha3
 */
import { createHash } from 'node:crypto'
import { keccakSha3_256 } from '../../shared/crypto/keccak.js'

/** The native SHA3-256 hasher, or `undefined` when the runtime lacks one. */
const nativeSha3: ((input: Uint8Array) => Buffer) | undefined = (() => {
  try {
    createHash('sha3-256').update('').digest()
    return (input: Uint8Array): Buffer => createHash('sha3-256').update(input).digest()
  } catch {
    return void 0
  }
})()

/**
 * Raw 32-byte SHA3-256 digest of the input.
 * @param {Uint8Array} input - the bytes to hash.
 * @returns {Buffer} the 32-byte digest.
 */
export function sha3_256Bytes(input: Uint8Array): Buffer {
  return nativeSha3 === void 0 ? Buffer.from(keccakSha3_256(input)) : nativeSha3(input)
}

/**
 * Lowercase hex SHA3-256 of UTF-8 text.
 * @param {string} text - the text to hash.
 * @returns {string} the 64-character lowercase hex digest.
 */
export function sha3_256Hex(text: string): string {
  return sha3_256Bytes(Buffer.from(text, 'utf8')).toString('hex')
}

/**
 * Lowercase hex SHA3-256 of the input bytes.
 * @param {Uint8Array} input - the bytes to hash.
 * @returns {string} the 64-character lowercase hex digest.
 */
export function sha3_256HexOfBytes(input: Uint8Array): string {
  return sha3_256Bytes(input).toString('hex')
}
