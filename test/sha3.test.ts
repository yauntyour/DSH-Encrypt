/**
 * The pure-JS Keccak fallback must be byte-identical to node:crypto's
 * "sha3-256": the dsh desktop host runs on Electron (BoringSSL), which has no
 * native SHA3, so vault fingerprints, verifiers and the shipped-file
 * integrity check are computed here instead. Divergence would corrupt every
 * document written under one runtime and read under the other.
 */
import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { sha3_256Hex } from '../lib/vault.js'
import { keccakSha3_256, keccakSha3_256HexOfText } from '../src/shared/crypto/keccak.js'

/** Lowercase hex rendering of digest bytes. */
function hexOf(digest: Uint8Array): string {
  let hex = ''
  for (const byte of digest) hex += byte.toString(16).padStart(2, '0')
  return hex
}

/** Deterministic byte pattern (covers all byte values). */
function pattern(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  for (let index = 0; index < length; index += 1) bytes[index] = (index * 31 + 7) & 0xff
  return bytes
}

/** Deterministic ASCII text long enough to cross sponge blocks. */
function ascii(length: number): string {
  let text = ''
  for (let index = 0; index < length; index += 1) text += String.fromCharCode(32 + ((index * 17) % 95))
  return text
}

// Sponge boundaries: rate = 136 bytes, so 135/136/137 and 271/272/273 flip
// padding and multi-block paths.
const LENGTHS = [0, 1, 7, 8, 63, 135, 136, 137, 200, 271, 272, 273, 1000]

describe('pure-JS SHA3-256 fallback', () => {
  it('matches the published SHA3-256 vectors', () => {
    expect(keccakSha3_256HexOfText('')).toBe('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')
    expect(keccakSha3_256HexOfText('abc')).toBe('3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532')
  })

  it('matches node:crypto over raw bytes at every sponge boundary', () => {
    for (const length of LENGTHS) {
      const bytes = pattern(length)
      const native = createHash('sha3-256').update(bytes).digest('hex')
      expect(hexOf(keccakSha3_256(bytes))).toBe(native)
    }
  })

  it('matches node:crypto over UTF-8 text at every sponge boundary', () => {
    for (const length of LENGTHS) {
      const text = ascii(length)
      const native = createHash('sha3-256').update(text, 'utf8').digest('hex')
      expect(keccakSha3_256HexOfText(text)).toBe(native)
    }
    const unicode = '口令-密码-🔐'
    expect(keccakSha3_256HexOfText(unicode)).toBe(createHash('sha3-256').update(unicode, 'utf8').digest('hex'))
  })

  it('keeps the public vault digest on the same bytes', () => {
    expect(sha3_256Hex('abc')).toBe(keccakSha3_256HexOfText('abc'))
    expect(sha3_256Hex('abc')).toBe(createHash('sha3-256').update('abc', 'utf8').digest('hex'))
  })
})
