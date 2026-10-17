/**
 * Pure-JS SHA3-256 (Keccak-f[1600], padding 0x06) over bytes.
 *
 * One implementation serves both halves of the plugin: the browser client
 * hashes the password here (no WebCrypto SHA3), and the node half falls back
 * to it when `node:crypto` lacks "sha3-256" — the dsh desktop host runs on
 * Electron, whose BoringSSL rejects the algorithm with "Digest method not
 * supported". Both must produce byte-identical digests to `node:crypto`.
 * @module dsh-encrypt/shared/crypto/keccak
 */
const KECCAK_RC: readonly bigint[] = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
]

const KECCAK_RHO: readonly number[] = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
]
const KECCAK_PI: readonly number[] = [
  0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
]
const MASK64 = (1n << 64n) - 1n
/** SHA3-256 sponge rate in bytes (1600 − 2×256 bits). */
const SHA3_256_RATE = 136

/**
 * Raw 32-byte SHA3-256 digest of the input.
 * @param {Uint8Array} input - the bytes to hash.
 * @returns {Uint8Array} the 32-byte digest.
 */
export function keccakSha3_256(input: Uint8Array): Uint8Array {
  const padded = new Uint8Array(Math.ceil((input.length + 1) / SHA3_256_RATE) * SHA3_256_RATE)
  padded.set(input)
  padded[input.length] = 0x06
  padded[padded.length - 1] = valueAt(padded, padded.length - 1) | 0x80
  let state = Array.from<bigint>({ length: 25 }).fill(0n)
  for (let offset = 0; offset < padded.length; offset += SHA3_256_RATE) {
    for (let index = 0; index < SHA3_256_RATE; index += 8) {
      let word = 0n
      for (let byte = 0; byte < 8; byte += 1) {
        word |= BigInt(valueAt(padded, offset + index + byte)) << BigInt(8 * byte)
      }
      state[index / 8] = valueAt(state, index / 8) ^ word
    }
    state = keccakF(state)
  }
  const output = new Uint8Array(32)
  for (let index = 0; index < 4; index += 1) {
    let word = valueAt(state, index)
    for (let byte = 0; byte < 8; byte += 1) {
      output[index * 8 + byte] = Number(word & 0xffn)
      word >>= 8n
    }
  }
  return output
}

/**
 * Lowercase hex SHA3-256 of UTF-8 text.
 * @param {string} text - the text to hash.
 * @returns {string} the 64-character lowercase hex digest.
 */
export function keccakSha3_256HexOfText(text: string): string {
  return hexOf(keccakSha3_256(new TextEncoder().encode(String(text))))
}

/** Lowercase hex rendering of digest bytes. */
function hexOf(digest: Uint8Array): string {
  let hex = ''
  for (const byte of digest) hex += byte.toString(16).padStart(2, '0')
  return hex
}

function keccakF(lanes: bigint[]): bigint[] {
  for (let round = 0; round < 24; round += 1) {
    const columns: bigint[] = []
    for (let x = 0; x < 5; x += 1) {
      columns[x] =
        valueAt(lanes, x) ^
        valueAt(lanes, x + 5) ^
        valueAt(lanes, x + 10) ^
        valueAt(lanes, x + 15) ^
        valueAt(lanes, x + 20)
    }
    const deltas: bigint[] = []
    for (let x = 0; x < 5; x += 1) {
      deltas[x] = valueAt(columns, (x + 4) % 5) ^ rotateLeft(valueAt(columns, (x + 1) % 5), 1)
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const index = x + 5 * y
        lanes[index] = valueAt(lanes, index) ^ valueAt(deltas, x)
      }
    }
    const rotated = Array.from<bigint>({ length: 25 }).fill(0n)
    for (let index = 0; index < 25; index += 1) {
      rotated[valueAt(KECCAK_PI, index)] = rotateLeft(valueAt(lanes, index), valueAt(KECCAK_RHO, index))
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const index = x + 5 * y
        lanes[index] =
          valueAt(rotated, index) ^ (~valueAt(rotated, ((x + 1) % 5) + 5 * y) & valueAt(rotated, ((x + 2) % 5) + 5 * y))
      }
    }
    lanes[0] = valueAt(lanes, 0) ^ valueAt(KECCAK_RC, round)
  }
  return lanes
}

function rotateLeft(value: bigint, offset: number): bigint {
  return ((value << BigInt(offset)) | (value >> BigInt(64 - offset))) & MASK64
}

function valueAt<T>(values: ArrayLike<T>, index: number): T {
  const value = values[index]
  if (value === void 0) throw new RangeError(`index ${index} is outside an array of length ${values.length}`)
  return value
}
