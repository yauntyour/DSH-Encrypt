/**
 * Browser-side SHA3-256: the shared pure-JS Keccak over UTF-8 text.
 *
 * The WebUI computes password digests here before POSTing them; the same
 * implementation backs the node side under Electron (BoringSSL has no
 * "sha3-256"), so both halves always agree byte for byte.
 * @module dsh-encrypt/client/sha3
 */
export { keccakSha3_256HexOfText as sha3_256Hex } from '../shared/crypto/keccak.js'
