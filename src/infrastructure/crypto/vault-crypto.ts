import type { Argon2Params, EntryRecord, KdfName, KdfParams, ScryptParams } from '../../domain/vault/model.js'
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto'
import { hashRaw as argon2HashRaw } from '@node-rs/argon2'
import {
  ARGON2_MAX_MEMORY_KIB,
  ARGON2_MAX_PARALLELISM,
  ARGON2_MAX_TIME,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  ARGON2_TIME,
  KEY_FILE_VERIFIER_REF,
  LEGACY_KDF,
  MASTER_KEY_BYTES,
  NONCE_BYTES,
  PASSWORD_SALT_BYTES,
  SCRYPT_MAXMEM,
  SCRYPT_MAX_N,
  SCRYPT_MAX_P,
  SCRYPT_MAX_R,
  TAG_BYTES,
  VAULT_KDF,
  VaultError,
} from '../../domain/vault/model.js'
import { validatePasswordKeyFileShape } from '../../domain/vault/schemas.js'
import {
  isAsciiHex,
  isAsciiLowerHex,
  isCredentialKeyName,
  isCredentialReference,
  isPlainRecord,
  trimTrailingCharacter,
} from '../../shared/validation/primitives.js'
import { sha3_256Hex } from './sha3.js'

type Argon2Algorithm = NonNullable<NonNullable<Parameters<typeof argon2HashRaw>[1]>['algorithm']>

const KEY_FILE_VERIFIER_TEXT = 'dsh-encrypt master-key verifier'

/** Whether a text is a valid lowercase hex SHA3-256 digest. */
export function isDigest(value: unknown): value is string {
  return isAsciiLowerHex(value, 64)
}

/** Erase a mutable key buffer. */
export function zeroizeBuffer(buffer: Buffer): void {
  buffer.fill(0)
}

/** Generate a fresh 256-bit master key. */
export function generateMasterKey(): Buffer {
  return randomBytes(MASTER_KEY_BYTES)
}

/** Encode a master key as base64url. */
export function encodeMasterKey(key: Buffer): string {
  assertMasterKey(key)
  return key.toString('base64url')
}

/** Parse a base64url or hexadecimal master key. */
export function parseMasterKey(text: string): Buffer {
  if (typeof text !== 'string') {
    throw new VaultError('MASTER_KEY_INVALID', 'the master key must be text (base64url or 64 hex digits)')
  }
  const value = text.trim()
  if (value.length === 0) throw new VaultError('MASTER_KEY_INVALID', 'the master key is empty')
  let key: Buffer
  if (isAsciiHex(value, 64)) {
    key = Buffer.from(value, 'hex')
  } else {
    try {
      key = Buffer.from(value, 'base64url')
    } catch {
      throw new VaultError('MASTER_KEY_INVALID', 'the master key is neither 64 hex digits nor base64url')
    }
    if (trimTrailingCharacter(key.toString('base64url'), '=') !== trimTrailingCharacter(value, '=')) {
      throw new VaultError('MASTER_KEY_INVALID', 'the master key is neither 64 hex digits nor base64url')
    }
  }
  if (key.length !== MASTER_KEY_BYTES) {
    throw new VaultError(
      'MASTER_KEY_INVALID',
      `the master key must decode to ${MASTER_KEY_BYTES} bytes, got ${key.length}`,
    )
  }
  return key
}

/** Generate a fresh salt for password-key derivation. */
export function generatePasswordSalt(): Buffer {
  return randomBytes(PASSWORD_SALT_BYTES)
}

/** Default Argon2id parameters. */
export function argon2Defaults(): Argon2Params {
  return { m: ARGON2_MEMORY_KIB, t: ARGON2_TIME, p: ARGON2_PARALLELISM }
}

/** Derive a master key with the selected document KDF. */
export async function deriveMasterKey(
  digest: string,
  salt: Buffer,
  params: KdfParams = argon2Defaults(),
  kdf: KdfName = VAULT_KDF,
): Promise<Buffer> {
  if (!isDigest(digest)) {
    throw new VaultError(
      'PASSWORD_INVALID',
      'the password digest must be 64 lowercase hex characters (SHA3-256 of the password)',
    )
  }
  if (!Buffer.isBuffer(salt) || salt.length === 0) {
    throw new VaultError('MASTER_KEY_INVALID', 'a password salt must be a non-empty buffer')
  }
  if (kdf === LEGACY_KDF) return deriveScryptKey(digest, salt, params as ScryptParams)
  if (kdf === VAULT_KDF) return deriveArgon2idKey(digest, salt, params as Argon2Params)
  throw new VaultError('MASTER_KEY_INVALID', `unsupported kdf ${String(kdf)}`)
}

/** Derive a key with Argon2id under bounded resource parameters. */
export async function deriveArgon2idKey(digest: string, salt: Buffer, params: Argon2Params): Promise<Buffer> {
  if (!Number.isInteger(params.m) || params.m < 8 || params.m > ARGON2_MAX_MEMORY_KIB) {
    throw new VaultError(
      'MASTER_KEY_INVALID',
      `argon2id memory cost must be an integer from 8 through ${ARGON2_MAX_MEMORY_KIB} KiB`,
    )
  }
  if (!Number.isInteger(params.t) || params.t < 1 || params.t > ARGON2_MAX_TIME) {
    throw new VaultError(
      'MASTER_KEY_INVALID',
      `argon2id time cost must be an integer from 1 through ${ARGON2_MAX_TIME}`,
    )
  }
  if (!Number.isInteger(params.p) || params.p < 1 || params.p > ARGON2_MAX_PARALLELISM) {
    throw new VaultError(
      'MASTER_KEY_INVALID',
      `argon2id parallelism must be an integer from 1 through ${ARGON2_MAX_PARALLELISM}`,
    )
  }
  const raw = await argon2HashRaw(Buffer.from(digest, 'utf8'), {
    algorithm: 2 as Argon2Algorithm,
    salt,
    outputLen: MASTER_KEY_BYTES,
    memoryCost: params.m,
    timeCost: params.t,
    parallelism: params.p,
  })
  const key = Buffer.from(raw)
  if (key.length < MASTER_KEY_BYTES) throw new VaultError('MASTER_KEY_INVALID', 'argon2id produced fewer than 32 bytes')
  return key.subarray(0, MASTER_KEY_BYTES)
}

/** Derive a legacy version-2 document key with scrypt. */
export async function deriveScryptKey(digest: string, salt: Buffer, params: ScryptParams): Promise<Buffer> {
  if (
    !Number.isInteger(params.n) ||
    !Number.isInteger(params.r) ||
    !Number.isInteger(params.p) ||
    params.n < 2 ||
    params.n > SCRYPT_MAX_N ||
    !Number.isInteger(Math.log2(params.n)) ||
    params.r < 1 ||
    params.r > SCRYPT_MAX_R ||
    params.p < 1 ||
    params.p > SCRYPT_MAX_P
  ) {
    throw new VaultError('MASTER_KEY_INVALID', 'scrypt parameters exceed the supported resource bounds')
  }
  return new Promise<Buffer>((resolve, reject) => {
    scrypt(
      digest,
      salt,
      MASTER_KEY_BYTES,
      { N: params.n, r: params.r, p: params.p, maxmem: SCRYPT_MAXMEM },
      (error, key) => {
        if (error !== null) reject(error)
        else resolve(key)
      },
    )
  })
}

/** Encrypt the fixed key-verifier plaintext. */
export function createKeyVerifier(key: Buffer): EntryRecord {
  return encryptEntry(key, KEY_FILE_VERIFIER_REF, KEY_FILE_VERIFIER_TEXT)
}

/** Serialize the standalone password-key file kept for API compatibility. */
export function createPasswordKeyFile(key: Buffer, salt: Buffer, params: Argon2Params = argon2Defaults()): string {
  assertMasterKey(key)
  const document = {
    version: 1,
    kdf: VAULT_KDF,
    m: params.m,
    t: params.t,
    p: params.p,
    salt: salt.toString('base64url'),
    verifier: createKeyVerifier(key),
  }
  return `${JSON.stringify(document, null, 2)}\n`
}

/** Whether text is a supported standalone password-key file. */
export function isPasswordKeyFile(text: string): boolean {
  try {
    return validatePasswordKeyFileShape(JSON.parse(text) as unknown).success
  } catch {
    return false
  }
}

/** Parse a standalone password-key file and authenticate its password. */
export async function parsePasswordKeyFile(text: string, password: string): Promise<Buffer> {
  let document: unknown
  try {
    document = JSON.parse(text)
  } catch {
    throw new VaultError('MASTER_KEY_INVALID', 'the key file is neither a legacy raw key nor a password key file')
  }
  const validated = validatePasswordKeyFileShape(document)
  if (!validated.success || validated.output === void 0) {
    throw new VaultError('MASTER_KEY_INVALID', 'unsupported password key-file format')
  }
  const keyFile = validated.output
  const salt = Buffer.from(keyFile.salt, 'base64url')
  const key =
    keyFile.kdf === LEGACY_KDF
      ? await deriveScryptKey(password, salt, { n: keyFile.n as number, r: keyFile.r as number, p: keyFile.p })
      : await deriveArgon2idKey(password, salt, { m: keyFile.m as number, t: keyFile.t as number, p: keyFile.p })
  try {
    decryptEntry(key, KEY_FILE_VERIFIER_REF, keyFile.verifier)
  } catch (error) {
    zeroizeBuffer(key)
    if (error instanceof VaultError && (error.code === 'VAULT_KEY_MISMATCH' || error.code === 'VAULT_CORRUPTED')) {
      throw new VaultError('PASSWORD_WRONG', 'the password does not match this master-key file')
    }
    throw error
  }
  return key
}

/** Validate an entry record and its SHA3-256 fingerprint. */
export function verifyEntryRecord(ref: string, record: unknown): asserts record is EntryRecord {
  if (!isPlainRecord(record) || typeof record.data !== 'string' || typeof record.sha3 !== 'string') {
    throw new VaultError('VAULT_INVALID', `entry "${ref}" must map to { data, sha3 } strings`)
  }
  if (fingerprint(record.data) !== record.sha3) {
    throw new VaultError(
      'VAULT_CORRUPTED',
      `entry "${ref}" failed its SHA3-256 integrity check: the stored ciphertext does not match its fingerprint`,
    )
  }
}

/** Encrypt one secret and bind it to its credential reference with GCM AAD. */
export function encryptEntry(key: Buffer, ref: string, plaintext: string): EntryRecord {
  assertMasterKey(key)
  if (!isCredentialReference(ref)) {
    throw new VaultError('VAULT_INVALID', `reference "${ref}" is not a credential reference`)
  }
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new VaultError('VAULT_INVALID', `the plaintext for "${ref}" must be a non-empty string`)
  }
  return sealText(key, ref, plaintext)
}

/**
 * Encrypt one record payload and bind it to its credential key with GCM AAD.
 * The record grammar is disjoint from the reference grammar, so a record
 * ciphertext can never authenticate as an entry ciphertext and vice versa.
 */
export function encryptRecordPayload(key: Buffer, recordKey: string, plaintext: string): EntryRecord {
  assertMasterKey(key)
  if (!isCredentialKeyName(recordKey)) {
    throw new VaultError('VAULT_INVALID', `record key "${recordKey}" is not a credential key (scope/id)`)
  }
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new VaultError('VAULT_INVALID', `the record payload for "${recordKey}" must be a non-empty string`)
  }
  return sealText(key, recordKey, plaintext)
}

/** Decrypt one entry into an erasure-capable buffer. */
export function decryptEntryBuffer(key: Buffer, ref: string, record: unknown): Buffer {
  assertMasterKey(key)
  if (!isCredentialReference(ref)) {
    throw new VaultError('VAULT_INVALID', `reference "${ref}" is not a credential reference`)
  }
  verifyEntryRecord(ref, record)
  return openText(key, ref, record)
}

/** Decrypt one record payload into an erasure-capable buffer. */
export function decryptRecordPayloadBuffer(key: Buffer, recordKey: string, record: unknown): Buffer {
  assertMasterKey(key)
  if (!isCredentialKeyName(recordKey)) {
    throw new VaultError('VAULT_INVALID', `record key "${recordKey}" is not a credential key (scope/id)`)
  }
  verifyEntryRecord(recordKey, record)
  return openText(key, recordKey, record)
}

/** Decrypt one entry into an immutable string and erase its intermediate buffer. */
export function decryptEntry(key: Buffer, ref: string, record: unknown): string {
  const plain = decryptEntryBuffer(key, ref, record)
  const text = plain.toString('utf8')
  zeroizeBuffer(plain)
  return text
}

/** Decrypt one record payload into an immutable string and erase its intermediate buffer. */
export function decryptRecordPayload(key: Buffer, recordKey: string, record: unknown): string {
  const plain = decryptRecordPayloadBuffer(key, recordKey, record)
  const text = plain.toString('utf8')
  zeroizeBuffer(plain)
  return text
}

/** Seal UTF-8 text as `nonce ‖ ciphertext ‖ tag` base64url with the AAD label. */
function sealText(key: Buffer, label: string, plaintext: string): EntryRecord {
  const nonce = randomBytes(NONCE_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.from(label, 'utf8'))
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  const data = Buffer.concat([nonce, ciphertext, tag]).toString('base64url')
  return { data, sha3: fingerprint(data) }
}

/** Open one verified ciphertext under the AAD label. */
function openText(key: Buffer, label: string, record: EntryRecord): Buffer {
  let blob: Buffer
  try {
    blob = Buffer.from(record.data, 'base64url')
  } catch {
    throw new VaultError('VAULT_CORRUPTED', `entry "${label}" is not valid base64url`)
  }
  if (blob.length <= NONCE_BYTES + TAG_BYTES) throw new VaultError('VAULT_CORRUPTED', `entry "${label}" is truncated`)
  const nonce = blob.subarray(0, NONCE_BYTES)
  const tag = blob.subarray(blob.length - TAG_BYTES)
  const ciphertext = blob.subarray(NONCE_BYTES, blob.length - TAG_BYTES)
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAAD(Buffer.from(label, 'utf8'))
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch {
    throw new VaultError(
      'VAULT_KEY_MISMATCH',
      `entry "${label}" failed AES-256-GCM authentication: the master key does not match this document, or the ciphertext was replaced`,
    )
  }
}

function assertMasterKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) {
    throw new VaultError('MASTER_KEY_INVALID', 'a master key must be a 32-byte buffer')
  }
}

function fingerprint(data: string): string {
  return sha3_256Hex(data)
}
