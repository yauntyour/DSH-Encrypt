import type { CredentialRecord } from '@deepseek-ai/dsh-credentials'

/** Stable domain constants and types for encrypted credential documents. */

/** Document schema version. v3 stretches the password digest with Argon2id. */
export const VAULT_VERSION = 3 as const
/**
 * Encrypted-document version that adds the sealed `records` section (the
 * credential seam's second key space). v3 documents have no records and still
 * parse; a store writes v4 the first time it holds one.
 */
export const RECORD_VAULT_VERSION = 4 as const
/** Algorithm identifier persisted in the document and asserted on parse. */
export const VAULT_ALGORITHM = 'aes-256-gcm+sha3-256' as const
/** KDF marker written by v3 documents. */
export const VAULT_KDF = 'argon2id' as const
/** KDF marker of legacy v2 documents. */
export const LEGACY_KDF = 'scrypt' as const
/** KDF input marker persisted in encrypted stores. */
export const VAULT_KDF_INPUT = 'sha3-256-password' as const
/** Format marker persisted in encrypted stores. */
export const ENCRYPTED_STORE_FORMAT = 'dsh-encrypt-credentials' as const
/** Fixed reference for a key verifier record. */
export const KEY_FILE_VERIFIER_REF = 'DSH_CREDENTIAL_MASTER_VERIFIER' as const
/** Fixed reference for the wrapped master key inside a remember block. */
export const REMEMBER_KEY_REF = 'remember_key' as const
/** Current remembered-login block format. Version 2 authenticates its policy metadata. */
export const REMEMBER_BLOCK_VERSION = 2 as const

export const MASTER_KEY_BYTES = 32 as const
export const NONCE_BYTES = 12 as const
export const TAG_BYTES = 16 as const
export const PASSWORD_SALT_BYTES = 16 as const
export const REMEMBER_DAY_MS = 86400000 as const

export const ARGON2_MEMORY_KIB = 65536 as const
export const ARGON2_TIME = 3 as const
export const ARGON2_PARALLELISM = 1 as const
export const ARGON2_MAX_MEMORY_KIB = 65536 as const
export const ARGON2_MAX_TIME = 3 as const
export const ARGON2_MAX_PARALLELISM = 1 as const

export const SCRYPT_N = 131072 as const
export const SCRYPT_R = 8 as const
export const SCRYPT_P = 1 as const
export const SCRYPT_MAXMEM: number = 256 * 1024 * 1024
export const SCRYPT_MAX_N = 131072 as const
export const SCRYPT_MAX_R = 8 as const
export const SCRYPT_MAX_P = 1 as const

export interface EntryRecord {
  data: string
  sha3: string
}

/**
 * Which key seals one stored record. `password` records are AES-256-GCM
 * ciphertext under the Argon2id password key: unreadable while the vault is
 * locked. `machine` records are ciphertext under the installation's records
 * key (kept in the runtime state file): always readable, so boot-time
 * consumers such as the local browser-session secret survive a locked boot.
 */
export type RecordSeal = 'password' | 'machine'

/** One plaintext record as stored in a plain document. */
export interface PlainRecordValue {
  form: 'plain'
  record: CredentialRecord
}

/** One sealed record as stored in an encrypted document. */
export interface SealedRecordValue {
  form: 'sealed'
  kind: CredentialRecord['kind']
  seal: RecordSeal
  entry: EntryRecord
}

/** One record slot in the in-memory snapshot; the form follows the document form. */
export type RecordValue = PlainRecordValue | SealedRecordValue

export interface Argon2Params {
  m: number
  t: number
  p: number
}

export interface ScryptParams {
  n: number
  r: number
  p: number
}

export type KdfParams = Argon2Params | ScryptParams
export type KdfName = typeof VAULT_KDF | typeof LEGACY_KDF

export interface RememberBlock {
  /** Absent only on legacy blocks, which password unlock can replace but ticket unlock refuses. */
  version?: typeof REMEMBER_BLOCK_VERSION | undefined
  salt: string
  issuedAt: number
  days: number
  cipher: EntryRecord
}

export interface ParsedEncryptedStore {
  salt: Buffer
  params: KdfParams
  kdf: KdfName
  verifier: EntryRecord
  entries: Map<string, EntryRecord>
  records: Map<string, SealedRecordValue>
  remember?: RememberBlock | undefined
  documentSha3: string
}

/** Vault failure with a stable machine-readable code. */
export class VaultError extends Error {
  code: string

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(`dsh-encrypt: ${message}`)
    this.name = 'VaultError'
    this.code = code
    if (details !== void 0 && details !== null && typeof details === 'object') Object.assign(this, details)
  }
}
