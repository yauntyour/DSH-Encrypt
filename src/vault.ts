/**
 * Public compatibility facade for the encrypted credential vault.
 *
 * Implementations live in focused domain, application, persistence, and
 * cryptography modules. This entry keeps the original package API stable.
 * @module dsh-encrypt/vault
 */

export {
  ARGON2_MAX_MEMORY_KIB,
  ARGON2_MAX_PARALLELISM,
  ARGON2_MAX_TIME,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  ARGON2_TIME,
  ENCRYPTED_STORE_FORMAT,
  KEY_FILE_VERIFIER_REF,
  LEGACY_KDF,
  MASTER_KEY_BYTES,
  NONCE_BYTES,
  PASSWORD_SALT_BYTES,
  RECORD_VAULT_VERSION,
  REMEMBER_DAY_MS,
  REMEMBER_KEY_REF,
  SCRYPT_MAXMEM,
  SCRYPT_N,
  SCRYPT_P,
  SCRYPT_R,
  TAG_BYTES,
  VAULT_ALGORITHM,
  VAULT_KDF,
  VAULT_KDF_INPUT,
  VAULT_VERSION,
  VaultError,
  type Argon2Params,
  type EntryRecord,
  type KdfName,
  type KdfParams,
  type ParsedEncryptedStore,
  type PlainRecordValue,
  type RecordSeal,
  type RecordValue,
  type RememberBlock,
  type ScryptParams,
  type SealedRecordValue,
} from './domain/vault/model.js'

export {
  argon2Defaults,
  createPasswordKeyFile,
  decryptEntry,
  decryptEntryBuffer,
  decryptRecordPayload,
  decryptRecordPayloadBuffer,
  deriveArgon2idKey,
  deriveMasterKey,
  deriveScryptKey,
  encodeMasterKey,
  encryptEntry,
  encryptRecordPayload,
  generateMasterKey,
  generatePasswordSalt,
  isDigest,
  isPasswordKeyFile,
  parseMasterKey,
  parsePasswordKeyFile,
  sha3_256Hex,
  verifyEntryRecord,
  zeroizeBuffer,
} from './infrastructure/crypto/vault-crypto.js'

export {
  detectCredentialStore,
  parseDocument,
  parseEncryptedStore,
  serializeDocument,
  serializeEncryptedStore,
  verifyDocument,
} from './infrastructure/persistence/vault-document.js'

export {
  PLAIN_DOCUMENT_VERSION,
  parsePlainDocument,
  renderPlainDocument,
  type PlainCredentialDocument,
  type PlainDocumentEdit,
} from './infrastructure/persistence/plain-credential-document.js'

export {
  encryptCredentialStore,
  unlockEncryptedStore,
  verifyPasswordDigest,
  type EncryptedStoreCreation,
} from './application/password-service.js'

export { createRememberBlock, recoverKeyFromRemember, rememberActive } from './application/remember-service.js'
