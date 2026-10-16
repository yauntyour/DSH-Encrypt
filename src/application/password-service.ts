import type { Argon2Params, EntryRecord, ParsedEncryptedStore, SealedRecordValue } from '../domain/vault/model.js'
import { KEY_FILE_VERIFIER_REF, VAULT_KDF, VaultError } from '../domain/vault/model.js'
import {
  argon2Defaults,
  createKeyVerifier,
  decryptEntry,
  deriveArgon2idKey,
  deriveMasterKey,
  encryptEntry,
  generatePasswordSalt,
  isDigest,
  zeroizeBuffer,
} from '../infrastructure/crypto/vault-crypto.js'
import { parseEncryptedStore, serializeEncryptedStore } from '../infrastructure/persistence/vault-document.js'
import { isCredentialReference } from '../shared/validation/primitives.js'

export interface EncryptedStoreCreation {
  text: string
  key: Buffer
  entries: Map<string, EntryRecord>
  records: Map<string, SealedRecordValue>
  verifier: EntryRecord
  salt: Buffer
  params: Argon2Params
}

/** Unlock an encrypted store and return only the state required by consumers. */
export async function unlockEncryptedStore(
  text: string,
  digest: string,
): Promise<Omit<ParsedEncryptedStore, 'documentSha3'> & { key: Buffer }> {
  const { key, parsed } = await deriveVerifiedKey(text, digest)
  return {
    key,
    entries: parsed.entries,
    records: parsed.records,
    verifier: parsed.verifier,
    salt: parsed.salt,
    params: parsed.params,
    kdf: parsed.kdf,
    remember: parsed.remember,
  }
}

/** Authenticate a password digest and immediately erase the derived key. */
export async function verifyPasswordDigest(text: string, digest: string): Promise<void> {
  const { key } = await deriveVerifiedKey(text, digest)
  zeroizeBuffer(key)
}

/**
 * Encrypt a complete plaintext credential map under a new password digest.
 * @param plaintexts - references and their values, encrypted as entries.
 * @param digest - SHA3-256 hex digest of the vault password.
 * @param params - Argon2id parameters for the new store.
 * @param sealRecords - seals the record snapshot under the derived key, so
 *   records enter the encrypted document together with the entries; omit for
 *   a store without records.
 * @returns the serialized store and its in-memory counterpart.
 */
export async function encryptCredentialStore(
  plaintexts: Map<string, string>,
  digest: string,
  params: Argon2Params = argon2Defaults(),
  sealRecords?: (key: Buffer) => Map<string, SealedRecordValue>,
): Promise<EncryptedStoreCreation> {
  assertPasswordDigest(digest)
  const salt = generatePasswordSalt()
  const key = await deriveArgon2idKey(digest, salt, params)
  const entries = new Map<string, EntryRecord>()
  for (const [ref, value] of plaintexts) {
    if (!isCredentialReference(ref)) {
      throw new VaultError('VAULT_INVALID', `entry key "${ref}" is not a credential reference`)
    }
    if (typeof value !== 'string' || value.length === 0) {
      throw new VaultError('VAULT_INVALID', `entry "${ref}" must be a non-empty string`)
    }
    entries.set(ref, encryptEntry(key, ref, value))
  }
  const records = sealRecords === void 0 ? new Map<string, SealedRecordValue>() : sealRecords(key)
  const verifier = createKeyVerifier(key)
  return {
    text: serializeEncryptedStore(entries, key, salt, params, void 0, VAULT_KDF, records, verifier),
    key,
    entries,
    records,
    verifier,
    salt,
    params,
  }
}

async function deriveVerifiedKey(text: string, digest: string): Promise<{ key: Buffer; parsed: ParsedEncryptedStore }> {
  assertPasswordDigest(digest)
  const parsed = parseEncryptedStore(text)
  const key = await deriveMasterKey(digest, parsed.salt, parsed.params, parsed.kdf)
  try {
    decryptEntry(key, KEY_FILE_VERIFIER_REF, parsed.verifier)
  } catch (error) {
    zeroizeBuffer(key)
    if (error instanceof VaultError && (error.code === 'VAULT_KEY_MISMATCH' || error.code === 'VAULT_CORRUPTED')) {
      throw new VaultError('PASSWORD_WRONG', 'the password digest does not match this credential store')
    }
    throw error
  }
  return { key, parsed }
}

function assertPasswordDigest(digest: string): void {
  if (!isDigest(digest)) {
    throw new VaultError(
      'PASSWORD_INVALID',
      'the password digest must be 64 lowercase hex characters (SHA3-256 of the password)',
    )
  }
}
