import type {
  Argon2Params,
  EntryRecord,
  KdfName,
  KdfParams,
  ParsedEncryptedStore,
  RememberBlock,
  ScryptParams,
  SealedRecordValue,
} from '../../domain/vault/model.js'
import type { EncryptedStoreShape, SealedRecordEntryShape } from '../../domain/vault/schemas.js'
import {
  ENCRYPTED_STORE_FORMAT,
  KEY_FILE_VERIFIER_REF,
  LEGACY_KDF,
  MASTER_KEY_BYTES,
  RECORD_VAULT_VERSION,
  REMEMBER_KEY_REF,
  VAULT_ALGORITHM,
  VAULT_KDF,
  VAULT_KDF_INPUT,
  VAULT_VERSION,
  VaultError,
} from '../../domain/vault/model.js'
import {
  validateEncryptedStoreShape,
  validateRememberBlockShape,
  validateVaultDocumentShape,
} from '../../domain/vault/schemas.js'
import { isCredentialKeyName, isPlainRecord } from '../../shared/validation/primitives.js'
import { sha3_256Hex } from '../crypto/sha3.js'
import { argon2Defaults, createKeyVerifier, verifyEntryRecord } from '../crypto/vault-crypto.js'

const STORE_FIELDS: readonly string[] = [
  'format',
  'version',
  'algorithm',
  'kdf',
  'kdfInput',
  'n',
  'r',
  'm',
  't',
  'p',
  'salt',
  'verifier',
  'remember',
  'entries',
  'records',
]

/** Serialize the legacy standalone vault-document shape. */
export function serializeDocument(entries: Map<string, EntryRecord>): string {
  const canonical = canonicalEntries(Object.fromEntries(entries))
  const block = JSON.stringify(canonical)
  const document = {
    version: VAULT_VERSION,
    algorithm: VAULT_ALGORITHM,
    sha3: hashText(block),
    entries: canonical,
  }
  return `${JSON.stringify(document, null, 2)}\n`
}

/** Parse and verify the legacy standalone vault-document shape. */
export function parseDocument(text: string): { entries: Map<string, EntryRecord>; documentSha3: string } {
  const input = parseJson(text, 'the vault document is not valid JSON')
  const validated = validateVaultDocumentShape(input)
  if (!validated.success || validated.output === void 0) {
    throw new VaultError('VAULT_INVALID', 'the vault document does not match the supported schema')
  }
  const document = validated.output
  const actual = hashText(JSON.stringify(canonicalEntries(document.entries)))
  if (actual !== document.sha3) {
    throw new VaultError(
      'VAULT_CORRUPTED',
      'the vault document failed its SHA3-256 integrity check: entries were added, removed, swapped, or altered',
    )
  }
  const entries = verifiedEntries(document.entries)
  return { entries, documentSha3: actual }
}

/** Verify a standalone vault document and discard its parsed entries. */
export function verifyDocument(text: string): void {
  parseDocument(text)
}

/** Detect whether credential text carries the encrypted-store marker. */
export function detectCredentialStore(text: string): 'encrypted' | 'plain' {
  const trimmed = text.trim()
  if (trimmed.length === 0) return 'plain'
  try {
    const document: unknown = JSON.parse(trimmed)
    return isPlainRecord(document) && document.format === ENCRYPTED_STORE_FORMAT ? 'encrypted' : 'plain'
  } catch {
    return 'plain'
  }
}

/**
 * Serialize a current or legacy encrypted credential store. The document is
 * fully determined by the snapshot, its parameters, and the key verifier: the
 * master key is only an input for creating a fresh verifier when none is
 * supplied, which is what lets a locked provider rewrite the document (a
 * machine-sealed record, a record deletion) without the password key.
 */
export function serializeEncryptedStore(
  entries: Map<string, EntryRecord>,
  key: Buffer | undefined,
  salt: Buffer,
  params: KdfParams = argon2Defaults(),
  remember?: RememberBlock,
  kdf: KdfName = VAULT_KDF,
  records?: ReadonlyMap<string, SealedRecordValue>,
  verifier?: EntryRecord,
): string {
  if (verifier !== void 0) {
    verifyEntryRecord(KEY_FILE_VERIFIER_REF, verifier)
  } else if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) {
    throw new VaultError('MASTER_KEY_INVALID', 'a master key must be a 32-byte buffer')
  }
  if (!Buffer.isBuffer(salt) || salt.length === 0) {
    throw new VaultError('MASTER_KEY_INVALID', 'a password salt must be a non-empty buffer')
  }
  if (remember !== void 0 && !validateRememberBlockShape(remember).success) {
    throw new VaultError('VAULT_INVALID', "the store's remember block does not match the supported schema")
  }
  if (kdf !== VAULT_KDF && kdf !== LEGACY_KDF) {
    throw new VaultError('MASTER_KEY_INVALID', `unsupported store kdf ${String(kdf)}`)
  }
  const sealed = records === void 0 || records.size === 0 ? void 0 : canonicalSealedRecords(records)
  const document: Record<string, unknown> = {
    format: ENCRYPTED_STORE_FORMAT,
    version: kdf === LEGACY_KDF ? 2 : sealed === void 0 ? VAULT_VERSION : RECORD_VAULT_VERSION,
    algorithm: VAULT_ALGORITHM,
    kdf,
    kdfInput: VAULT_KDF_INPUT,
    salt: salt.toString('base64url'),
    verifier: verifier ?? createKeyVerifier(key as Buffer),
    entries: canonicalEntries(Object.fromEntries(entries)),
  }
  if (kdf === LEGACY_KDF) {
    const legacy = params as ScryptParams
    document.n = legacy.n
    document.r = legacy.r
    document.p = legacy.p
  } else {
    const current = params as Argon2Params
    document.m = current.m
    document.t = current.t
    document.p = current.p
  }
  if (remember !== void 0) document.remember = remember
  // v4 only exists to carry records: a store without them stays v3 so an
  // older dsh-encrypt build can still open it.
  if (sealed !== void 0) document.records = sealed
  document.sha3 = hashText(JSON.stringify(fingerprintTarget(document)))
  return `${JSON.stringify(document, null, 2)}\n`
}

/** Parse and verify a current or legacy encrypted credential store. */
export function parseEncryptedStore(text: string): ParsedEncryptedStore {
  const input = parseJson(text, 'the encrypted credential store is not valid JSON')
  if (!isPlainRecord(input) || input.format !== ENCRYPTED_STORE_FORMAT) {
    throw new VaultError('VAULT_INVALID', `the document is not a ${ENCRYPTED_STORE_FORMAT} store`)
  }
  if (input.version === 1) {
    throw new VaultError(
      'VAULT_INVALID',
      'unsupported store version 1; a store encrypted by dsh-encrypt ≤ 0.1.0-rc.6 must be unlocked and returned to plaintext with that version first',
    )
  }
  const validated = validateEncryptedStoreShape(input)
  if (!validated.success || validated.output === void 0) {
    throw new VaultError('VAULT_INVALID', 'the encrypted credential store does not match the supported schema')
  }
  return buildParsedStore(validated.output)
}

function buildParsedStore(store: EncryptedStoreShape): ParsedEncryptedStore {
  const actual = hashText(JSON.stringify(fingerprintTarget(store as unknown as Record<string, unknown>)))
  if (actual !== store.sha3) {
    throw new VaultError(
      'VAULT_CORRUPTED',
      'the encrypted credential store failed its SHA3-256 integrity check: its header, entries, or records were altered',
    )
  }
  const remember = store.remember ?? void 0
  if (remember !== void 0) verifyEntryRecord(REMEMBER_KEY_REF, remember.cipher)
  verifyEntryRecord(KEY_FILE_VERIFIER_REF, store.verifier)
  return {
    salt: Buffer.from(store.salt, 'base64url'),
    params: store.kdf === LEGACY_KDF ? { n: store.n, r: store.r, p: store.p } : { m: store.m, t: store.t, p: store.p },
    kdf: store.kdf,
    verifier: store.verifier,
    entries: verifiedEntries(store.entries),
    records: 'records' in store ? verifiedSealedRecords(store.records) : new Map<string, SealedRecordValue>(),
    remember,
    documentSha3: actual,
  }
}

function canonicalEntries(entries: Record<string, EntryRecord>): Record<string, EntryRecord> {
  const sorted: Record<string, EntryRecord> = {}
  for (const ref of Object.keys(entries).sort()) {
    const record = entries[ref]
    if (record === void 0) throw new VaultError('VAULT_INVALID', `entry "${ref}" is missing`)
    sorted[ref] = record
  }
  return sorted
}

function canonicalSealedRecords(
  records: ReadonlyMap<string, SealedRecordValue>,
): Record<string, SealedRecordEntryShape> {
  const sorted: Record<string, SealedRecordEntryShape> = {}
  for (const key of [...records.keys()].sort()) {
    const slot = records.get(key)
    if (slot === void 0) throw new VaultError('VAULT_INVALID', `record "${key}" is missing`)
    if (!isCredentialKeyName(key)) throw new VaultError('VAULT_INVALID', `record key "${key}" is not a credential key`)
    sorted[key] = { kind: slot.kind, seal: slot.seal, data: slot.entry.data, sha3: slot.entry.sha3 }
  }
  return sorted
}

function verifiedEntries(records: Record<string, EntryRecord>): Map<string, EntryRecord> {
  const entries = new Map<string, EntryRecord>()
  for (const [ref, record] of Object.entries(records)) {
    verifyEntryRecord(ref, record)
    entries.set(ref, record)
  }
  return entries
}

function verifiedSealedRecords(records: Record<string, SealedRecordEntryShape>): Map<string, SealedRecordValue> {
  const sealed = new Map<string, SealedRecordValue>()
  for (const [key, record] of Object.entries(records)) {
    verifyEntryRecord(key, record)
    sealed.set(key, {
      form: 'sealed',
      kind: record.kind,
      seal: record.seal,
      entry: { data: record.data, sha3: record.sha3 },
    })
  }
  return sealed
}

function fingerprintTarget(document: Record<string, unknown>): Record<string, unknown> {
  const target: Record<string, unknown> = {}
  for (const field of STORE_FIELDS) {
    if (document[field] !== void 0) target[field] = document[field]
  }
  return target
}

function hashText(text: string): string {
  return sha3_256Hex(text)
}

function parseJson(text: string, message: string): unknown {
  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new VaultError('VAULT_INVALID', message)
  }
}
