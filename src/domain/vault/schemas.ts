import type { Argon2Params, EntryRecord, RecordSeal, RememberBlock, ScryptParams } from './model.js'
import type { CredentialRecord } from '@deepseek-ai/dsh-credentials'
import {
  check,
  finite,
  integer,
  literal,
  maxValue,
  minValue,
  nonEmpty,
  nullable,
  number,
  optional,
  pipe,
  record,
  safeParse,
  strictObject,
  string,
  unknown,
  union,
} from 'valibot'
import { isCredentialKeyName, isCredentialReference } from '../../shared/validation/primitives.js'
import {
  ARGON2_MAX_MEMORY_KIB,
  ARGON2_MAX_PARALLELISM,
  ARGON2_MAX_TIME,
  ENCRYPTED_STORE_FORMAT,
  LEGACY_KDF,
  RECORD_VAULT_VERSION,
  REMEMBER_BLOCK_VERSION,
  SCRYPT_MAX_N,
  SCRYPT_MAX_P,
  SCRYPT_MAX_R,
  VAULT_ALGORITHM,
  VAULT_KDF,
  VAULT_KDF_INPUT,
  VAULT_VERSION,
} from './model.js'

export interface VaultDocumentShape {
  version: typeof VAULT_VERSION
  algorithm: typeof VAULT_ALGORITHM
  sha3: string
  entries: Record<string, EntryRecord>
}

interface EncryptedStoreBaseShape {
  format: typeof ENCRYPTED_STORE_FORMAT
  algorithm: typeof VAULT_ALGORITHM
  kdfInput: typeof VAULT_KDF_INPUT
  salt: string
  verifier: EntryRecord
  remember?: RememberBlock | null | undefined
  entries: Record<string, EntryRecord>
  sha3: string
}

interface LegacyEncryptedStoreShape extends EncryptedStoreBaseShape, ScryptParams {
  version: 2
  kdf: typeof LEGACY_KDF
  m?: unknown
  t?: unknown
}

interface Argon2EncryptedStoreShape extends EncryptedStoreBaseShape, Argon2Params {
  version: typeof VAULT_VERSION
  kdf: typeof VAULT_KDF
  n?: unknown
  r?: unknown
}

/** One sealed record entry as stored in a v4 encrypted document. */
export interface SealedRecordEntryShape {
  kind: CredentialRecord['kind']
  seal: RecordSeal
  data: string
  sha3: string
}

interface RecordedEncryptedStoreShape extends EncryptedStoreBaseShape, Argon2Params {
  version: typeof RECORD_VAULT_VERSION
  kdf: typeof VAULT_KDF
  n?: unknown
  r?: unknown
  records: Record<string, SealedRecordEntryShape>
}

export type EncryptedStoreShape = LegacyEncryptedStoreShape | Argon2EncryptedStoreShape | RecordedEncryptedStoreShape

export interface PasswordKeyFileShape {
  version: number
  kdf: typeof VAULT_KDF | typeof LEGACY_KDF
  salt: string
  verifier: EntryRecord
  m?: number | undefined
  t?: number | undefined
  n?: number | undefined
  r?: number | undefined
  p: number
}

export interface SchemaResult<T> {
  success: boolean
  output?: T | undefined
}

const nonEmptyStringSchema = pipe(string(), nonEmpty())
const credentialReferenceSchema = pipe(string(), check<string>(isCredentialReference))
const scryptNSchema = pipe(number(), integer(), minValue(2), maxValue(SCRYPT_MAX_N))
const scryptRSchema = pipe(number(), integer(), minValue(1), maxValue(SCRYPT_MAX_R))
const scryptPSchema = pipe(number(), integer(), minValue(1), maxValue(SCRYPT_MAX_P))
const entryRecordSchema = strictObject({ data: string(), sha3: string() })
const entriesSchema = record(credentialReferenceSchema, entryRecordSchema)
const rememberDaysSchema = union([literal(-1), pipe(number(), integer(), minValue(1), maxValue(30))])
const rememberBlockSchema = strictObject({
  version: optional(literal(REMEMBER_BLOCK_VERSION)),
  salt: nonEmptyStringSchema,
  issuedAt: pipe(number(), finite(), minValue(0)),
  days: rememberDaysSchema,
  cipher: entryRecordSchema,
})

const vaultDocumentSchema = strictObject({
  version: literal(VAULT_VERSION),
  algorithm: literal(VAULT_ALGORITHM),
  sha3: string(),
  entries: entriesSchema,
})

const encryptedStoreBaseEntries = {
  format: literal(ENCRYPTED_STORE_FORMAT),
  algorithm: literal(VAULT_ALGORITHM),
  kdfInput: literal(VAULT_KDF_INPUT),
  salt: nonEmptyStringSchema,
  verifier: entryRecordSchema,
  remember: optional(nullable(rememberBlockSchema)),
  entries: entriesSchema,
  sha3: string(),
}

const legacyEncryptedStoreSchema = strictObject({
  ...encryptedStoreBaseEntries,
  version: literal(2),
  kdf: literal(LEGACY_KDF),
  n: scryptNSchema,
  r: scryptRSchema,
  m: optional(unknown()),
  t: optional(unknown()),
  p: scryptPSchema,
})

const argon2EncryptedStoreSchema = strictObject({
  ...encryptedStoreBaseEntries,
  version: literal(VAULT_VERSION),
  kdf: literal(VAULT_KDF),
  m: pipe(number(), integer(), minValue(8), maxValue(ARGON2_MAX_MEMORY_KIB)),
  t: pipe(number(), integer(), minValue(1), maxValue(ARGON2_MAX_TIME)),
  n: optional(unknown()),
  r: optional(unknown()),
  p: pipe(number(), integer(), minValue(1), maxValue(ARGON2_MAX_PARALLELISM)),
})

const recordKindSchema = union([literal('api-key'), literal('grant')])
const recordSealSchema = union([literal('password'), literal('machine')])
const sealedRecordEntrySchema = strictObject({
  kind: recordKindSchema,
  seal: recordSealSchema,
  data: string(),
  sha3: string(),
})
const sealedRecordsSchema = record(pipe(string(), check<string>(isCredentialKeyName)), sealedRecordEntrySchema)

const recordedEncryptedStoreSchema = strictObject({
  ...encryptedStoreBaseEntries,
  version: literal(RECORD_VAULT_VERSION),
  kdf: literal(VAULT_KDF),
  m: pipe(number(), integer(), minValue(8), maxValue(ARGON2_MAX_MEMORY_KIB)),
  t: pipe(number(), integer(), minValue(1), maxValue(ARGON2_MAX_TIME)),
  n: optional(unknown()),
  r: optional(unknown()),
  p: pipe(number(), integer(), minValue(1), maxValue(ARGON2_MAX_PARALLELISM)),
  records: sealedRecordsSchema,
})

const encryptedStoreSchema = union([
  legacyEncryptedStoreSchema,
  argon2EncryptedStoreSchema,
  recordedEncryptedStoreSchema,
])

const passwordKeyFileSchema = union([
  strictObject({
    version: number(),
    kdf: literal(VAULT_KDF),
    m: pipe(number(), integer(), minValue(8), maxValue(ARGON2_MAX_MEMORY_KIB)),
    t: pipe(number(), integer(), minValue(1), maxValue(ARGON2_MAX_TIME)),
    p: pipe(number(), integer(), minValue(1), maxValue(ARGON2_MAX_PARALLELISM)),
    salt: nonEmptyStringSchema,
    verifier: entryRecordSchema,
  }),
  strictObject({
    version: number(),
    kdf: literal(LEGACY_KDF),
    n: scryptNSchema,
    r: scryptRSchema,
    p: scryptPSchema,
    salt: nonEmptyStringSchema,
    verifier: entryRecordSchema,
  }),
])

function result<T>(parsed: { success: boolean; output?: unknown }): SchemaResult<T> {
  return parsed.success ? { success: true, output: parsed.output as T } : { success: false }
}

/** Validate the legacy standalone vault-document shape. */
export function validateVaultDocumentShape(input: unknown): SchemaResult<VaultDocumentShape> {
  return result<VaultDocumentShape>(safeParse(vaultDocumentSchema, input))
}

/** Validate the current or legacy encrypted credential-store shape. */
export function validateEncryptedStoreShape(input: unknown): SchemaResult<EncryptedStoreShape> {
  return result<EncryptedStoreShape>(safeParse(encryptedStoreSchema, input))
}

/** Validate a password key-file shape. */
export function validatePasswordKeyFileShape(input: unknown): SchemaResult<PasswordKeyFileShape> {
  return result<PasswordKeyFileShape>(safeParse(passwordKeyFileSchema, input))
}

/** Validate a remember block without accepting unknown fields. */
export function validateRememberBlockShape(input: unknown): SchemaResult<RememberBlock> {
  return result<RememberBlock>(safeParse(rememberBlockSchema, input))
}
