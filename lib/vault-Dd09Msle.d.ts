import { CredentialRecord } from "@deepseek-ai/dsh-credentials";
//#region src/domain/vault/model.d.ts
/** Stable domain constants and types for encrypted credential documents. */
/** Document schema version. v3 stretches the password digest with Argon2id. */
declare const VAULT_VERSION: 3;
/**
 * Encrypted-document version that adds the sealed `records` section (the
 * credential seam's second key space). v3 documents have no records and still
 * parse; a store writes v4 the first time it holds one.
 */
declare const RECORD_VAULT_VERSION: 4;
/** Algorithm identifier persisted in the document and asserted on parse. */
declare const VAULT_ALGORITHM: "aes-256-gcm+sha3-256";
/** KDF marker written by v3 documents. */
declare const VAULT_KDF: "argon2id";
/** KDF marker of legacy v2 documents. */
declare const LEGACY_KDF: "scrypt";
/** KDF input marker persisted in encrypted stores. */
declare const VAULT_KDF_INPUT: "sha3-256-password";
/** Format marker persisted in encrypted stores. */
declare const ENCRYPTED_STORE_FORMAT: "dsh-encrypt-credentials";
/** Fixed reference for a key verifier record. */
declare const KEY_FILE_VERIFIER_REF: "DSH_CREDENTIAL_MASTER_VERIFIER";
/** Fixed reference for the wrapped master key inside a remember block. */
declare const REMEMBER_KEY_REF: "remember_key";
/** Current remembered-login block format. Version 2 authenticates its policy metadata. */
declare const REMEMBER_BLOCK_VERSION: 2;
declare const MASTER_KEY_BYTES: 32;
declare const NONCE_BYTES: 12;
declare const TAG_BYTES: 16;
declare const PASSWORD_SALT_BYTES: 16;
declare const REMEMBER_DAY_MS: 86400000;
declare const ARGON2_MEMORY_KIB: 65536;
declare const ARGON2_TIME: 3;
declare const ARGON2_PARALLELISM: 1;
declare const ARGON2_MAX_MEMORY_KIB: 65536;
declare const ARGON2_MAX_TIME: 3;
declare const ARGON2_MAX_PARALLELISM: 1;
declare const SCRYPT_N: 131072;
declare const SCRYPT_R: 8;
declare const SCRYPT_P: 1;
declare const SCRYPT_MAXMEM: number;
interface EntryRecord {
  data: string;
  sha3: string;
}
/**
 * Which key seals one stored record. `password` records are AES-256-GCM
 * ciphertext under the Argon2id password key: unreadable while the vault is
 * locked. `machine` records are ciphertext under the installation's records
 * key (kept in the runtime state file): always readable, so boot-time
 * consumers such as the local browser-session secret survive a locked boot.
 */
type RecordSeal = "password" | "machine";
/** One plaintext record as stored in a plain document. */
interface PlainRecordValue {
  form: "plain";
  record: CredentialRecord;
}
/** One sealed record as stored in an encrypted document. */
interface SealedRecordValue {
  form: "sealed";
  kind: CredentialRecord["kind"];
  seal: RecordSeal;
  entry: EntryRecord;
}
/** One record slot in the in-memory snapshot; the form follows the document form. */
type RecordValue = PlainRecordValue | SealedRecordValue;
interface Argon2Params {
  m: number;
  t: number;
  p: number;
}
interface ScryptParams {
  n: number;
  r: number;
  p: number;
}
type KdfParams = Argon2Params | ScryptParams;
type KdfName = typeof VAULT_KDF | typeof LEGACY_KDF;
interface RememberBlock {
  /** Absent only on legacy blocks, which password unlock can replace but ticket unlock refuses. */
  version?: typeof REMEMBER_BLOCK_VERSION | undefined;
  salt: string;
  issuedAt: number;
  days: number;
  cipher: EntryRecord;
}
interface ParsedEncryptedStore {
  salt: Buffer;
  params: KdfParams;
  kdf: KdfName;
  verifier: EntryRecord;
  entries: Map<string, EntryRecord>;
  records: Map<string, SealedRecordValue>;
  remember?: RememberBlock | undefined;
  documentSha3: string;
}
/** Vault failure with a stable machine-readable code. */
declare class VaultError extends Error {
  code: string;
  constructor(code: string, message: string, details?: Record<string, unknown>);
}
//#endregion
//#region src/infrastructure/crypto/vault-crypto.d.ts
/** Lowercase hex SHA3-256 of a UTF-8 text. */
declare function sha3_256Hex(text: string): string;
/** Whether a text is a valid lowercase hex SHA3-256 digest. */
declare function isDigest(value: unknown): value is string;
/** Erase a mutable key buffer. */
declare function zeroizeBuffer(buffer: Buffer): void;
/** Generate a fresh 256-bit master key. */
declare function generateMasterKey(): Buffer;
/** Encode a master key as base64url. */
declare function encodeMasterKey(key: Buffer): string;
/** Parse a base64url or hexadecimal master key. */
declare function parseMasterKey(text: string): Buffer;
/** Generate a fresh salt for password-key derivation. */
declare function generatePasswordSalt(): Buffer;
/** Default Argon2id parameters. */
declare function argon2Defaults(): Argon2Params;
/** Derive a master key with the selected document KDF. */
declare function deriveMasterKey(digest: string, salt: Buffer, params?: KdfParams, kdf?: KdfName): Promise<Buffer>;
/** Derive a key with Argon2id under bounded resource parameters. */
declare function deriveArgon2idKey(digest: string, salt: Buffer, params: Argon2Params): Promise<Buffer>;
/** Derive a legacy version-2 document key with scrypt. */
declare function deriveScryptKey(digest: string, salt: Buffer, params: ScryptParams): Promise<Buffer>;
/** Serialize the standalone password-key file kept for API compatibility. */
declare function createPasswordKeyFile(key: Buffer, salt: Buffer, params?: Argon2Params): string;
/** Whether text is a supported standalone password-key file. */
declare function isPasswordKeyFile(text: string): boolean;
/** Parse a standalone password-key file and authenticate its password. */
declare function parsePasswordKeyFile(text: string, password: string): Promise<Buffer>;
/** Validate an entry record and its SHA3-256 fingerprint. */
declare function verifyEntryRecord(ref: string, record: unknown): asserts record is EntryRecord;
/** Encrypt one secret and bind it to its credential reference with GCM AAD. */
declare function encryptEntry(key: Buffer, ref: string, plaintext: string): EntryRecord;
/**
 * Encrypt one record payload and bind it to its credential key with GCM AAD.
 * The record grammar is disjoint from the reference grammar, so a record
 * ciphertext can never authenticate as an entry ciphertext and vice versa.
 */
declare function encryptRecordPayload(key: Buffer, recordKey: string, plaintext: string): EntryRecord;
/** Decrypt one entry into an erasure-capable buffer. */
declare function decryptEntryBuffer(key: Buffer, ref: string, record: unknown): Buffer;
/** Decrypt one record payload into an erasure-capable buffer. */
declare function decryptRecordPayloadBuffer(key: Buffer, recordKey: string, record: unknown): Buffer;
/** Decrypt one entry into an immutable string and erase its intermediate buffer. */
declare function decryptEntry(key: Buffer, ref: string, record: unknown): string;
/** Decrypt one record payload into an immutable string and erase its intermediate buffer. */
declare function decryptRecordPayload(key: Buffer, recordKey: string, record: unknown): string;
//#endregion
//#region src/infrastructure/persistence/vault-document.d.ts
/** Serialize the legacy standalone vault-document shape. */
declare function serializeDocument(entries: Map<string, EntryRecord>): string;
/** Parse and verify the legacy standalone vault-document shape. */
declare function parseDocument(text: string): {
  entries: Map<string, EntryRecord>;
  documentSha3: string;
};
/** Verify a standalone vault document and discard its parsed entries. */
declare function verifyDocument(text: string): void;
/** Detect whether credential text carries the encrypted-store marker. */
declare function detectCredentialStore(text: string): "encrypted" | "plain";
/**
 * Serialize a current or legacy encrypted credential store. The document is
 * fully determined by the snapshot, its parameters, and the key verifier: the
 * master key is only an input for creating a fresh verifier when none is
 * supplied, which is what lets a locked provider rewrite the document (a
 * machine-sealed record, a record deletion) without the password key.
 */
declare function serializeEncryptedStore(entries: Map<string, EntryRecord>, key: Buffer | undefined, salt: Buffer, params?: KdfParams, remember?: RememberBlock, kdf?: KdfName, records?: ReadonlyMap<string, SealedRecordValue>, verifier?: EntryRecord): string;
/** Parse and verify a current or legacy encrypted credential store. */
declare function parseEncryptedStore(text: string): ParsedEncryptedStore;
//#endregion
//#region src/infrastructure/persistence/plain-credential-document.d.ts
/** Document layout version for the versioned plaintext form. */
declare const PLAIN_DOCUMENT_VERSION: 1;
/** Everything one plaintext document holds. */
interface PlainCredentialDocument {
  refs: Map<string, string>;
  records: Map<string, CredentialRecord>;
  /** Top-level keys this build does not define; the caller reports them. */
  ignoredKeys: string[];
}
/** One edit to apply to the plaintext document. */
type PlainDocumentEdit = {
  kind: "ref";
  ref: string;
  value: string | undefined;
} | {
  kind: "record";
  key: string;
  record: CredentialRecord | undefined;
};
/**
 * Parse a plaintext credential document in either layout.
 * @param text - the document's text.
 * @param filename - absolute path, quoted in errors.
 * @returns the parsed references, records, and ignored top-level keys.
 * @throws Error or TypeError naming the document and the defect; no stored
 *   value is quoted in a diagnostic.
 */
declare function parsePlainDocument(text: string, filename: string): PlainCredentialDocument;
/**
 * Render one plaintext edit in the versioned layout while preserving YAML
 * comments of an already-versioned or recognized flat document.
 * @param text - the current document text, or `undefined` for a new document.
 * @param edit - the reference or record to set, or to remove when its value
 *   is `undefined`.
 * @returns the rendered document text.
 */
declare function renderPlainDocument(text: string | undefined, edit: PlainDocumentEdit): string;
//#endregion
//#region src/application/password-service.d.ts
interface EncryptedStoreCreation {
  text: string;
  key: Buffer;
  entries: Map<string, EntryRecord>;
  records: Map<string, SealedRecordValue>;
  verifier: EntryRecord;
  salt: Buffer;
  params: Argon2Params;
}
/** Unlock an encrypted store and return only the state required by consumers. */
declare function unlockEncryptedStore(text: string, digest: string): Promise<Omit<ParsedEncryptedStore, "documentSha3"> & {
  key: Buffer;
}>;
/** Authenticate a password digest and immediately erase the derived key. */
declare function verifyPasswordDigest(text: string, digest: string): Promise<void>;
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
declare function encryptCredentialStore(plaintexts: Map<string, string>, digest: string, params?: Argon2Params, sealRecords?: (key: Buffer) => Map<string, SealedRecordValue>): Promise<EncryptedStoreCreation>;
//#endregion
//#region src/application/remember-service.d.ts
/** Whether a remembered-login block remains inside its configured window. */
declare function rememberActive(remember: RememberBlock, now?: number): boolean;
/** Wrap a master key under a fresh browser-held remembered-login ticket. */
declare function createRememberBlock(key: Buffer, days: number, now?: number): {
  block: RememberBlock;
  secret: string;
};
/** Recover and authenticate a master key from a remembered-login ticket. */
declare function recoverKeyFromRemember(text: string, secretText: string): Omit<ParsedEncryptedStore, "documentSha3"> & {
  key: Buffer;
  remember: RememberBlock;
};
//#endregion
export { MASTER_KEY_BYTES as $, encryptRecordPayload as A, ARGON2_MAX_MEMORY_KIB as B, decryptRecordPayload as C, deriveScryptKey as D, deriveMasterKey as E, parseMasterKey as F, ARGON2_TIME as G, ARGON2_MAX_TIME as H, parsePasswordKeyFile as I, EntryRecord as J, Argon2Params as K, sha3_256Hex as L, generatePasswordSalt as M, isDigest as N, encodeMasterKey as O, isPasswordKeyFile as P, LEGACY_KDF as Q, verifyEntryRecord as R, decryptEntryBuffer as S, deriveArgon2idKey as T, ARGON2_MEMORY_KIB as U, ARGON2_MAX_PARALLELISM as V, ARGON2_PARALLELISM as W, KdfName as X, KEY_FILE_VERIFIER_REF as Y, KdfParams as Z, serializeEncryptedStore as _, VAULT_ALGORITHM as _t, encryptCredentialStore as a, REMEMBER_DAY_MS as at, createPasswordKeyFile as b, VAULT_VERSION as bt, PLAIN_DOCUMENT_VERSION as c, RecordValue as ct, parsePlainDocument as d, SCRYPT_N as dt, NONCE_BYTES as et, renderPlainDocument as f, SCRYPT_P as ft, serializeDocument as g, TAG_BYTES as gt, parseEncryptedStore as h, SealedRecordValue as ht, EncryptedStoreCreation as i, RECORD_VAULT_VERSION as it, generateMasterKey as j, encryptEntry as k, PlainCredentialDocument as l, RememberBlock as lt, parseDocument as m, ScryptParams as mt, recoverKeyFromRemember as n, ParsedEncryptedStore as nt, unlockEncryptedStore as o, REMEMBER_KEY_REF as ot, detectCredentialStore as p, SCRYPT_R as pt, ENCRYPTED_STORE_FORMAT as q, rememberActive as r, PlainRecordValue as rt, verifyPasswordDigest as s, RecordSeal as st, createRememberBlock as t, PASSWORD_SALT_BYTES as tt, PlainDocumentEdit as u, SCRYPT_MAXMEM as ut, verifyDocument as v, VAULT_KDF as vt, decryptRecordPayloadBuffer as w, decryptEntry as x, VaultError as xt, argon2Defaults as y, VAULT_KDF_INPUT as yt, zeroizeBuffer as z };
//# sourceMappingURL=vault-Dd09Msle.d.ts.map