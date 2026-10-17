import { a as isPlainRecord, i as isCredentialReference, n as isAsciiLowerHex, r as isCredentialKeyName, s as trimTrailingCharacter, t as isAsciiHex } from "./primitives-D0BudhaR.js";
import { n as sha3_256Hex, t as sha3_256Bytes } from "./sha3-BheHhOm6.js";
import { credentialRef } from "@deepseek-ai/dsh-credentials";
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from "node:crypto";
import { hashRaw } from "@node-rs/argon2";
import { check, finite, integer, literal, maxValue, minValue, nonEmpty, nullable, number, optional, pipe, record, safeParse, strictObject, string, union, unknown } from "valibot";
import { Document, isMap, isScalar, parseDocument } from "yaml";
//#region src/domain/vault/model.ts
/** Stable domain constants and types for encrypted credential documents. */
/** Document schema version. v3 stretches the password digest with Argon2id. */
const VAULT_VERSION = 3;
/**
* Encrypted-document version that adds the sealed `records` section (the
* credential seam's second key space). v3 documents have no records and still
* parse; a store writes v4 the first time it holds one.
*/
const RECORD_VAULT_VERSION = 4;
/** Algorithm identifier persisted in the document and asserted on parse. */
const VAULT_ALGORITHM = "aes-256-gcm+sha3-256";
/** KDF marker written by v3 documents. */
const VAULT_KDF = "argon2id";
/** KDF marker of legacy v2 documents. */
const LEGACY_KDF = "scrypt";
/** KDF input marker persisted in encrypted stores. */
const VAULT_KDF_INPUT = "sha3-256-password";
/** Format marker persisted in encrypted stores. */
const ENCRYPTED_STORE_FORMAT = "dsh-encrypt-credentials";
/** Fixed reference for a key verifier record. */
const KEY_FILE_VERIFIER_REF = "DSH_CREDENTIAL_MASTER_VERIFIER";
/** Fixed reference for the wrapped master key inside a remember block. */
const REMEMBER_KEY_REF = "remember_key";
const MASTER_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const PASSWORD_SALT_BYTES = 16;
const REMEMBER_DAY_MS = 864e5;
const ARGON2_MEMORY_KIB = 65536;
const ARGON2_TIME = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_MAX_MEMORY_KIB = 65536;
const ARGON2_MAX_TIME = 3;
const ARGON2_MAX_PARALLELISM = 1;
const SCRYPT_N = 131072;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 268435456;
const SCRYPT_MAX_N = 131072;
/** Vault failure with a stable machine-readable code. */
var VaultError = class extends Error {
	code;
	constructor(code, message, details) {
		super(`dsh-encrypt: ${message}`);
		this.name = "VaultError";
		this.code = code;
		if (details !== void 0 && details !== null && typeof details === "object") Object.assign(this, details);
	}
};
//#endregion
//#region src/domain/vault/schemas.ts
const nonEmptyStringSchema = pipe(string(), nonEmpty());
const credentialReferenceSchema = pipe(string(), check(isCredentialReference));
const scryptNSchema = pipe(number(), integer(), minValue(2), maxValue(SCRYPT_MAX_N));
const scryptRSchema = pipe(number(), integer(), minValue(1), maxValue(8));
const scryptPSchema = pipe(number(), integer(), minValue(1), maxValue(1));
const entryRecordSchema = strictObject({
	data: string(),
	sha3: string()
});
const entriesSchema = record(credentialReferenceSchema, entryRecordSchema);
const rememberDaysSchema = union([literal(-1), pipe(number(), integer(), minValue(1), maxValue(30))]);
const rememberBlockSchema = strictObject({
	version: optional(literal(2)),
	salt: nonEmptyStringSchema,
	issuedAt: pipe(number(), finite(), minValue(0)),
	days: rememberDaysSchema,
	cipher: entryRecordSchema
});
const vaultDocumentSchema = strictObject({
	version: literal(3),
	algorithm: literal(VAULT_ALGORITHM),
	sha3: string(),
	entries: entriesSchema
});
const encryptedStoreBaseEntries = {
	format: literal(ENCRYPTED_STORE_FORMAT),
	algorithm: literal(VAULT_ALGORITHM),
	kdfInput: literal(VAULT_KDF_INPUT),
	salt: nonEmptyStringSchema,
	verifier: entryRecordSchema,
	remember: optional(nullable(rememberBlockSchema)),
	entries: entriesSchema,
	sha3: string()
};
const legacyEncryptedStoreSchema = strictObject({
	...encryptedStoreBaseEntries,
	version: literal(2),
	kdf: literal(LEGACY_KDF),
	n: scryptNSchema,
	r: scryptRSchema,
	m: optional(unknown()),
	t: optional(unknown()),
	p: scryptPSchema
});
const argon2EncryptedStoreSchema = strictObject({
	...encryptedStoreBaseEntries,
	version: literal(3),
	kdf: literal(VAULT_KDF),
	m: pipe(number(), integer(), minValue(8), maxValue(ARGON2_MAX_MEMORY_KIB)),
	t: pipe(number(), integer(), minValue(1), maxValue(3)),
	n: optional(unknown()),
	r: optional(unknown()),
	p: pipe(number(), integer(), minValue(1), maxValue(1))
});
const recordKindSchema = union([literal("api-key"), literal("grant")]);
const recordSealSchema = union([literal("password"), literal("machine")]);
const sealedRecordEntrySchema = strictObject({
	kind: recordKindSchema,
	seal: recordSealSchema,
	data: string(),
	sha3: string()
});
const sealedRecordsSchema = record(pipe(string(), check(isCredentialKeyName)), sealedRecordEntrySchema);
const recordedEncryptedStoreSchema = strictObject({
	...encryptedStoreBaseEntries,
	version: literal(4),
	kdf: literal(VAULT_KDF),
	m: pipe(number(), integer(), minValue(8), maxValue(ARGON2_MAX_MEMORY_KIB)),
	t: pipe(number(), integer(), minValue(1), maxValue(3)),
	n: optional(unknown()),
	r: optional(unknown()),
	p: pipe(number(), integer(), minValue(1), maxValue(1)),
	records: sealedRecordsSchema
});
const encryptedStoreSchema = union([
	legacyEncryptedStoreSchema,
	argon2EncryptedStoreSchema,
	recordedEncryptedStoreSchema
]);
const passwordKeyFileSchema = union([strictObject({
	version: number(),
	kdf: literal(VAULT_KDF),
	m: pipe(number(), integer(), minValue(8), maxValue(ARGON2_MAX_MEMORY_KIB)),
	t: pipe(number(), integer(), minValue(1), maxValue(3)),
	p: pipe(number(), integer(), minValue(1), maxValue(1)),
	salt: nonEmptyStringSchema,
	verifier: entryRecordSchema
}), strictObject({
	version: number(),
	kdf: literal(LEGACY_KDF),
	n: scryptNSchema,
	r: scryptRSchema,
	p: scryptPSchema,
	salt: nonEmptyStringSchema,
	verifier: entryRecordSchema
})]);
function result(parsed) {
	return parsed.success ? {
		success: true,
		output: parsed.output
	} : { success: false };
}
/** Validate the legacy standalone vault-document shape. */
function validateVaultDocumentShape(input) {
	return result(safeParse(vaultDocumentSchema, input));
}
/** Validate the current or legacy encrypted credential-store shape. */
function validateEncryptedStoreShape(input) {
	return result(safeParse(encryptedStoreSchema, input));
}
/** Validate a password key-file shape. */
function validatePasswordKeyFileShape(input) {
	return result(safeParse(passwordKeyFileSchema, input));
}
/** Validate a remember block without accepting unknown fields. */
function validateRememberBlockShape(input) {
	return result(safeParse(rememberBlockSchema, input));
}
//#endregion
//#region src/infrastructure/crypto/vault-crypto.ts
const KEY_FILE_VERIFIER_TEXT = "dsh-encrypt master-key verifier";
/** Whether a text is a valid lowercase hex SHA3-256 digest. */
function isDigest(value) {
	return isAsciiLowerHex(value, 64);
}
/** Erase a mutable key buffer. */
function zeroizeBuffer(buffer) {
	buffer.fill(0);
}
/** Generate a fresh 256-bit master key. */
function generateMasterKey() {
	return randomBytes(32);
}
/** Encode a master key as base64url. */
function encodeMasterKey(key) {
	assertMasterKey(key);
	return key.toString("base64url");
}
/** Parse a base64url or hexadecimal master key. */
function parseMasterKey(text) {
	if (typeof text !== "string") throw new VaultError("MASTER_KEY_INVALID", "the master key must be text (base64url or 64 hex digits)");
	const value = text.trim();
	if (value.length === 0) throw new VaultError("MASTER_KEY_INVALID", "the master key is empty");
	let key;
	if (isAsciiHex(value, 64)) key = Buffer.from(value, "hex");
	else {
		try {
			key = Buffer.from(value, "base64url");
		} catch {
			throw new VaultError("MASTER_KEY_INVALID", "the master key is neither 64 hex digits nor base64url");
		}
		if (trimTrailingCharacter(key.toString("base64url"), "=") !== trimTrailingCharacter(value, "=")) throw new VaultError("MASTER_KEY_INVALID", "the master key is neither 64 hex digits nor base64url");
	}
	if (key.length !== 32) throw new VaultError("MASTER_KEY_INVALID", `the master key must decode to 32 bytes, got ${key.length}`);
	return key;
}
/** Generate a fresh salt for password-key derivation. */
function generatePasswordSalt() {
	return randomBytes(16);
}
/** Default Argon2id parameters. */
function argon2Defaults() {
	return {
		m: ARGON2_MEMORY_KIB,
		t: 3,
		p: 1
	};
}
/** Derive a master key with the selected document KDF. */
async function deriveMasterKey(digest, salt, params = argon2Defaults(), kdf = VAULT_KDF) {
	if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
	if (!Buffer.isBuffer(salt) || salt.length === 0) throw new VaultError("MASTER_KEY_INVALID", "a password salt must be a non-empty buffer");
	if (kdf === "scrypt") return deriveScryptKey(digest, salt, params);
	if (kdf === "argon2id") return deriveArgon2idKey(digest, salt, params);
	throw new VaultError("MASTER_KEY_INVALID", `unsupported kdf ${String(kdf)}`);
}
/** Derive a key with Argon2id under bounded resource parameters. */
async function deriveArgon2idKey(digest, salt, params) {
	if (!Number.isInteger(params.m) || params.m < 8 || params.m > 65536) throw new VaultError("MASTER_KEY_INVALID", `argon2id memory cost must be an integer from 8 through ${ARGON2_MAX_MEMORY_KIB} KiB`);
	if (!Number.isInteger(params.t) || params.t < 1 || params.t > 3) throw new VaultError("MASTER_KEY_INVALID", `argon2id time cost must be an integer from 1 through 3`);
	if (!Number.isInteger(params.p) || params.p < 1 || params.p > 1) throw new VaultError("MASTER_KEY_INVALID", `argon2id parallelism must be an integer from 1 through 1`);
	const raw = await hashRaw(Buffer.from(digest, "utf8"), {
		algorithm: 2,
		salt,
		outputLen: 32,
		memoryCost: params.m,
		timeCost: params.t,
		parallelism: params.p
	});
	const key = Buffer.from(raw);
	if (key.length < 32) throw new VaultError("MASTER_KEY_INVALID", "argon2id produced fewer than 32 bytes");
	return key.subarray(0, 32);
}
/** Derive a legacy version-2 document key with scrypt. */
async function deriveScryptKey(digest, salt, params) {
	if (!Number.isInteger(params.n) || !Number.isInteger(params.r) || !Number.isInteger(params.p) || params.n < 2 || params.n > 131072 || !Number.isInteger(Math.log2(params.n)) || params.r < 1 || params.r > 8 || params.p < 1 || params.p > 1) throw new VaultError("MASTER_KEY_INVALID", "scrypt parameters exceed the supported resource bounds");
	return new Promise((resolve, reject) => {
		scrypt(digest, salt, 32, {
			N: params.n,
			r: params.r,
			p: params.p,
			maxmem: SCRYPT_MAXMEM
		}, (error, key) => {
			if (error !== null) reject(error);
			else resolve(key);
		});
	});
}
/** Encrypt the fixed key-verifier plaintext. */
function createKeyVerifier(key) {
	return encryptEntry(key, KEY_FILE_VERIFIER_REF, KEY_FILE_VERIFIER_TEXT);
}
/** Serialize the standalone password-key file kept for API compatibility. */
function createPasswordKeyFile(key, salt, params = argon2Defaults()) {
	assertMasterKey(key);
	const document = {
		version: 1,
		kdf: VAULT_KDF,
		m: params.m,
		t: params.t,
		p: params.p,
		salt: salt.toString("base64url"),
		verifier: createKeyVerifier(key)
	};
	return `${JSON.stringify(document, null, 2)}\n`;
}
/** Whether text is a supported standalone password-key file. */
function isPasswordKeyFile(text) {
	try {
		return validatePasswordKeyFileShape(JSON.parse(text)).success;
	} catch {
		return false;
	}
}
/** Parse a standalone password-key file and authenticate its password. */
async function parsePasswordKeyFile(text, password) {
	let document;
	try {
		document = JSON.parse(text);
	} catch {
		throw new VaultError("MASTER_KEY_INVALID", "the key file is neither a legacy raw key nor a password key file");
	}
	const validated = validatePasswordKeyFileShape(document);
	if (!validated.success || validated.output === void 0) throw new VaultError("MASTER_KEY_INVALID", "unsupported password key-file format");
	const keyFile = validated.output;
	const salt = Buffer.from(keyFile.salt, "base64url");
	const key = keyFile.kdf === "scrypt" ? await deriveScryptKey(password, salt, {
		n: keyFile.n,
		r: keyFile.r,
		p: keyFile.p
	}) : await deriveArgon2idKey(password, salt, {
		m: keyFile.m,
		t: keyFile.t,
		p: keyFile.p
	});
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, keyFile.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("PASSWORD_WRONG", "the password does not match this master-key file");
		throw error;
	}
	return key;
}
/** Validate an entry record and its SHA3-256 fingerprint. */
function verifyEntryRecord(ref, record) {
	if (!isPlainRecord(record) || typeof record.data !== "string" || typeof record.sha3 !== "string") throw new VaultError("VAULT_INVALID", `entry "${ref}" must map to { data, sha3 } strings`);
	if (fingerprint(record.data) !== record.sha3) throw new VaultError("VAULT_CORRUPTED", `entry "${ref}" failed its SHA3-256 integrity check: the stored ciphertext does not match its fingerprint`);
}
/** Encrypt one secret and bind it to its credential reference with GCM AAD. */
function encryptEntry(key, ref, plaintext) {
	assertMasterKey(key);
	if (!isCredentialReference(ref)) throw new VaultError("VAULT_INVALID", `reference "${ref}" is not a credential reference`);
	if (typeof plaintext !== "string" || plaintext.length === 0) throw new VaultError("VAULT_INVALID", `the plaintext for "${ref}" must be a non-empty string`);
	return sealText(key, ref, plaintext);
}
/**
* Encrypt one record payload and bind it to its credential key with GCM AAD.
* The record grammar is disjoint from the reference grammar, so a record
* ciphertext can never authenticate as an entry ciphertext and vice versa.
*/
function encryptRecordPayload(key, recordKey, plaintext) {
	assertMasterKey(key);
	if (!isCredentialKeyName(recordKey)) throw new VaultError("VAULT_INVALID", `record key "${recordKey}" is not a credential key (scope/id)`);
	if (typeof plaintext !== "string" || plaintext.length === 0) throw new VaultError("VAULT_INVALID", `the record payload for "${recordKey}" must be a non-empty string`);
	return sealText(key, recordKey, plaintext);
}
/** Decrypt one entry into an erasure-capable buffer. */
function decryptEntryBuffer(key, ref, record) {
	assertMasterKey(key);
	if (!isCredentialReference(ref)) throw new VaultError("VAULT_INVALID", `reference "${ref}" is not a credential reference`);
	verifyEntryRecord(ref, record);
	return openText(key, ref, record);
}
/** Decrypt one record payload into an erasure-capable buffer. */
function decryptRecordPayloadBuffer(key, recordKey, record) {
	assertMasterKey(key);
	if (!isCredentialKeyName(recordKey)) throw new VaultError("VAULT_INVALID", `record key "${recordKey}" is not a credential key (scope/id)`);
	verifyEntryRecord(recordKey, record);
	return openText(key, recordKey, record);
}
/** Decrypt one entry into an immutable string and erase its intermediate buffer. */
function decryptEntry(key, ref, record) {
	const plain = decryptEntryBuffer(key, ref, record);
	const text = plain.toString("utf8");
	zeroizeBuffer(plain);
	return text;
}
/** Decrypt one record payload into an immutable string and erase its intermediate buffer. */
function decryptRecordPayload(key, recordKey, record) {
	const plain = decryptRecordPayloadBuffer(key, recordKey, record);
	const text = plain.toString("utf8");
	zeroizeBuffer(plain);
	return text;
}
/** Seal UTF-8 text as `nonce ‖ ciphertext ‖ tag` base64url with the AAD label. */
function sealText(key, label, plaintext) {
	const nonce = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", key, nonce);
	cipher.setAAD(Buffer.from(label, "utf8"));
	const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	const data = Buffer.concat([
		nonce,
		ciphertext,
		tag
	]).toString("base64url");
	return {
		data,
		sha3: fingerprint(data)
	};
}
/** Open one verified ciphertext under the AAD label. */
function openText(key, label, record) {
	let blob;
	try {
		blob = Buffer.from(record.data, "base64url");
	} catch {
		throw new VaultError("VAULT_CORRUPTED", `entry "${label}" is not valid base64url`);
	}
	if (blob.length <= 28) throw new VaultError("VAULT_CORRUPTED", `entry "${label}" is truncated`);
	const nonce = blob.subarray(0, 12);
	const tag = blob.subarray(blob.length - 16);
	const ciphertext = blob.subarray(12, blob.length - 16);
	try {
		const decipher = createDecipheriv("aes-256-gcm", key, nonce);
		decipher.setAAD(Buffer.from(label, "utf8"));
		decipher.setAuthTag(tag);
		return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
	} catch {
		throw new VaultError("VAULT_KEY_MISMATCH", `entry "${label}" failed AES-256-GCM authentication: the master key does not match this document, or the ciphertext was replaced`);
	}
}
function assertMasterKey(key) {
	if (!Buffer.isBuffer(key) || key.length !== 32) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
}
function fingerprint(data) {
	return sha3_256Hex(data);
}
//#endregion
//#region src/infrastructure/persistence/vault-document.ts
const STORE_FIELDS = [
	"format",
	"version",
	"algorithm",
	"kdf",
	"kdfInput",
	"n",
	"r",
	"m",
	"t",
	"p",
	"salt",
	"verifier",
	"remember",
	"entries",
	"records"
];
/** Serialize the legacy standalone vault-document shape. */
function serializeDocument(entries) {
	const canonical = canonicalEntries(Object.fromEntries(entries));
	const block = JSON.stringify(canonical);
	const document = {
		version: 3,
		algorithm: VAULT_ALGORITHM,
		sha3: hashText(block),
		entries: canonical
	};
	return `${JSON.stringify(document, null, 2)}\n`;
}
/** Parse and verify the legacy standalone vault-document shape. */
function parseDocument$1(text) {
	const validated = validateVaultDocumentShape(parseJson(text, "the vault document is not valid JSON"));
	if (!validated.success || validated.output === void 0) throw new VaultError("VAULT_INVALID", "the vault document does not match the supported schema");
	const document = validated.output;
	const actual = hashText(JSON.stringify(canonicalEntries(document.entries)));
	if (actual !== document.sha3) throw new VaultError("VAULT_CORRUPTED", "the vault document failed its SHA3-256 integrity check: entries were added, removed, swapped, or altered");
	return {
		entries: verifiedEntries(document.entries),
		documentSha3: actual
	};
}
/** Verify a standalone vault document and discard its parsed entries. */
function verifyDocument(text) {
	parseDocument$1(text);
}
/** Detect whether credential text carries the encrypted-store marker. */
function detectCredentialStore(text) {
	const trimmed = text.trim();
	if (trimmed.length === 0) return "plain";
	try {
		const document = JSON.parse(trimmed);
		return isPlainRecord(document) && document.format === "dsh-encrypt-credentials" ? "encrypted" : "plain";
	} catch {
		return "plain";
	}
}
/**
* Serialize a current or legacy encrypted credential store. The document is
* fully determined by the snapshot, its parameters, and the key verifier: the
* master key is only an input for creating a fresh verifier when none is
* supplied, which is what lets a locked provider rewrite the document (a
* machine-sealed record, a record deletion) without the password key.
*/
function serializeEncryptedStore(entries, key, salt, params = argon2Defaults(), remember, kdf = VAULT_KDF, records, verifier) {
	if (verifier !== void 0) verifyEntryRecord(KEY_FILE_VERIFIER_REF, verifier);
	else if (!Buffer.isBuffer(key) || key.length !== 32) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	if (!Buffer.isBuffer(salt) || salt.length === 0) throw new VaultError("MASTER_KEY_INVALID", "a password salt must be a non-empty buffer");
	if (remember !== void 0 && !validateRememberBlockShape(remember).success) throw new VaultError("VAULT_INVALID", "the store's remember block does not match the supported schema");
	if (kdf !== "argon2id" && kdf !== "scrypt") throw new VaultError("MASTER_KEY_INVALID", `unsupported store kdf ${String(kdf)}`);
	const sealed = records === void 0 || records.size === 0 ? void 0 : canonicalSealedRecords(records);
	const document = {
		format: ENCRYPTED_STORE_FORMAT,
		version: kdf === "scrypt" ? 2 : sealed === void 0 ? 3 : 4,
		algorithm: VAULT_ALGORITHM,
		kdf,
		kdfInput: VAULT_KDF_INPUT,
		salt: salt.toString("base64url"),
		verifier: verifier ?? createKeyVerifier(key),
		entries: canonicalEntries(Object.fromEntries(entries))
	};
	if (kdf === "scrypt") {
		const legacy = params;
		document.n = legacy.n;
		document.r = legacy.r;
		document.p = legacy.p;
	} else {
		const current = params;
		document.m = current.m;
		document.t = current.t;
		document.p = current.p;
	}
	if (remember !== void 0) document.remember = remember;
	if (sealed !== void 0) document.records = sealed;
	document.sha3 = hashText(JSON.stringify(fingerprintTarget(document)));
	return `${JSON.stringify(document, null, 2)}\n`;
}
/** Parse and verify a current or legacy encrypted credential store. */
function parseEncryptedStore(text) {
	const input = parseJson(text, "the encrypted credential store is not valid JSON");
	if (!isPlainRecord(input) || input.format !== "dsh-encrypt-credentials") throw new VaultError("VAULT_INVALID", `the document is not a ${ENCRYPTED_STORE_FORMAT} store`);
	if (input.version === 1) throw new VaultError("VAULT_INVALID", "unsupported store version 1; a store encrypted by dsh-encrypt ≤ 0.1.0-rc.6 must be unlocked and returned to plaintext with that version first");
	const validated = validateEncryptedStoreShape(input);
	if (!validated.success || validated.output === void 0) throw new VaultError("VAULT_INVALID", "the encrypted credential store does not match the supported schema");
	return buildParsedStore(validated.output);
}
function buildParsedStore(store) {
	const actual = hashText(JSON.stringify(fingerprintTarget(store)));
	if (actual !== store.sha3) throw new VaultError("VAULT_CORRUPTED", "the encrypted credential store failed its SHA3-256 integrity check: its header, entries, or records were altered");
	const remember = store.remember ?? void 0;
	if (remember !== void 0) verifyEntryRecord(REMEMBER_KEY_REF, remember.cipher);
	verifyEntryRecord(KEY_FILE_VERIFIER_REF, store.verifier);
	return {
		salt: Buffer.from(store.salt, "base64url"),
		params: store.kdf === "scrypt" ? {
			n: store.n,
			r: store.r,
			p: store.p
		} : {
			m: store.m,
			t: store.t,
			p: store.p
		},
		kdf: store.kdf,
		verifier: store.verifier,
		entries: verifiedEntries(store.entries),
		records: "records" in store ? verifiedSealedRecords(store.records) : /* @__PURE__ */ new Map(),
		remember,
		documentSha3: actual
	};
}
function canonicalEntries(entries) {
	const sorted = {};
	for (const ref of Object.keys(entries).sort()) {
		const record = entries[ref];
		if (record === void 0) throw new VaultError("VAULT_INVALID", `entry "${ref}" is missing`);
		sorted[ref] = record;
	}
	return sorted;
}
function canonicalSealedRecords(records) {
	const sorted = {};
	for (const key of [...records.keys()].sort()) {
		const slot = records.get(key);
		if (slot === void 0) throw new VaultError("VAULT_INVALID", `record "${key}" is missing`);
		if (!isCredentialKeyName(key)) throw new VaultError("VAULT_INVALID", `record key "${key}" is not a credential key`);
		sorted[key] = {
			kind: slot.kind,
			seal: slot.seal,
			data: slot.entry.data,
			sha3: slot.entry.sha3
		};
	}
	return sorted;
}
function verifiedEntries(records) {
	const entries = /* @__PURE__ */ new Map();
	for (const [ref, record] of Object.entries(records)) {
		verifyEntryRecord(ref, record);
		entries.set(ref, record);
	}
	return entries;
}
function verifiedSealedRecords(records) {
	const sealed = /* @__PURE__ */ new Map();
	for (const [key, record] of Object.entries(records)) {
		verifyEntryRecord(key, record);
		sealed.set(key, {
			form: "sealed",
			kind: record.kind,
			seal: record.seal,
			entry: {
				data: record.data,
				sha3: record.sha3
			}
		});
	}
	return sealed;
}
function fingerprintTarget(document) {
	const target = {};
	for (const field of STORE_FIELDS) if (document[field] !== void 0) target[field] = document[field];
	return target;
}
function hashText(text) {
	return sha3_256Hex(text);
}
function parseJson(text, message) {
	try {
		return JSON.parse(text);
	} catch {
		throw new VaultError("VAULT_INVALID", message);
	}
}
//#endregion
//#region src/application/remember-service.ts
const REMEMBER_TICKET_DOMAIN = "dsh-encrypt-remember-ticket";
/** Whether a remembered-login block remains inside its configured window. */
function rememberActive(remember, now = Date.now()) {
	if (remember.issuedAt > now) return false;
	return remember.days === -1 || now - remember.issuedAt <= remember.days * 864e5;
}
/** Wrap a master key under a fresh browser-held remembered-login ticket. */
function createRememberBlock(key, days, now = Date.now()) {
	if (!Buffer.isBuffer(key) || key.length !== 32) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	if (!Number.isInteger(days) || days !== -1 && (days < 1 || days > 30)) throw new VaultError("PASSWORD_INVALID", "remembered-login days must be 1..30 or -1 (forever)");
	const salt = generatePasswordSalt();
	const secret = randomBytes(32);
	const blockBase = {
		version: 2,
		salt: salt.toString("base64url"),
		issuedAt: now,
		days
	};
	const wrappingKey = ticketKey(salt, secret);
	try {
		const cipher = encryptEntry(wrappingKey, rememberKeyReference(blockBase), encodeMasterKey(key));
		return {
			block: {
				...blockBase,
				cipher
			},
			secret: secret.toString("base64url")
		};
	} finally {
		zeroizeBuffer(wrappingKey);
		zeroizeBuffer(secret);
	}
}
/** Recover and authenticate a master key from a remembered-login ticket. */
function recoverKeyFromRemember(text, secretText) {
	const parsed = parseEncryptedStore(text);
	if (parsed.remember === void 0) throw new VaultError("REMEMBER_INVALID", "this credential store has no remembered login");
	if (parsed.remember.version !== 2) throw new VaultError("REMEMBER_INVALID", "the remembered login uses an expired ticket format");
	if (!rememberActive(parsed.remember)) throw new VaultError("REMEMBER_EXPIRED", "the remembered login has expired; enter the password again");
	const secret = parseRememberSecret(secretText);
	let key;
	let wrappingKey;
	try {
		wrappingKey = ticketKey(Buffer.from(parsed.remember.salt, "base64url"), secret);
		key = parseMasterKey(decryptEntry(wrappingKey, rememberKeyReference(parsed.remember), parsed.remember.cipher));
	} catch (error) {
		throwRememberInvalid(error);
	} finally {
		if (wrappingKey !== void 0) zeroizeBuffer(wrappingKey);
		zeroizeBuffer(secret);
	}
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, parsed.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		throwRememberInvalid(error);
	}
	return {
		key,
		entries: parsed.entries,
		records: parsed.records,
		verifier: parsed.verifier,
		salt: parsed.salt,
		params: parsed.params,
		kdf: parsed.kdf,
		remember: parsed.remember
	};
}
function parseRememberSecret(secretText) {
	if (typeof secretText !== "string" || secretText.length === 0) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket is empty");
	let secret;
	try {
		secret = Buffer.from(secretText, "base64url");
	} catch {
		throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket is not valid base64url");
	}
	if (secret.length !== 32) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket must decode to 32 bytes");
	return secret;
}
function ticketKey(salt, secret) {
	return sha3_256Bytes(Buffer.concat([
		Buffer.from(REMEMBER_TICKET_DOMAIN, "utf8"),
		salt,
		secret
	]));
}
/** Bind every expiry-policy field to the GCM tag through a credential-safe AAD reference. */
function rememberKeyReference(remember) {
	const metadata = JSON.stringify({
		version: remember.version,
		salt: remember.salt,
		issuedAt: remember.issuedAt,
		days: remember.days
	});
	return `${REMEMBER_KEY_REF}_${sha3_256Hex(metadata)}`;
}
function throwRememberInvalid(error) {
	if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket does not match this credential store");
	throw error;
}
//#endregion
//#region src/domain/vault/records.ts
/**
* Credential-record payload validation shared by the three boundaries a
* record crosses: the plain YAML document, the encrypted document's sealed
* payloads, and the seam's `modifyRecord` input. The rules match the
* credentials seam: an api-key record carries an optional non-empty `key` and
* optional POSIX-named environment values, a grant record carries an opaque
* payload that must survive a JSON round trip (so a locked document can never
* hold a value a JSON document cannot spell), and a typo in a tag or field is
* rejected rather than silently dropped.
* @module dsh-encrypt/domain/vault/records
*/
/**
* Check one candidate record.
* @param value - the candidate, from a document or a seam consumer.
* @returns `undefined` when the value is a valid record; otherwise a message
*   naming the defect without repeating any stored value.
*/
function credentialRecordIssue(value) {
	if (!isPlainRecord(value)) return "must be a mapping";
	const kind = value.kind;
	if (kind === "api-key") {
		const extra = unknownFieldIssue(value, [
			"kind",
			"key",
			"env"
		]);
		if (extra !== void 0) return extra;
		const key = value.key;
		if (key !== void 0 && (typeof key !== "string" || key.length === 0)) return "has a non-string or empty key";
		return envIssue(value.env);
	}
	if (kind === "grant") {
		const extra = unknownFieldIssue(value, ["kind", "payload"]);
		if (extra !== void 0) return extra;
		if (!("payload" in value)) return "has no payload";
		return jsonValueIssue("payload", value.payload, /* @__PURE__ */ new Set());
	}
	if (kind === void 0) return "has no kind";
	return `has unknown kind ${JSON.stringify(kind)}`;
}
/** Reject a field the tag does not define. */
function unknownFieldIssue(value, allowed) {
	for (const field of Object.keys(value)) if (!allowed.includes(field)) return `has unknown field "${field}"`;
}
/** Admit an api-key record's provider environment: POSIX names over non-empty strings. */
function envIssue(env) {
	if (env === void 0) return void 0;
	if (!isPlainRecord(env)) return "has a non-mapping env";
	for (const [name, value] of Object.entries(env)) {
		if (!isCredentialReference(name)) return `env name "${name}" is not a credential reference`;
		if (typeof value !== "string" || value.length === 0) return `env "${name}" must be a non-empty string`;
	}
}
/**
* Reject a payload that cannot survive a JSON round trip: a double that
* JSON cannot spell, an alias cycle, or a class instance, `Date`, or `bigint`
* this document has no faithful JSON spelling for. Neither the value nor any
* nested value is quoted in a diagnostic.
*/
function jsonValueIssue(where, value, seen) {
	if (value === null || typeof value === "string" || typeof value === "boolean") return void 0;
	if (typeof value === "number") return Number.isFinite(value) ? void 0 : `${where} holds a non-finite number`;
	if (typeof value === "object") {
		if (seen.has(value)) return `${where} is cyclic`;
		if (Object.getPrototypeOf(value) === Object.prototype || Array.isArray(value)) {
			seen.add(value);
			for (const nested of Object.values(value)) {
				const issue = jsonValueIssue(where, nested, seen);
				if (issue !== void 0) return issue;
			}
			seen.delete(value);
			return;
		}
	}
	return `${where} holds a value JSON cannot represent`;
}
//#endregion
//#region src/infrastructure/persistence/plain-credential-document.ts
/** Document layout version for the versioned plaintext form. */
const PLAIN_DOCUMENT_VERSION = 1;
/**
* Parse a plaintext credential document in either layout.
* @param text - the document's text.
* @param filename - absolute path, quoted in errors.
* @returns the parsed references, records, and ignored top-level keys.
* @throws Error or TypeError naming the document and the defect; no stored
*   value is quoted in a diagnostic.
*/
function parsePlainDocument(text, filename) {
	const document = parseDocument(text, {
		prettyErrors: true,
		uniqueKeys: true
	});
	if (document.errors.length > 0) throw new Error(`dsh-encrypt: invalid document at ${filename}: ${document.errors.map((error) => {
		const at = error.linePos?.[0];
		return `${error.code}${at === void 0 ? "" : ` at line ${String(at.line)}, column ${String(at.col)}`}`;
	}).join("; ")}`);
	const root = document.toJS() ?? {};
	if (!isPlainRecord(root)) throw new TypeError(`dsh-encrypt: ${filename} must be a mapping of credential reference to value`);
	const keys = Object.keys(root);
	if (keys.length === 0) return {
		refs: /* @__PURE__ */ new Map(),
		records: /* @__PURE__ */ new Map(),
		ignoredKeys: []
	};
	if (typeof root.version === "number") {
		if (root.version !== 1) throw new Error(`dsh-encrypt: ${filename} declares version ${JSON.stringify(root.version)}; this build reads version 1`);
		return {
			refs: parseRefs(root.refs, filename),
			records: parseRecords(root.records, filename),
			ignoredKeys: keys.filter((key) => key !== "version" && key !== "refs" && key !== "records")
		};
	}
	return {
		refs: parseRefs(root, filename),
		records: /* @__PURE__ */ new Map(),
		ignoredKeys: []
	};
}
/**
* Render one plaintext edit in the versioned layout while preserving YAML
* comments of an already-versioned or recognized flat document.
* @param text - the current document text, or `undefined` for a new document.
* @param edit - the reference or record to set, or to remove when its value
*   is `undefined`.
* @returns the rendered document text.
*/
function renderPlainDocument(text, edit) {
	const document = baseDocument(text);
	if (edit.kind === "ref") {
		if (edit.value === void 0) document.deleteIn(["refs", edit.ref]);
		else document.setIn(["refs", edit.ref], edit.value);
	} else if (edit.record === void 0) document.deleteIn(["records", edit.key]);
	else document.setIn(["records", edit.key], edit.record);
	dropEmptySections(document);
	return document.toString();
}
/**
* Pick the document to edit: a fresh versioned skeleton, the migrated flat
* layout when it is recognized exactly, the versioned layout in place, or —
* for accepted-but-unrecognized text such as a document with directives — a
* fresh versioned document rebuilt from its parsed references.
*/
function baseDocument(text) {
	if (text === void 0) return versionedDocument();
	const migrated = migratedFlatLayout(text);
	if (migrated !== void 0) return parseDocument(migrated);
	const parsed = parseDocument(text, {
		prettyErrors: true,
		uniqueKeys: true
	});
	const root = parsed.errors.length === 0 ? parsed.toJS() ?? {} : void 0;
	if (isPlainRecord(root) && root.version === 1) return parsed;
	const rebuilt = versionedDocument();
	for (const [ref, value] of parsePlainDocument(text, "the plaintext credential document").refs) rebuilt.setIn(["refs", ref], value);
	return rebuilt;
}
/** A fresh `version: 1` document. */
function versionedDocument() {
	const document = new Document({});
	document.setIn(["version"], 1);
	return document;
}
/**
* Render the versioned layout for the pre-port flat document, or `undefined`
* for anything else. The layout is recognized exactly: a non-empty top-level
* mapping of reference names to non-empty string scalars, no numeric
* `version` marker, and no document directives. Anything else keeps whatever
* base document the caller selected.
*/
function migratedFlatLayout(text) {
	const document = parseDocument(text, {
		prettyErrors: true,
		uniqueKeys: true
	});
	if (document.errors.length > 0) return void 0;
	const flat = document.contents;
	if (!isMap(flat) || flat.items.length === 0) return void 0;
	for (const line of text.split("\n")) if (line.startsWith("%") || line.startsWith("---") || line.startsWith("...")) return void 0;
	for (const pair of flat.items) {
		if (!isScalar(pair.key) || typeof pair.key.value !== "string") return void 0;
		if (pair.key.value === "version" && isScalar(pair.value) && typeof pair.value.value === "number") return void 0;
		try {
			credentialRef(pair.key.value);
		} catch {
			return;
		}
		if (!isScalar(pair.value) || typeof pair.value.value !== "string" || pair.value.value.length === 0) return void 0;
	}
	return `version: 1\nrefs:\n${text.split("\n").map((line) => line.length === 0 ? line : `  ${line}`).join("\n")}${text.endsWith("\n") ? "" : "\n"}`;
}
/** Drop a `refs` or `records` section the last edit emptied. */
function dropEmptySections(document) {
	for (const section of ["refs", "records"]) {
		const contents = document.getIn([section]);
		if (isMap(contents) && contents.items.length === 0) document.deleteIn([section]);
	}
}
/** Parse one `refs` (or flat root) section: reference names to non-empty strings. */
function parseRefs(section, filename) {
	const refs = /* @__PURE__ */ new Map();
	for (const [ref, value] of Object.entries(asSection(section, "refs", filename))) {
		credentialRef(ref);
		if (typeof value !== "string") throw new TypeError(`dsh-encrypt: the value for "${ref}" in ${filename} must be a string`);
		if (value.length === 0) throw new Error(`dsh-encrypt: the value for "${ref}" in ${filename} is empty; remove the key instead`);
		refs.set(ref, value);
	}
	return refs;
}
/** Parse the `records` section: credential keys to validated records. */
function parseRecords(section, filename) {
	const records = /* @__PURE__ */ new Map();
	for (const [key, value] of Object.entries(asSection(section, "records", filename))) {
		if (!isCredentialKeyName(key)) throw new TypeError(`dsh-encrypt: record key "${key}" in ${filename} is not a credential key (scope/id)`);
		const issue = credentialRecordIssue(value);
		if (issue !== void 0) throw new TypeError(`dsh-encrypt: record "${key}" in ${filename} ${issue}`);
		records.set(key, value);
	}
	return records;
}
/** Read one document section as a mapping, absent sections being empty. */
function asSection(section, name, filename) {
	if (section === void 0 || section === null) return {};
	if (!isPlainRecord(section)) throw new TypeError(`dsh-encrypt: the ${name} section in ${filename} must be a mapping`);
	return section;
}
//#endregion
//#region src/application/password-service.ts
/** Unlock an encrypted store and return only the state required by consumers. */
async function unlockEncryptedStore(text, digest) {
	const { key, parsed } = await deriveVerifiedKey(text, digest);
	return {
		key,
		entries: parsed.entries,
		records: parsed.records,
		verifier: parsed.verifier,
		salt: parsed.salt,
		params: parsed.params,
		kdf: parsed.kdf,
		remember: parsed.remember
	};
}
/** Authenticate a password digest and immediately erase the derived key. */
async function verifyPasswordDigest(text, digest) {
	const { key } = await deriveVerifiedKey(text, digest);
	zeroizeBuffer(key);
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
async function encryptCredentialStore(plaintexts, digest, params = argon2Defaults(), sealRecords) {
	assertPasswordDigest(digest);
	const salt = generatePasswordSalt();
	const key = await deriveArgon2idKey(digest, salt, params);
	const entries = /* @__PURE__ */ new Map();
	for (const [ref, value] of plaintexts) {
		if (!isCredentialReference(ref)) throw new VaultError("VAULT_INVALID", `entry key "${ref}" is not a credential reference`);
		if (typeof value !== "string" || value.length === 0) throw new VaultError("VAULT_INVALID", `entry "${ref}" must be a non-empty string`);
		entries.set(ref, encryptEntry(key, ref, value));
	}
	const records = sealRecords === void 0 ? /* @__PURE__ */ new Map() : sealRecords(key);
	const verifier = createKeyVerifier(key);
	return {
		text: serializeEncryptedStore(entries, key, salt, params, void 0, VAULT_KDF, records, verifier),
		key,
		entries,
		records,
		verifier,
		salt,
		params
	};
}
async function deriveVerifiedKey(text, digest) {
	assertPasswordDigest(digest);
	const parsed = parseEncryptedStore(text);
	const key = await deriveMasterKey(digest, parsed.salt, parsed.params, parsed.kdf);
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, parsed.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("PASSWORD_WRONG", "the password digest does not match this credential store");
		throw error;
	}
	return {
		key,
		parsed
	};
}
function assertPasswordDigest(digest) {
	if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
}
//#endregion
export { SCRYPT_N as $, generatePasswordSalt as A, ARGON2_MEMORY_KIB as B, deriveArgon2idKey as C, encryptEntry as D, encodeMasterKey as E, verifyEntryRecord as F, LEGACY_KDF as G, ARGON2_TIME as H, zeroizeBuffer as I, PASSWORD_SALT_BYTES as J, MASTER_KEY_BYTES as K, ARGON2_MAX_MEMORY_KIB as L, isPasswordKeyFile as M, parseMasterKey as N, encryptRecordPayload as O, parsePasswordKeyFile as P, SCRYPT_MAXMEM as Q, ARGON2_MAX_PARALLELISM as R, decryptRecordPayloadBuffer as S, deriveScryptKey as T, ENCRYPTED_STORE_FORMAT as U, ARGON2_PARALLELISM as V, KEY_FILE_VERIFIER_REF as W, REMEMBER_DAY_MS as X, RECORD_VAULT_VERSION as Y, REMEMBER_KEY_REF as Z, argon2Defaults as _, parsePlainDocument as a, VAULT_KDF_INPUT as at, decryptEntryBuffer as b, createRememberBlock as c, detectCredentialStore as d, SCRYPT_P as et, parseDocument$1 as f, verifyDocument as g, serializeEncryptedStore as h, PLAIN_DOCUMENT_VERSION as i, VAULT_KDF as it, isDigest as j, generateMasterKey as k, recoverKeyFromRemember as l, serializeDocument as m, unlockEncryptedStore as n, TAG_BYTES as nt, renderPlainDocument as o, VAULT_VERSION as ot, parseEncryptedStore as p, NONCE_BYTES as q, verifyPasswordDigest as r, VAULT_ALGORITHM as rt, credentialRecordIssue as s, VaultError as st, encryptCredentialStore as t, SCRYPT_R as tt, rememberActive as u, createPasswordKeyFile as v, deriveMasterKey as w, decryptRecordPayload as x, decryptEntry as y, ARGON2_MAX_TIME as z };

//# sourceMappingURL=vault-C7Wp8Tfo.js.map