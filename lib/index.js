import { a as isPlainRecord } from "./primitives-D0BudhaR.js";
import { detectDshRuntime } from "./compat.js";
import { D as encryptEntry, E as encodeMasterKey, F as sha3_256Hex, L as zeroizeBuffer, N as parseMasterKey, O as encryptRecordPayload, Z as REMEMBER_DAY_MS, _ as argon2Defaults, a as parsePlainDocument, at as VAULT_KDF, b as decryptEntryBuffer, c as createRememberBlock, ct as VaultError, d as detectCredentialStore, h as serializeEncryptedStore, j as isDigest, k as generateMasterKey, l as recoverKeyFromRemember, n as unlockEncryptedStore, o as renderPlainDocument, p as parseEncryptedStore, r as verifyPasswordDigest, s as credentialRecordIssue, t as encryptCredentialStore, u as rememberActive, x as decryptRecordPayload, y as decryptEntry } from "./vault-GdInQTdi.js";
import { loadAndVerifyIntegrity } from "./integrity.js";
import { t as LeakGuard } from "./leak-guard-Demfexa5.js";
import { formatLockoutMessage, isLockedOut, recordLockoutFailure } from "./lockout.js";
import { constants } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { lstat, mkdir, open } from "node:fs/promises";
import { Service } from "@deepseek-ai/cordis";
import { withFileLock, writeFileAtomic } from "@deepseek-ai/dsh-atomic-write";
import { CredentialProvider, credentialRef, parseCredentialKey } from "@deepseek-ai/dsh-credentials";
import { canonicalizeWatchPath, resolveDshHome } from "@deepseek-ai/dsh-home-paths";
import { launchEnvironmentOf } from "@deepseek-ai/dsh-launch-environment";
import z from "@deepseek-ai/schemastery";
import { watch } from "chokidar";
import { boolean, check, finite, integer, maxValue, minValue, number, pipe, safeParse, string } from "valibot";
//#region src/application/operation-queue.ts
/** A failure-isolated serial task queue for document mutations. */
var OperationQueue = class {
	#tail = Promise.resolve();
	/** Run one operation after all earlier operations have settled. */
	run(operation) {
		const task = this.#tail.then(operation);
		this.#tail = task.then(() => void 0, () => void 0);
		return task;
	}
	/** Resolve after the current queue tail has settled. */
	idle() {
		return this.#tail;
	}
};
//#endregion
//#region src/application/provider-policy.ts
/**
* The record the local browser-session secret lives in. Boot-time consumers
* read or write this record before any vault password can be supplied, so it
* is always `machine`-sealed and never password-sealed — otherwise a locked
* vault would break the Web UI's own login.
*/
const LOCKED_BOOT_RECORD_KEY = "client-connection/browser-session";
/**
* Choose the seal for a record entering encrypted storage. Existing records
* keep their seal; this decides new ones. While the vault is locked no
* password key exists, so the record is machine-sealed and stays usable.
* @param key - the record's credential key.
* @param passwordAvailable - whether a password key seals this write.
* @returns the seal to assign.
*/
function sealForRecord(key, passwordAvailable) {
	return key === LOCKED_BOOT_RECORD_KEY || !passwordAvailable ? "machine" : "password";
}
/** Build a Web-safe lockout view. */
function lockoutSnapshot(failures, lockedUntil, now = Date.now()) {
	const retryAfterMs = Math.max(0, lockedUntil - now);
	return {
		failures,
		lockedUntil,
		retryAfterMs,
		locked: retryAfterMs > 0
	};
}
/** Select and bound the runtime remember setting over its configured default. */
function effectiveRememberDays(runtimeDays, configuredDays) {
	const value = runtimeDays ?? configuredDays;
	return Number.isInteger(value) && value >= -1 && value <= 30 ? value : 0;
}
/** Build a Web-safe remembered-login view. */
function rememberSnapshot(days, block, now = Date.now()) {
	return {
		days,
		active: days !== 0 && block !== void 0 && block.version === 2 && block.days === days && rememberActive(block, now),
		issuedAt: block?.issuedAt ?? null,
		expiresAt: block !== void 0 && block.days !== -1 ? block.issuedAt + block.days * REMEMBER_DAY_MS : null
	};
}
//#endregion
//#region src/domain/provider/model.ts
const CREDENTIALS_FILENAME = ".credentials.yaml";
const DEFAULT_PASSWORD_ENV = "DSH_CREDENTIAL_PASSWORD";
//#endregion
//#region src/infrastructure/persistence/provider-state.ts
const rememberDaysSchema = pipe(number(), integer(), minValue(-1), maxValue(30));
const failuresSchema = pipe(number(), integer(), minValue(0));
const timestampSchema = pipe(number(), finite(), minValue(0));
const encryptedSchema = boolean();
const recordsKeySchema = pipe(string(), check((value) => {
	try {
		parseMasterKey(value);
		return true;
	} catch {
		return false;
	}
}));
/** Validate each state field independently so one bad field cannot erase good state. */
function parseProviderRuntimeState(input) {
	if (!isPlainRecord(input)) return {
		state: {},
		invalidFields: ["document"]
	};
	const state = {};
	const invalidFields = [];
	copyField(input, state, invalidFields, "rememberDays", rememberDaysSchema);
	copyField(input, state, invalidFields, "encrypted", encryptedSchema);
	copyField(input, state, invalidFields, "unlockFailures", failuresSchema);
	copyField(input, state, invalidFields, "unlockLockedUntil", timestampSchema);
	copyField(input, state, invalidFields, "recordsKey", recordsKeySchema);
	return {
		state,
		invalidFields
	};
}
/** Serialize only meaningful provider state fields. */
function serializeProviderRuntimeState(state) {
	const document = {};
	if (state.rememberDays !== void 0 && safeParse(rememberDaysSchema, state.rememberDays).success) document.rememberDays = state.rememberDays;
	if (state.encrypted === true) document.encrypted = true;
	if (state.unlockFailures !== void 0 && state.unlockFailures > 0 && safeParse(failuresSchema, state.unlockFailures).success) document.unlockFailures = state.unlockFailures;
	if (state.unlockLockedUntil !== void 0 && state.unlockLockedUntil > 0 && safeParse(timestampSchema, state.unlockLockedUntil).success) document.unlockLockedUntil = state.unlockLockedUntil;
	if (state.recordsKey !== void 0 && safeParse(recordsKeySchema, state.recordsKey).success) document.recordsKey = state.recordsKey;
	return `${JSON.stringify(document, null, 2)}\n`;
}
function copyField(input, output, invalidFields, field, schema) {
	const value = input[field];
	if (value === void 0) return;
	const parsed = safeParse(schema, value);
	if (parsed.success) output[field] = parsed.output;
	else invalidFields.push(field);
}
//#endregion
//#region src/infrastructure/persistence/secure-file.ts
const GROUP_OTHER_BITS = 63;
const GROUP_OTHER_WRITE_BITS = 18;
/** Reject unsafe file types, ownership and POSIX permissions without following links. */
async function assertOwnerOnly(filename) {
	await assertSecureParent(filename);
	let info;
	try {
		info = await lstat(filename);
	} catch (error) {
		if (!isENOENT(error)) throw error;
		await canonicalizeWatchPath(filename);
		return;
	}
	assertSafeFileInfo(filename, info);
}
/** Read one protected UTF-8 file through a no-follow descriptor. */
async function readOwnerOnlyText(filename) {
	await assertOwnerOnly(filename);
	const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
	const handle = await open(filename, constants.O_RDONLY | constants.O_NONBLOCK | noFollow);
	try {
		assertSafeFileInfo(filename, await handle.stat());
		return await handle.readFile({ encoding: "utf8" });
	} finally {
		await handle.close();
	}
}
function assertSafeFileInfo(filename, info) {
	if (info.isSymbolicLink()) throw new Error(`dsh-encrypt: ${filename} must not be a symbolic link`);
	if (!info.isFile()) throw new Error(`dsh-encrypt: ${filename} must be a regular file`);
	if (process.platform === "win32") return;
	assertCurrentOwner(filename, info);
	if ((info.mode & GROUP_OTHER_BITS) !== 0) throw new Error(`dsh-encrypt: ${filename} is accessible beyond its owner (mode ${(info.mode & 511).toString(8)}); run "chmod 600 ${filename}" before starting again`);
}
async function assertSecureParent(filename) {
	const parent = dirname(filename);
	let info;
	try {
		info = await lstat(parent);
	} catch (error) {
		if (isENOENT(error)) return;
		throw error;
	}
	if (info.isSymbolicLink()) throw new Error(`dsh-encrypt: credential directory ${parent} must not be a symbolic link`);
	if (!info.isDirectory()) throw new Error(`dsh-encrypt: credential directory ${parent} must be a directory`);
	if (process.platform === "win32") return;
	assertCurrentOwner(parent, info);
	if ((info.mode & GROUP_OTHER_WRITE_BITS) !== 0) throw new Error(`dsh-encrypt: credential directory ${parent} is writable beyond its owner (mode ${(info.mode & 511).toString(8)})`);
}
function assertCurrentOwner(filename, info) {
	const getuid = process.getuid;
	if (typeof getuid !== "function") return;
	if (info.uid !== getuid()) throw new Error(`dsh-encrypt: ${filename} is not owned by the current user`);
}
/** Whether a filesystem error reports an absent file. */
function isENOENT(error) {
	return error?.code === "ENOENT";
}
//#endregion
//#region src/infrastructure/runtime/provider-config.ts
/** Apply provider defaults once at the composition boundary. */
function normalizeProviderConfig(config = {}) {
	const leakMinMaskLength = boundedInteger(config.leakMinMaskLength, 8, 4, 64);
	const leakMaxMaskLength = Math.max(leakMinMaskLength, boundedInteger(config.leakMaxMaskLength, 256, 16, 1024));
	const lockoutBaseMs = boundedInteger(config.lockoutBaseMs, 3e4, 1e3, 36e5);
	return {
		...config,
		allowEnvFallback: config.allowEnvFallback ?? true,
		passwordEnv: config.passwordEnv ?? "DSH_CREDENTIAL_PASSWORD",
		watch: config.watch ?? true,
		debounceMs: boundedInteger(config.debounceMs, 100, 0, 6e4),
		rememberDays: boundedInteger(config.rememberDays, 0, -1, 30),
		rememberChannel: config.rememberChannel === "header" ? "header" : "cookie",
		leakGuard: config.leakGuard ?? true,
		leakMinMaskLength,
		leakMaxMaskLength,
		maxUnlockAttempts: boundedInteger(config.maxUnlockAttempts, 5, 1, 32),
		lockoutBaseMs,
		lockoutMaxMs: Math.max(lockoutBaseMs, boundedInteger(config.lockoutMaxMs, 9e5, 1e3, 864e5))
	};
}
function boundedInteger(value, fallback, minimum, maximum) {
	if (typeof value !== "number" || !Number.isInteger(value)) return fallback;
	return Math.min(maximum, Math.max(minimum, value));
}
/** Resolve the credential and runtime-state files from provider config. */
function resolveSpec(config = {}) {
	const home = resolveDshHome(config.dshHome);
	return {
		filename: resolve(config.path ?? join(home, ".credentials.yaml")),
		stateFile: resolve(join(home, ".dsh-encrypt.json")),
		allowEnvFallback: config.allowEnvFallback ?? true,
		passwordEnv: config.passwordEnv ?? "DSH_CREDENTIAL_PASSWORD",
		watch: config.watch ?? true,
		debounceMs: config.debounceMs ?? 100
	};
}
//#endregion
//#region src/index.ts
loadAndVerifyIntegrity(import.meta.url);
/** Whether one credential changed between two snapshots (for the updated event). */
function refChanged(prev, next, ref) {
	return prev.get(ref) !== next.get(ref);
}
/** A comparable signature of one record slot (for the updated event). */
function recordSignature(slot) {
	if (slot === void 0) return "";
	return slot.form === "plain" ? `plain:${JSON.stringify(slot.record)}` : `sealed:${slot.seal}:${slot.kind}:${slot.entry.data}`;
}
/** Narrow the record snapshot to sealed entries for an encrypted-document write. */
function sealedRecordMap(records) {
	const sealed = /* @__PURE__ */ new Map();
	for (const [key, slot] of records) {
		if (slot.form !== "sealed") throw new VaultError("VAULT_INVALID", `record "${key}" is plaintext while the store form is encrypted`);
		sealed.set(key, slot);
	}
	return sealed;
}
/** Build the plain-form record snapshot from parsed records. */
function plainRecordMap(records) {
	const slots = /* @__PURE__ */ new Map();
	for (const [key, record] of records) slots.set(key, {
		form: "plain",
		record
	});
	return slots;
}
/** Narrow the entry snapshot to ciphertext records for an encrypted-document write. */
function encryptedEntryMap(entries) {
	const narrowed = /* @__PURE__ */ new Map();
	for (const [ref, value] of entries) {
		if (typeof value === "string") throw new VaultError("VAULT_INVALID", `entry "${ref}" is plaintext while the store form is encrypted`);
		narrowed.set(ref, value);
	}
	return narrowed;
}
/**
* Single-file encrypted credentials provider with a WebUI-managed password.
*/
var EncryptedCredentialProvider = class extends CredentialProvider {
	config;
	static Config = z.object({
		path: z.string(),
		dshHome: z.string(),
		allowEnvFallback: z.boolean().default(true),
		passwordEnv: z.string().default(DEFAULT_PASSWORD_ENV),
		watch: z.boolean().default(true),
		debounceMs: z.number().min(0).max(6e4).default(100),
		rememberDays: z.number().min(-1).max(30).default(0),
		/** Channel carrying the remembered-login ticket: the HttpOnly cookie (default) or the localStorage-backed header (XSS-readable; only for cookie-storage-quirky WebViews). */
		rememberChannel: z.union([z.const("cookie"), z.const("header")]).default("cookie"),
		/** Master switch for the credential leak guard (output redaction). */
		leakGuard: z.boolean().default(true),
		/** Values shorter than this are never masked (avoids prose mangling). */
		leakMinMaskLength: z.number().min(4).max(64).default(8),
		/** Values longer than this are never masked (stream lookback window). */
		leakMaxMaskLength: z.number().min(16).max(1024).default(256),
		/** Consecutive failed unlocks before the first lockout window. */
		maxUnlockAttempts: z.number().min(1).max(32).default(5),
		/** First lockout window in milliseconds (exponential from here). */
		lockoutBaseMs: z.number().min(1e3).max(36e5).default(3e4),
		/** Lockout window ceiling in milliseconds. */
		lockoutMaxMs: z.number().min(1e3).max(864e5).default(9e5)
	});
	static {
		Object.defineProperty(this.prototype, Service.init, {
			configurable: true,
			value() {
				return this.initializeService();
			},
			writable: true
		});
	}
	spec;
	/** Current on-disk form: `plain` while no password is set. */
	format = "plain";
	/** Whether the encrypted form is currently unlocked (always true in plain form). */
	unlocked = true;
	/** The derived key while unlocked; zeroized on lock/dispose. */
	key;
	/** KDF salt and cost parameters of the current encrypted document. */
	salt;
	params;
	/**
	* The current document's key verifier, kept so a locked rewrite (a
	* machine-sealed record, a deletion) can reproduce the document without
	* the password key.
	*/
	verifier;
	/** KDF of the current encrypted document: "argon2id" or legacy "scrypt". */
	kdf = VAULT_KDF;
	/**
	* The in-memory snapshot: plaintext values in the plain form, ciphertext
	* records in the encrypted form. Never both, never plaintext alongside a
	* lockable key.
	*/
	entries = /* @__PURE__ */ new Map();
	/**
	* Record snapshot: plaintext records in the plain form, sealed records in
	* the encrypted form. Never mixes the two.
	*/
	records = /* @__PURE__ */ new Map();
	/**
	* The installation records key, sealing and opening `machine`-sealed
	* records (kept in the state file, so it survives a locked restart). Not
	* password-derived and not part of the lock state.
	*/
	recordsKey;
	/**
	* Raw text of the last read or persisted document; `undefined` while the
	* file is absent. Watcher events whose content equals this cache are
	* no-ops, which is also the self-write suppression.
	*/
	text;
	/** Current remembered-login block from the encrypted document, if any. */
	remember;
	/** Runtime-overridden remembered-login window from the state file. */
	stateRememberDays;
	/** The ciphertext-only policy flag persisted in the state file. */
	stateEncrypted;
	/** True while the file holds plaintext against the ciphertext-only policy. */
	refusePlain = false;
	/** Public compatibility view of the exclusive operation chain. */
	operations = Promise.resolve();
	/** Failure-isolated serial queue used to schedule document mutations. */
	operationQueue = new OperationQueue();
	/** Set at dispose: refuse new writes and let in-flight work no-op. */
	closed = false;
	/** Leak guard: masks resolved credential values in output streams. */
	leakGuard;
	/** Consecutive failed unlock attempts (persisted in the state file). */
	unlockFailures = 0;
	/** Epoch ms until which unlocks are refused (persisted in the state file). */
	unlockLockedUntil = 0;
	/** Number of password checks admitted to the serial queue but not settled. */
	pendingUnlocks = 0;
	isClosed() {
		return this.closed;
	}
	constructor(ctx, config = {}) {
		super(ctx);
		const runtime = detectDshRuntime();
		if (runtime !== null) ctx.logger.info("dsh-encrypt: running on dsh %s", runtime.version);
		this.config = normalizeProviderConfig(config);
		this.spec = resolveSpec(this.config);
		this.leakGuard = new LeakGuard({
			enabled: this.config.leakGuard,
			minMaskLength: this.config.leakMinMaskLength,
			maxMaskLength: this.config.leakMaxMaskLength
		});
	}
	/** The WebUI-facing lockout snapshot (never secret-bearing). */
	lockoutSnapshot(now = Date.now()) {
		return lockoutSnapshot(this.unlockFailures, this.unlockLockedUntil, now);
	}
	/** Reject an unlock attempt while the lockout window is active. */
	assertUnlockAllowed(now = Date.now()) {
		if (isLockedOut(this.unlockLockedUntil, now)) throw new VaultError("TOO_MANY_ATTEMPTS", formatLockoutMessage(this.unlockLockedUntil - now), { retryAfterMs: Math.max(0, this.unlockLockedUntil - now) });
	}
	/** Count one failed unlock and (re-)arm the exponential window. */
	async recordUnlockFailure() {
		const next = recordLockoutFailure({
			failures: this.unlockFailures,
			lockedUntil: this.unlockLockedUntil
		}, {
			maxAttempts: this.config.maxUnlockAttempts,
			lockoutBaseMs: this.config.lockoutBaseMs,
			lockoutMaxMs: this.config.lockoutMaxMs
		});
		this.unlockFailures = next.failures;
		this.unlockLockedUntil = next.lockedUntil;
		await this.persistState();
		this.ctx.logger.warn("dsh-encrypt: unlock failed (attempt %d); %s", next.failures, next.retryAfterMs > 0 ? `locked out for ${Math.max(1, Math.ceil(next.retryAfterMs / 1e3))}s` : "retry allowed");
	}
	/** Reset the failure counter after a successful unlock. */
	async clearUnlockFailures() {
		if (this.unlockFailures === 0 && this.unlockLockedUntil === 0) return;
		this.unlockFailures = 0;
		this.unlockLockedUntil = 0;
		await this.persistState();
	}
	/**
	* Reconcile the leak guard's mask set with the current vault state:
	* plain form registers every entry value; a locked vault (or a refused
	* plaintext file) clears the set; an encrypted+unlocked vault keeps the
	* incrementally resolved values registered by resolve().
	*/
	syncGuard() {
		if (!this.config.leakGuard) {
			this.leakGuard.clear();
			return;
		}
		if (this.refusePlain || this.format === "encrypted" && !this.unlocked) {
			this.leakGuard.clear();
			return;
		}
		if (this.format === "plain") this.leakGuard.rebuild([...this.entries.values()]);
	}
	/** The inherited-environment value for a reference, or `undefined` when empty or unset. */
	inherited(ref) {
		if (!this.spec.allowEnvFallback) return void 0;
		const entry = launchEnvironmentOf(this.ctx).getFrom(ref, ["process"]);
		return entry !== void 0 && entry.value.length > 0 ? entry.value : void 0;
	}
	/** The read-only `.env` fallback — below the managed file, never above it. */
	dotenvFallback(ref) {
		if (!this.spec.allowEnvFallback) return void 0;
		const entry = launchEnvironmentOf(this.ctx).getFrom(ref, ["project-env", "user-env"]);
		return entry !== void 0 && entry.value.length > 0 ? entry : void 0;
	}
	async *initializeService() {
		yield async () => {
			this.closed = true;
			await this.operations;
			this.dropKey();
			this.dropRecordsKey();
			this.entries.clear();
			this.records.clear();
			this.text = void 0;
		};
		try {
			await assertOwnerOnly(this.spec.filename);
			await this.loadStateFile();
			await this.loadInitial();
			if (!this.spec.watch) return;
			const watcher = watch(await canonicalizeWatchPath(this.spec.filename), {
				ignoreInitial: true,
				awaitWriteFinish: {
					stabilityThreshold: this.spec.debounceMs,
					pollInterval: Math.max(1, Math.min(this.spec.debounceMs, 10))
				}
			});
			watcher.on("all", () => {
				if (this.closed) return;
				this.queueRefresh();
			});
			watcher.on("ready", () => {
				if (this.closed) return;
				this.queueRefresh();
			});
			watcher.on("error", (error) => {
				this.ctx.logger.warn("dsh-encrypt: watcher error on %s", this.spec.filename);
				this.ctx.logger.warn(error);
			});
			yield async () => {
				this.closed = true;
				await watcher.close();
				await this.operations;
				this.dropKey();
				this.dropRecordsKey();
			};
		} catch (error) {
			this.dropKey();
			this.dropRecordsKey();
			throw error;
		}
	}
	/** Zeroize and release the derived key (lock). */
	dropKey() {
		if (this.key !== void 0) {
			zeroizeBuffer(this.key);
			this.key = void 0;
		}
		this.unlocked = this.format === "plain";
		this.leakGuard.clear();
	}
	/** Zeroize and release the installation records key (dispose only; a lock keeps it). */
	dropRecordsKey() {
		if (this.recordsKey !== void 0) {
			zeroizeBuffer(this.recordsKey);
			this.recordsKey = void 0;
		}
	}
	/** The installation records key, generated and kept in memory on first need. */
	requireRecordsKey() {
		this.recordsKey ??= generateMasterKey();
		return this.recordsKey;
	}
	/**
	* The installation records key for opening a machine-sealed record. A
	* machine slot whose key is gone is unrecoverable, so refuse loudly rather
	* than guessing with a fresh key.
	*/
	machineRecordsKey() {
		if (this.recordsKey === void 0) throw new VaultError("VAULT_INVALID", "the installation records key is missing from the state file");
		return this.recordsKey;
	}
	/**
	* Assert the encrypted snapshot is complete enough to rewrite the document
	* — locked or not. Locked rewrites reuse the document's verifier, so the
	* password key is not required.
	*/
	assertDocumentWritable(verb) {
		if (this.format !== "encrypted" || this.salt === void 0 || this.params === void 0 || this.text === void 0) throw new VaultError("VAULT_INVALID", `cannot ${verb}: the encrypted credential store is incomplete`);
	}
	/** Serialize the current encrypted snapshot, reusing the document's verifier. */
	serializeSnapshot(entries, records, remember) {
		this.assertDocumentWritable("rewrite the credential store");
		return serializeEncryptedStore(encryptedEntryMap(entries), this.key, this.salt, this.params, remember, this.kdf, sealedRecordMap(records), this.verifier);
	}
	/**
	* Adopt sealed records from a parsed document. A `machine`-sealed record
	* without the installation key is unreadable lost ciphertext: the key
	* would have to be forged, so the entries are dropped with an error and
	* rebuilt by the consumer that owns them.
	*/
	adoptSealedRecords(records) {
		if (![...records.values()].some((slot) => slot.seal === "machine") || this.recordsKey !== void 0) {
			this.records = new Map(records);
			return;
		}
		const kept = /* @__PURE__ */ new Map();
		let dropped = 0;
		for (const [key, slot] of records) {
			if (slot.seal === "machine") {
				dropped += 1;
				continue;
			}
			kept.set(key, slot);
		}
		this.records = kept;
		this.ctx.logger.error("dsh-encrypt: %d machine-sealed record(s) are unreadable because the state file no longer carries the records key; they were dropped and will be rebuilt on the next write", dropped);
	}
	/** Open one sealed record payload into a validated record. */
	openRecord(key, entry, keyBuffer) {
		const text = decryptRecordPayload(keyBuffer, key, entry);
		let value;
		try {
			value = JSON.parse(text);
		} catch {
			throw new VaultError("VAULT_CORRUPTED", `record "${key}" does not hold valid JSON`);
		}
		const issue = credentialRecordIssue(value);
		if (issue !== void 0) throw new VaultError("VAULT_CORRUPTED", `record "${key}" ${issue}`);
		return value;
	}
	/**
	* Seal one record payload under its chosen seal. A password seal needs the
	* unlocked vault key; a machine seal needs only the installation key, so it
	* works while the vault is locked.
	*/
	sealRecord(key, record, seal, passwordKey) {
		if (seal === "machine") return {
			form: "sealed",
			kind: record.kind,
			seal,
			entry: encryptRecordPayload(this.requireRecordsKey(), key, JSON.stringify(record))
		};
		if (passwordKey === void 0) throw new VaultError("VAULT_LOCKED", `the credential record "${key}" cannot be password-sealed without the vault password`);
		return {
			form: "sealed",
			kind: record.kind,
			seal,
			entry: encryptRecordPayload(passwordKey, key, JSON.stringify(record))
		};
	}
	/**
	* Seal the current record snapshot for a new password key: plaintext
	* records take their policy seal, password-sealed records re-encrypt under
	* the new key, and machine-sealed records carry over untouched.
	*/
	sealRecordsFor(passwordKey) {
		const sealed = /* @__PURE__ */ new Map();
		for (const [key, slot] of this.records) {
			if (slot.form === "sealed") {
				if (slot.seal === "machine") {
					sealed.set(key, slot);
					continue;
				}
				this.assertUnlocked("re-seal a credential record");
				const record = this.openRecord(key, slot.entry, this.key);
				sealed.set(key, this.sealRecord(key, record, "password", passwordKey));
				continue;
			}
			sealed.set(key, this.sealRecord(key, slot.record, sealForRecord(key, true), passwordKey));
		}
		return sealed;
	}
	/**
	* Seal a plaintext record snapshot for the encrypted form during an
	* external-edit re-encryption. A machine seal needs the installation key;
	* it is generated and persisted before the ciphertext that depends on it.
	*/
	async sealRecordsFromPlain(records, passwordKey) {
		let needsMachineKey = false;
		for (const key of records.keys()) if (sealForRecord(key, true) === "machine") needsMachineKey = true;
		if (needsMachineKey && this.recordsKey === void 0) {
			this.requireRecordsKey();
			await this.persistState();
		}
		const sealed = /* @__PURE__ */ new Map();
		for (const [key, record] of records) sealed.set(key, this.sealRecord(key, record, sealForRecord(key, true), passwordKey));
		return sealed;
	}
	/**
	* Generate and persist the installation records key before a transition
	* that will machine-seal records, so the ciphertext never precedes the key
	* that opens it.
	*/
	async persistRecordsKeyIfNeeded() {
		let needed = false;
		for (const [key, slot] of this.records) if (slot.form === "plain" ? sealForRecord(key, true) === "machine" : slot.seal === "machine") needed = true;
		if (needed && this.recordsKey === void 0) {
			this.requireRecordsKey();
			await this.persistState();
		}
	}
	/** Report top-level keys the versioned plaintext layout does not define. */
	logIgnoredPlainKeys(ignoredKeys) {
		if (ignoredKeys.length === 0) return;
		this.ctx.logger.warn("dsh-encrypt: ignoring unknown keys in %s: %s", this.spec.filename, ignoredKeys.join(", "));
	}
	/**
	* Boot read: an absent file is an empty plain store. A present encrypted
	* store must pass its SHA3-256 integrity checks before activation; it then
	* boots LOCKED (unless `$DSH_CREDENTIAL_PASSWORD` supplies the password —
	* a supplied-but-wrong password fails activation, never boots locked).
	*/
	async loadInitial() {
		let text;
		try {
			text = await readOwnerOnlyText(this.spec.filename);
		} catch (error) {
			if (!isENOENT(error)) throw error;
			this.format = "plain";
			this.unlocked = true;
			this.entries = /* @__PURE__ */ new Map();
			this.records = /* @__PURE__ */ new Map();
			this.refusePlain = this.stateEncrypted === true;
			if (this.refusePlain) this.ctx.logger.error("dsh-encrypt: the encrypted credential file is missing; credential access and plaintext writes remain disabled");
			return;
		}
		if (detectCredentialStore(text) === "encrypted") {
			const parsed = parseEncryptedStore(text);
			this.format = "encrypted";
			this.salt = parsed.salt;
			this.params = parsed.params;
			this.kdf = parsed.kdf;
			this.entries = parsed.entries;
			this.adoptSealedRecords(parsed.records);
			this.verifier = parsed.verifier;
			this.remember = parsed.remember;
			this.text = text;
			this.unlocked = false;
			if (this.stateEncrypted !== true) {
				this.stateEncrypted = true;
				await this.persistState();
			}
			const ambient = launchEnvironmentOf(this.ctx).get(this.spec.passwordEnv);
			if (ambient !== void 0 && ambient.value.length > 0) {
				const digest = sha3_256Hex(ambient.value);
				const unlocked = await unlockEncryptedStore(text, digest);
				this.applyUnlock(unlocked);
				if (unlocked.kdf === "scrypt") await this.upgradeKdf(digest);
				await this.revokeRememberIfDisabled();
			}
			return;
		}
		this.format = "plain";
		this.unlocked = true;
		const parsed = parsePlainDocument(text, this.spec.filename);
		this.logIgnoredPlainKeys(parsed.ignoredKeys);
		this.entries = parsed.refs;
		this.records = plainRecordMap(parsed.records);
		this.verifier = void 0;
		this.text = text;
		this.syncGuard();
		if (this.stateEncrypted === true) {
			this.refusePlain = true;
			this.ctx.logger.error("dsh-encrypt: %s holds PLAINTEXT credentials while ciphertext is required; credential resolution is refused until the password is set again", this.spec.filename);
		}
	}
	/** Apply an unlock result to the snapshot (used by boot env unlock and the API). */
	applyUnlock(unlocked) {
		this.key = unlocked.key;
		this.entries = unlocked.entries;
		this.adoptSealedRecords(unlocked.records);
		this.verifier = unlocked.verifier;
		this.salt = unlocked.salt;
		this.params = unlocked.params;
		this.kdf = unlocked.kdf ?? "argon2id";
		this.remember = unlocked.remember;
		this.unlocked = true;
		this.leakGuard.clear();
		for (const [key, slot] of this.records) if (slot.form === "sealed" && slot.seal === "password") this.notifyRecordUpdated(parseCredentialKey(key));
	}
	/**
	* Resolve one reference per operation: plaintext value, or a decrypted
	* transient value while unlocked. Never cached between operations.
	* @param ref - the reference to resolve.
	* @returns value and source, or `undefined` while unconfigured.
	*/
	resolve(ref) {
		if (this.refusePlain) return Promise.reject(new VaultError("VAULT_INVALID", "the credential file was replaced with plaintext while ciphertext is required; set the password again in Settings → 加密安全 to re-encrypt it"));
		const inherited = this.inherited(ref);
		if (inherited !== void 0) {
			this.leakGuard.add(inherited, ref);
			return Promise.resolve({
				value: inherited,
				source: "env"
			});
		}
		const record = this.entries.get(ref);
		if (record !== void 0) try {
			if (this.format === "encrypted") {
				if (!this.unlocked) return Promise.reject(new VaultError("VAULT_LOCKED", `the credential store is locked; unlock it in Settings → 加密安全 (or export ${this.spec.passwordEnv})`));
				if (this.key === void 0) return Promise.reject(new VaultError("VAULT_LOCKED", "the credential store has no active key"));
				const value = decryptEntry(this.key, ref, record);
				this.leakGuard.add(value, ref);
				return Promise.resolve({
					value,
					source: "file"
				});
			}
			if (typeof record !== "string") return Promise.reject(new VaultError("VAULT_INVALID", `the plain credential "${ref}" is not text`));
			this.leakGuard.add(record, ref);
			return Promise.resolve({
				value: record,
				source: "file"
			});
		} catch (error) {
			return Promise.reject(error);
		}
		const fallback = this.dotenvFallback(ref);
		if (fallback !== void 0) {
			this.leakGuard.add(fallback.value, ref);
			return Promise.resolve({
				value: fallback.value,
				source: fallback.source
			});
		}
		return Promise.resolve(void 0);
	}
	/**
	* Run `fn` with one reference temporarily unlocked. The plaintext argument
	* lives for the callback and is dropped with it.
	* @param ref - the reference to unlock.
	* @param fn - the consumer; receives the plaintext or `undefined` while unconfigured.
	* @returns the callback's result.
	*/
	async withUnlocked(ref, fn) {
		const hit = await this.resolve(ref);
		return fn(hit === void 0 ? void 0 : hit.value);
	}
	/**
	* Burn-after-read variant: run `fn` with the plaintext as a mutable
	* Buffer and zeroize it in a finally block once the callback settles.
	* JavaScript strings are immutable, so the string seam above can only
	* drop references — this buffer copy is the erasure-capable path.
	* @param ref - the reference to unlock.
	* @param fn - the consumer; receives the plaintext buffer or `undefined`.
	* @returns the callback's result.
	*/
	async withUnlockedBuffer(ref, fn) {
		const hit = await this.resolve(ref);
		if (hit === void 0) return fn(void 0);
		let buffer;
		if (this.format === "encrypted" && this.key !== void 0) buffer = decryptEntryBuffer(this.key, ref, this.entries.get(ref));
		else buffer = Buffer.from(hit.value, "utf8");
		try {
			return await fn(buffer);
		} finally {
			zeroizeBuffer(buffer);
		}
	}
	/** The WebUI-facing snapshot: form, lock state, remembered-login, lockout and leak-guard state. */
	async status() {
		return Promise.resolve({
			format: this.format,
			unlocked: this.unlocked,
			plaintextForbidden: this.refusePlain,
			remember: this.rememberState(),
			lockout: this.lockoutSnapshot(),
			leakGuard: {
				enabled: this.config.leakGuard,
				masks: this.leakGuard.size()
			},
			rememberChannel: this.config.rememberChannel
		});
	}
	/**
	* Unlock the encrypted store with the password's SHA3-256 digest (the
	* WebUI derives it; the raw password never reaches this process).
	* @param digest - the lowercase hex SHA3-256 digest of the password.
	*/
	async unlock(digest) {
		if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
		if (this.isClosed()) throw new Error("dsh-encrypt is disposed");
		const pendingLimit = Math.max(1, Math.min(8, this.config.maxUnlockAttempts));
		if (this.pendingUnlocks >= pendingLimit) throw new VaultError("TOO_MANY_ATTEMPTS", "too many unlock requests are already pending", { retryAfterMs: 1e3 });
		this.pendingUnlocks += 1;
		try {
			return await this.enqueue(() => this.unlockQueued(digest));
		} finally {
			this.pendingUnlocks -= 1;
		}
	}
	/** Perform one admitted unlock inside the provider's exclusive operation queue. */
	async unlockQueued(digest) {
		if (this.isClosed()) throw new Error("dsh-encrypt was disposed before the queued unlock ran");
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store has no password; nothing to unlock");
		if (this.unlocked) return { unlocked: true };
		this.assertUnlockAllowed();
		await this.reconcileFromDisk();
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store no longer has a password (the file was changed externally)");
		if (this.unlocked) return { unlocked: true };
		if (this.text === void 0) throw new VaultError("VAULT_INVALID", "the encrypted credential store has no document text");
		const sourceText = this.text;
		let unlocked;
		try {
			unlocked = await unlockEncryptedStore(sourceText, digest);
		} catch (error) {
			if (error instanceof VaultError && error.code === "PASSWORD_WRONG") await this.recordUnlockFailure();
			throw error;
		}
		await this.reconcileFromDisk();
		if (this.text !== sourceText || this.format !== "encrypted" || this.unlocked) {
			zeroizeBuffer(unlocked.key);
			throw new VaultError("VAULT_CHANGED", "the credential store changed while it was being unlocked; try again");
		}
		this.applyUnlock(unlocked);
		if (unlocked.kdf === "scrypt") await this.upgradeKdf(digest);
		await this.clearUnlockFailures();
		await this.revokeRememberIfDisabled();
		return { unlocked: true };
	}
	/**
	* Re-encrypt a legacy scrypt (v2) store into the Argon2id (v3) format
	* after a password unlock: every entry is decrypted under the legacy key
	* and re-encrypted under a fresh Argon2id salt/key derived from the same
	* digest, then the document is replaced in place. The legacy key is
	* zeroized; a remembered-login block wrapping it is dropped.
	* @param digest - lowercase hex SHA3-256 digest of the password.
	*/
	async upgradeKdf(digest) {
		this.assertUnlocked("upgrade the KDF");
		const plaintexts = /* @__PURE__ */ new Map();
		for (const [ref, record] of this.entries) plaintexts.set(ref, decryptEntry(this.key, ref, record));
		const created = await encryptCredentialStore(plaintexts, digest, argon2Defaults(), (key) => this.sealRecordsFor(key));
		plaintexts.clear();
		await withFileLock(this.spec.filename, async () => {
			await this.reconcileFromDisk();
			if (!this.unlocked || this.key === void 0) throw new VaultError("VAULT_LOCKED", "the credential store locked while upgrading its KDF; unlock it again");
			await writeFileAtomic(this.spec.filename, created.text, {
				mode: 384,
				dirMode: 448
			});
			this.text = created.text;
			this.entries = created.entries;
			this.records = created.records;
			this.verifier = created.verifier;
			this.salt = created.salt;
			this.params = created.params;
			this.remember = void 0;
			this.dropKey();
			this.key = created.key;
			this.kdf = VAULT_KDF;
			this.unlocked = true;
			this.leakGuard.clear();
			this.ctx.logger.warn("dsh-encrypt: legacy scrypt store upgraded to argon2id in place");
		});
	}
	/**
	* Set the first password: the file's plaintext contents are replaced by
	* the encrypted document in place, and the provider stays unlocked. Any
	* previous remembered-login block dies with the old plain form.
	* @param digest - lowercase hex SHA3-256 digest of the new password.
	*/
	async setPassword(digest) {
		if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
		if (this.format === "encrypted") throw new VaultError("VAULT_ALREADY_ENCRYPTED", "the credential store already has a password; use changePassword");
		return this.passwordTransition(async () => {
			const plaintexts = this.entries;
			await this.persistRecordsKeyIfNeeded();
			const created = await encryptCredentialStore(plaintexts, digest, argon2Defaults(), (key) => this.sealRecordsFor(key));
			await writeFileAtomic(this.spec.filename, created.text, {
				mode: 384,
				dirMode: 448
			});
			this.text = created.text;
			this.format = "encrypted";
			this.unlocked = true;
			this.entries = created.entries;
			this.records = created.records;
			this.verifier = created.verifier;
			this.salt = created.salt;
			this.params = created.params;
			this.kdf = VAULT_KDF;
			this.key = created.key;
			this.remember = void 0;
			this.refusePlain = false;
			this.stateEncrypted = true;
			this.leakGuard.clear();
			await this.persistState();
		});
	}
	/**
	* Change the password of the encrypted store (must be unlocked). The
	* caller must prove knowledge of the CURRENT password: `oldDigest` is
	* verified against the AEAD verifier before anything is re-encrypted, so
	* a merely unlocked store is not enough to take it over. Every entry is
	* then re-encrypted under the new derived key, and the old
	* remembered-login block dies with the old key. A wrong `oldDigest`
	* counts as a failed unlock (lockout); a correct one clears the counter.
	* @param {string} oldDigest - lowercase hex SHA3-256 digest of the current password.
	* @param {string} digest - lowercase hex SHA3-256 digest of the new password.
	*/
	async changePassword(oldDigest, digest) {
		if (!isDigest(oldDigest)) throw new VaultError("PASSWORD_INVALID", "the current password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
		if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the new password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
		this.assertUnlocked("change the password");
		this.assertUnlockAllowed();
		return this.passwordTransition(async () => {
			this.assertUnlocked("change the password");
			this.assertUnlockAllowed();
			try {
				await verifyPasswordDigest(this.text, oldDigest);
			} catch (error) {
				if (error instanceof VaultError && error.code === "PASSWORD_WRONG") await this.recordUnlockFailure();
				throw error;
			}
			const plaintexts = /* @__PURE__ */ new Map();
			for (const [ref, record] of this.entries) plaintexts.set(ref, decryptEntry(this.key, ref, record));
			const created = await encryptCredentialStore(plaintexts, digest, argon2Defaults(), (key) => this.sealRecordsFor(key));
			plaintexts.clear();
			await writeFileAtomic(this.spec.filename, created.text, {
				mode: 384,
				dirMode: 448
			});
			this.text = created.text;
			this.entries = created.entries;
			this.records = created.records;
			this.verifier = created.verifier;
			this.salt = created.salt;
			this.params = created.params;
			this.dropKey();
			this.key = created.key;
			this.kdf = VAULT_KDF;
			this.unlocked = true;
			this.remember = void 0;
			await this.clearUnlockFailures();
		});
	}
	/** Assert the encrypted store is unlocked before a password transition. */
	assertUnlocked(verb) {
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", `cannot ${verb}: the credential store has no password`);
		if (!this.unlocked || this.key === void 0 || this.salt === void 0 || this.params === void 0 || this.text === void 0) throw new VaultError("VAULT_LOCKED", `cannot ${verb}: the credential store is locked; unlock it in Settings → 加密安全`);
	}
	/** Shared queue+lock+reconcile wrapper for password transitions. */
	async passwordTransition(operation) {
		if (this.isClosed()) throw new Error("dsh-encrypt is disposed");
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error("dsh-encrypt was disposed before the queued password transition ran");
			await mkdir(dirname(this.spec.filename), {
				recursive: true,
				mode: 448
			});
			return withFileLock(this.spec.filename, async () => {
				await this.reconcileFromDisk();
				return operation();
			});
		});
	}
	async describe(ref) {
		if (this.refusePlain) return Promise.resolve({
			configured: false,
			source: "locked",
			writable: false
		});
		if (this.inherited(ref) !== void 0) return Promise.resolve({
			configured: true,
			source: "env",
			writable: false
		});
		if (this.format === "encrypted" && !this.unlocked) return Promise.resolve({
			configured: false,
			source: "locked",
			writable: false
		});
		if (this.entries.get(ref) !== void 0) return Promise.resolve({
			configured: true,
			source: "file",
			writable: true
		});
		const fallback = this.dotenvFallback(ref);
		if (fallback !== void 0) return Promise.resolve({
			configured: true,
			source: fallback.source,
			writable: true
		});
		return Promise.resolve({
			configured: false,
			writable: true
		});
	}
	/** True while password-sealed records can be decrypted right now. */
	recordsReadable() {
		return this.format === "plain" || this.unlocked && this.key !== void 0;
	}
	/**
	* Read one record. Password-sealed records read as `undefined` while the
	* vault is locked — boot-time consumers must keep working — and the same
	* holds while a plaintext file is refused; machine-sealed records always
	* read.
	* @param key - the record to read.
	* @returns the record, or `undefined` while absent or unreadable.
	*/
	async readRecord(key) {
		if (this.refusePlain) return void 0;
		const slot = this.records.get(key);
		if (slot === void 0) return void 0;
		if (slot.form === "plain") return slot.record;
		if (slot.seal === "machine") return this.openRecord(key, slot.entry, this.machineRecordsKey());
		if (!this.recordsReadable()) return void 0;
		this.assertUnlocked("read a credential record");
		return this.openRecord(key, slot.entry, this.key);
	}
	/**
	* Describe one record without reading it.
	* @param key - the record to describe.
	* @returns configuration, the record kind (clear metadata), and whether a
	*   modification would currently succeed.
	*/
	async describeRecord(key) {
		if (this.refusePlain) return {
			configured: false,
			writable: false
		};
		const slot = this.records.get(key);
		if (slot === void 0) return {
			configured: false,
			writable: true
		};
		if (slot.form === "plain") return {
			configured: true,
			kind: slot.record.kind,
			writable: true
		};
		return {
			configured: true,
			kind: slot.kind,
			writable: slot.seal === "machine" || this.recordsReadable()
		};
	}
	/**
	* List every stored record's address and kind — never its value.
	* @returns the records, sorted by key.
	*/
	async listRecords() {
		if (this.refusePlain) return [];
		const listed = [];
		for (const key of [...this.records.keys()].sort()) {
			const slot = this.records.get(key);
			if (slot === void 0) continue;
			listed.push({
				key: parseCredentialKey(key),
				kind: slot.form === "plain" ? slot.record.kind : slot.kind
			});
		}
		return listed;
	}
	/**
	* Read-modify-write one record under the store's file lock. While locked a
	* password-sealed record refuses with `VAULT_LOCKED`, while a record that
	* does not exist yet is created machine-sealed — boot-time consumers such
	* as the local browser session keep working on a locked vault.
	* @param key - the record to modify.
	* @param mutate - receives the current record and returns its replacement,
	*   or `undefined` to leave it untouched.
	* @returns the record after the write, or the current one when the
	*   mutation declined.
	*/
	async modifyRecord(key, mutate) {
		if (this.refusePlain) throw new VaultError("VAULT_INVALID", "credential records are unavailable while the credential file is plaintext; set the password again in Settings → 加密安全 to re-encrypt it");
		if (this.isClosed()) throw new Error(`dsh-encrypt is disposed: cannot modify record "${key}"`);
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error(`dsh-encrypt was disposed before the queued "${key}" record write ran`);
			await mkdir(dirname(this.spec.filename), {
				recursive: true,
				mode: 448
			});
			return withFileLock(this.spec.filename, async () => {
				await this.reconcileFromDisk();
				if (this.refusePlain) throw new VaultError("VAULT_INVALID", "credential records are unavailable because ciphertext is required; set the password again to create a new encrypted store");
				const slot = this.records.get(key);
				let current;
				if (slot !== void 0) {
					if (slot.form === "plain") current = slot.record;
					else if (slot.seal === "machine") current = this.openRecord(key, slot.entry, this.machineRecordsKey());
					else if (this.recordsReadable()) {
						this.assertUnlocked("modify a credential record");
						current = this.openRecord(key, slot.entry, this.key);
					} else throw new VaultError("VAULT_LOCKED", `the credential record "${key}" is sealed under the vault password; unlock it in Settings → 加密安全 to modify it`);
				}
				const next = await mutate(current);
				if (next === void 0) return current;
				const issue = credentialRecordIssue(next);
				if (issue !== void 0) throw new TypeError(`dsh-encrypt: the record mutation for "${key}" ${issue}`);
				if (this.format === "encrypted") {
					const seal = slot === void 0 || slot.form === "plain" ? sealForRecord(key, this.recordsReadable()) : slot.seal;
					if (seal === "password") this.assertUnlocked("store a credential record");
					if (seal === "machine" && this.recordsKey === void 0) {
						this.requireRecordsKey();
						await this.persistState();
					}
					const sealed = this.sealRecord(key, next, seal, this.key);
					const nextRecords = new Map(this.records);
					nextRecords.set(key, sealed);
					const nextText = this.serializeSnapshot(this.entries, nextRecords, this.remember);
					if (nextText !== this.text) {
						await writeFileAtomic(this.spec.filename, nextText, {
							mode: 384,
							dirMode: 448
						});
						this.text = nextText;
					}
					this.records = nextRecords;
				} else {
					const nextText = renderPlainDocument(this.text, {
						kind: "record",
						key,
						record: next
					});
					if (nextText !== this.text) {
						await writeFileAtomic(this.spec.filename, nextText, {
							mode: 384,
							dirMode: 448
						});
						this.text = nextText;
					}
					const nextRecords = new Map(this.records);
					nextRecords.set(key, {
						form: "plain",
						record: next
					});
					this.records = nextRecords;
				}
				this.notifyRecordUpdated(key);
				return next;
			});
		});
	}
	/**
	* Remove one record under the store's file lock; removing an absent record
	* is a no-op. Works while locked — dropping ciphertext needs no key.
	* @param key - the record to remove.
	*/
	async deleteRecord(key) {
		if (this.refusePlain) throw new VaultError("VAULT_INVALID", "credential records are unavailable while the credential file is plaintext; set the password again in Settings → 加密安全 to re-encrypt it");
		if (this.isClosed()) throw new Error(`dsh-encrypt is disposed: cannot delete record "${key}"`);
		await this.enqueue(async () => {
			if (this.isClosed()) throw new Error(`dsh-encrypt was disposed before the queued "${key}" record deletion ran`);
			await mkdir(dirname(this.spec.filename), {
				recursive: true,
				mode: 448
			});
			await withFileLock(this.spec.filename, async () => {
				await this.reconcileFromDisk();
				if (this.refusePlain) throw new VaultError("VAULT_INVALID", "credential records are unavailable because ciphertext is required; set the password again to create a new encrypted store");
				if (!this.records.has(key)) return;
				const nextRecords = new Map(this.records);
				nextRecords.delete(key);
				if (this.format === "encrypted") {
					const nextText = this.serializeSnapshot(this.entries, nextRecords, this.remember);
					if (nextText !== this.text) {
						await writeFileAtomic(this.spec.filename, nextText, {
							mode: 384,
							dirMode: 448
						});
						this.text = nextText;
					}
				} else {
					const nextText = renderPlainDocument(this.text, {
						kind: "record",
						key,
						record: void 0
					});
					if (nextText !== this.text) {
						await writeFileAtomic(this.spec.filename, nextText, {
							mode: 384,
							dirMode: 448
						});
						this.text = nextText;
					}
				}
				this.records = nextRecords;
				this.notifyRecordUpdated(key);
			});
		});
	}
	/**
	* Fan the reference event out under the current name and, contained, under
	* the legacy `credentials/updated` name older dsh lines still listen to.
	* @param ref - the reference whose stored value changed.
	*/
	notifyUpdated(ref) {
		super.notifyUpdated(ref);
		const args = ["credentials/updated", ref];
		for (const listener of this.ctx.events.dispatch("emit", args)) try {
			const returned = listener(ref);
			if (returned != null && typeof returned.then === "function") Promise.resolve(returned).then(void 0, (error) => {
				this.warnLegacyListenerFailure(ref, error);
			});
		} catch (error) {
			this.warnLegacyListenerFailure(ref, error);
		}
	}
	/** Report one failed legacy `credentials/updated` listener without changing the committed outcome. */
	warnLegacyListenerFailure(ref, error) {
		this.ctx.logger.warn("dsh-encrypt: a legacy \"credentials/updated\" listener failed for %s", ref);
		this.ctx.logger.warn(error);
	}
	async set(ref, value) {
		if (value.length === 0) throw new Error(`dsh-encrypt: an empty value cannot be stored for "${ref}"; use unset`);
		await this.write(ref, value);
	}
	async unset(ref) {
		await this.write(ref, void 0);
	}
	/** Queue one exclusive document operation behind every earlier one. */
	async enqueue(operation) {
		const task = this.operationQueue.run(operation);
		this.operations = this.operationQueue.idle();
		return task;
	}
	/** Queue a reload; only an invariant violation escaping the fan-out can reject it. */
	queueRefresh() {
		this.enqueue(async () => this.refresh()).catch((error) => {
			this.ctx.logger.error("dsh-encrypt: reload commit failed at %s", this.spec.filename);
			this.ctx.logger.error(error);
		});
	}
	/** Queue one entry edit; entry checks reject early, the queue re-judges them at run time. */
	async write(ref, value) {
		const verb = value === void 0 ? "unset" : "set";
		if (this.refusePlain) throw new VaultError("VAULT_INVALID", "credential writes are refused while the credential file is plaintext; set the password again in Settings → 加密安全 to re-encrypt it");
		if (this.isClosed()) throw new Error(`dsh-encrypt is disposed: cannot ${verb} "${ref}"`);
		this.assertUnshadowed(ref, verb);
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error(`dsh-encrypt was disposed before the queued "${ref}" ${verb} ran`);
			this.assertUnshadowed(ref, verb);
			await mkdir(dirname(this.spec.filename), {
				recursive: true,
				mode: 448
			});
			await withFileLock(this.spec.filename, async () => {
				await this.reconcileFromDisk();
				if (this.refusePlain) throw new VaultError("VAULT_INVALID", "credential writes are refused because ciphertext is required; set the password again to create a new encrypted store");
				const existing = this.entries.get(ref);
				if (value === void 0 && existing === void 0) return;
				if (this.format === "encrypted") {
					if (!this.unlocked) throw new VaultError("VAULT_LOCKED", "the credential store is locked; unlock it in Settings → 加密安全 before storing credentials");
					this.assertUnlocked("store credentials");
					const next = new Map(this.entries);
					if (value === void 0) next.delete(ref);
					else next.set(ref, encryptEntry(this.key, ref, value));
					const nextText = this.serializeSnapshot(next, this.records, this.remember);
					if (nextText === this.text) return;
					await writeFileAtomic(this.spec.filename, nextText, {
						mode: 384,
						dirMode: 448
					});
					this.text = nextText;
					this.entries = next;
					if (value !== void 0) this.leakGuard.add(value, ref);
				} else {
					const nextText = renderPlainDocument(this.text, {
						kind: "ref",
						ref,
						value
					});
					if (nextText === this.text) return;
					await writeFileAtomic(this.spec.filename, nextText, {
						mode: 384,
						dirMode: 448
					});
					this.text = nextText;
					if (value === void 0) this.entries.delete(ref);
					else this.entries.set(ref, value);
					this.syncGuard();
				}
				this.notifyUpdated(ref);
			});
		});
	}
	/**
	* Reject a write the inherited environment would shadow into apparent
	* no-effect. Only that layer can shadow a write.
	*/
	assertUnshadowed(ref, verb) {
		if (this.inherited(ref) !== void 0) throw new Error(`dsh-encrypt: "${ref}" is supplied read-only by the launching environment, so ${verb} would be shadowed; unset it in the shell you start dsh from instead`);
	}
	/**
	* Re-read the document after a watcher event. Unchanged content (including
	* this provider's own writes) is a no-op; an unreadable or corrupt
	* document keeps the last good snapshot and warns — a live hot-reload must
	* never take the process down.
	*/
	async refresh() {
		if (this.closed) return;
		try {
			await this.reconcileFromDisk();
		} catch (error) {
			this.ctx.logger.warn("dsh-encrypt: reload failed at %s; keeping the last good document", this.spec.filename);
			this.ctx.logger.warn(error);
		}
	}
	/**
	* Compare the on-disk text against the cache and publish any difference
	* into the seam. Absence publishes the empty plain store; an unreadable or
	* invalid document throws, so each caller picks its policy. An external
	* form switch (plain→encrypted or back) is adopted: a newly encrypted file
	* boots locked, a decrypted one clears the key.
	*/
	async reconcileFromDisk() {
		await assertOwnerOnly(this.spec.filename);
		let text;
		try {
			text = await readOwnerOnlyText(this.spec.filename);
		} catch (error) {
			if (!isENOENT(error)) throw error;
			text = void 0;
		}
		if (text === this.text || this.isClosed()) return;
		if (text === void 0) {
			this.text = void 0;
			this.format = "plain";
			this.entries = /* @__PURE__ */ new Map();
			this.records = /* @__PURE__ */ new Map();
			this.verifier = void 0;
			this.remember = void 0;
			this.dropKey();
			this.unlocked = true;
			this.refusePlain = this.stateEncrypted === true;
			if (this.refusePlain) this.ctx.logger.error("dsh-encrypt: the encrypted credential file is missing; credential access and plaintext writes remain disabled");
			return;
		}
		if (detectCredentialStore(text) === "encrypted") {
			const parsed = parseEncryptedStore(text);
			this.text = text;
			this.format = "encrypted";
			this.entries = parsed.entries;
			this.adoptSealedRecords(parsed.records);
			this.verifier = parsed.verifier;
			this.salt = parsed.salt;
			this.params = parsed.params;
			this.kdf = parsed.kdf;
			this.remember = parsed.remember;
			this.refusePlain = false;
			this.dropKey();
			return;
		}
		const parsed = parsePlainDocument(text, this.spec.filename);
		if (parsed.ignoredKeys.length > 0) this.logIgnoredPlainKeys(parsed.ignoredKeys);
		if (this.stateEncrypted === true) {
			if (this.unlocked && this.key !== void 0) {
				this.assertUnlocked("re-encrypt an external plaintext edit");
				const entries = /* @__PURE__ */ new Map();
				for (const [ref, value] of parsed.refs) entries.set(ref, encryptEntry(this.key, ref, value));
				const records = await this.sealRecordsFromPlain(parsed.records, this.key);
				const cipher = this.serializeSnapshot(entries, records, this.remember);
				await writeFileAtomic(this.spec.filename, cipher, {
					mode: 384,
					dirMode: 448
				});
				this.text = cipher;
				this.format = "encrypted";
				this.entries = entries;
				this.records = records;
				this.unlocked = true;
				this.leakGuard.clear();
				this.ctx.logger.warn("dsh-encrypt: external plaintext edit at %s was re-encrypted in place (ciphertext-only policy)", this.spec.filename);
				return;
			}
			this.leakGuard.clear();
			this.ctx.logger.error("dsh-encrypt: refusing to adopt plaintext at %s while locked; keeping the last good encrypted snapshot", this.spec.filename);
			return;
		}
		const changed = [];
		for (const ref of /* @__PURE__ */ new Set([...this.entries.keys(), ...parsed.refs.keys()])) if (refChanged(this.entries, parsed.refs, ref)) changed.push(credentialRef(ref));
		const changedRecords = [];
		for (const key of /* @__PURE__ */ new Set([...this.records.keys(), ...parsed.records.keys()])) {
			const record = parsed.records.get(key);
			const nextSlot = record === void 0 ? void 0 : {
				form: "plain",
				record
			};
			if (recordSignature(this.records.get(key)) !== recordSignature(nextSlot)) changedRecords.push(parseCredentialKey(key));
		}
		this.text = text;
		this.format = "plain";
		this.entries = parsed.refs;
		this.records = plainRecordMap(parsed.records);
		this.verifier = void 0;
		this.remember = void 0;
		this.dropKey();
		this.unlocked = true;
		this.syncGuard();
		for (const ref of changed) this.notifyUpdated(ref);
		for (const key of changedRecords) this.notifyRecordUpdated(key);
	}
	/** The effective remembered-login window: runtime state file over patch config. */
	effectiveDays() {
		return effectiveRememberDays(this.stateRememberDays, this.config.rememberDays);
	}
	/** The WebUI-facing remembered-login snapshot. */
	rememberState() {
		return rememberSnapshot(this.effectiveDays(), this.remember);
	}
	/** Load the runtime state file ({ rememberDays }) if present and valid. */
	async loadStateFile() {
		let text;
		try {
			text = await readOwnerOnlyText(this.spec.stateFile);
		} catch (error) {
			if (!isENOENT(error)) throw error;
			return;
		}
		let doc;
		try {
			doc = JSON.parse(text);
		} catch (error) {
			throw new VaultError("STATE_INVALID", `the provider state file is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
		}
		const parsed = parseProviderRuntimeState(doc);
		if (parsed.invalidFields.includes("document") || parsed.invalidFields.includes("encrypted")) throw new VaultError("STATE_INVALID", "the provider state file has an invalid ciphertext-policy field");
		if (parsed.invalidFields.length > 0) this.ctx.logger.warn("dsh-encrypt: ignoring invalid state fields in %s: %s", this.spec.stateFile, parsed.invalidFields.join(", "));
		if (parsed.state.rememberDays !== void 0) this.stateRememberDays = parsed.state.rememberDays;
		if (parsed.state.encrypted === true) this.stateEncrypted = true;
		if (parsed.state.unlockFailures !== void 0) this.unlockFailures = parsed.state.unlockFailures;
		if (parsed.state.unlockLockedUntil !== void 0) this.unlockLockedUntil = parsed.state.unlockLockedUntil;
		if (parsed.state.recordsKey !== void 0) this.recordsKey = parseMasterKey(parsed.state.recordsKey);
	}
	/**
	* Write the runtime state file: the remembered-login window, the
	* ciphertext-only policy flag, and the installation records key. Never
	* throws — state persistence must not break credential operations.
	*/
	async persistState() {
		try {
			await mkdir(dirname(this.spec.stateFile), {
				recursive: true,
				mode: 448
			});
			await assertOwnerOnly(this.spec.stateFile);
			const text = serializeProviderRuntimeState({
				rememberDays: this.stateRememberDays,
				encrypted: this.stateEncrypted,
				unlockFailures: this.unlockFailures,
				unlockLockedUntil: this.unlockLockedUntil,
				recordsKey: this.recordsKey === void 0 ? void 0 : encodeMasterKey(this.recordsKey)
			});
			await writeFileAtomic(this.spec.stateFile, text, {
				mode: 384,
				dirMode: 448
			});
		} catch (error) {
			this.ctx.logger.warn("dsh-encrypt: cannot write state file %s: %s", this.spec.stateFile, error instanceof Error ? error.message : String(error));
		}
	}
	/**
	* Change the remembered-login window (0 = every time, 1..30 days, -1 =
	* forever). Persists in the runtime state file and invalidates any stored
	* block; when the store is currently unlocked a fresh ticket is issued
	* immediately under the new window.
	* @param {number} days - the new window.
	* @returns {Promise<{ secret: string, days: number, issuedAt: number, expiresAt: number|null }|null>}
	*/
	async setRememberDays(days) {
		if (!Number.isInteger(days) || days < -1 || days > 30) throw new VaultError("PASSWORD_INVALID", "remembered-login days must be an integer from -1 (forever) through 30, or 0 to require the password every time");
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error("dsh-encrypt is disposed");
			this.stateRememberDays = days;
			await this.persistState();
			if (this.format !== "encrypted") return null;
			await withFileLock(this.spec.filename, async () => {
				await this.reconcileFromDisk();
				if (this.remember !== void 0 && this.key !== void 0 && this.unlocked) {
					this.assertUnlocked("change remembered-login settings");
					const text = this.serializeSnapshot(this.entries, this.records, void 0);
					await writeFileAtomic(this.spec.filename, text, {
						mode: 384,
						dirMode: 448
					});
					this.text = text;
					this.remember = void 0;
				}
			});
			if (days !== 0 && this.unlocked && this.key !== void 0) return this.persistRemember(days);
			return null;
		});
	}
	/**
	* Issue a remembered-login ticket wrapping the current master key. No-op
	* unless the store is encrypted, unlocked, and the window is non-zero.
	* @returns {Promise<{ secret: string, days: number, issuedAt: number, expiresAt: number|null }|null>}
	*/
	async issueRemember() {
		if (this.effectiveDays() === 0 || this.format !== "encrypted" || !this.unlocked || this.key === void 0) return null;
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error("dsh-encrypt was disposed before the remembered-login issue ran");
			if (this.effectiveDays() === 0 || this.format !== "encrypted" || !this.unlocked || this.key === void 0) return null;
			await this.reconcileFromDisk();
			return this.persistRemember(this.effectiveDays());
		});
	}
	/** Rewrite the store with a fresh remember block and return the ticket. */
	async persistRemember(days) {
		return withFileLock(this.spec.filename, async () => {
			await this.reconcileFromDisk();
			this.assertUnlocked("issue a remembered login");
			const created = createRememberBlock(this.key, days);
			const text = this.serializeSnapshot(this.entries, this.records, created.block);
			await writeFileAtomic(this.spec.filename, text, {
				mode: 384,
				dirMode: 448
			});
			this.text = text;
			this.remember = created.block;
			return {
				secret: created.secret,
				days,
				issuedAt: created.block.issuedAt,
				expiresAt: days === -1 ? null : created.block.issuedAt + days * REMEMBER_DAY_MS
			};
		});
	}
	/**
	* Unlock with the browser-held remembered-login ticket. Fails with
	* REMEMBER_EXPIRED / REMEMBER_INVALID when the ticket is stale or does
	* not match — the web layer then falls back to the password form.
	* @param {string} secretText - the base64url ticket.
	*/
	async unlockWithRemember(secretText) {
		if (this.isClosed()) throw new Error("dsh-encrypt is disposed");
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error("dsh-encrypt was disposed before the queued remembered unlock ran");
			if (this.effectiveDays() === 0) throw new VaultError("REMEMBER_INVALID", "remembered login is disabled by the current configuration");
			if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store has no password; nothing to unlock");
			if (this.unlocked) return { unlocked: true };
			await this.reconcileFromDisk();
			if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store no longer has a password (the file was changed externally)");
			if (this.unlocked) return { unlocked: true };
			if (this.text === void 0) throw new VaultError("VAULT_INVALID", "the encrypted credential store has no document text");
			if (this.remember?.days !== this.effectiveDays()) throw new VaultError("REMEMBER_INVALID", "the remembered login no longer matches the current configuration");
			const sourceText = this.text;
			const unlocked = recoverKeyFromRemember(sourceText, secretText);
			await this.reconcileFromDisk();
			if (this.text !== sourceText || this.format !== "encrypted" || this.unlocked) {
				zeroizeBuffer(unlocked.key);
				throw new VaultError("VAULT_CHANGED", "the credential store changed while it was being unlocked; try again");
			}
			this.applyUnlock(unlocked);
			this.ctx.logger.info("dsh-encrypt: unlocked with the remembered-login ticket");
			await this.revokeRememberIfDisabled();
			return { unlocked: true };
		});
	}
	/**
	* Drop a persisted remembered-login block the runtime window no longer
	* allows (the slider moved to 0 while the store was locked, when the
	* block could not be rewritten without the key). Runs right after a
	* password or ticket unlock; a no-op when nothing is stale.
	*/
	async revokeRememberIfDisabled() {
		if (this.remember === void 0 || this.effectiveDays() !== 0 || !this.unlocked || this.key === void 0) return;
		await withFileLock(this.spec.filename, async () => {
			await this.reconcileFromDisk();
			if (this.remember === void 0 || this.effectiveDays() !== 0 || !this.unlocked || this.key === void 0) return;
			this.assertUnlocked("revoke a remembered login");
			const text = this.serializeSnapshot(this.entries, this.records, void 0);
			await writeFileAtomic(this.spec.filename, text, {
				mode: 384,
				dirMode: 448
			});
			this.text = text;
			this.remember = void 0;
			this.ctx.logger.info("dsh-encrypt: revoked a remembered-login block the current window no longer allows");
		});
	}
};
//#endregion
export { CREDENTIALS_FILENAME, DEFAULT_PASSWORD_ENV, EncryptedCredentialProvider, EncryptedCredentialProvider as default, VaultError, assertOwnerOnly, parsePlainDocument, renderPlainDocument, resolveSpec };

//# sourceMappingURL=index.js.map