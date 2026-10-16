import { J as EntryRecord, X as KdfName, Z as KdfParams, ct as RecordValue, d as parsePlainDocument, f as renderPlainDocument, ht as SealedRecordValue, lt as RememberBlock, o as unlockEncryptedStore, st as RecordSeal, xt as VaultError } from "./vault-Dd09Msle.js";
import { t as LeakGuard } from "./leak-guard-BYcHOd2D.js";
import { Context } from "@deepseek-ai/cordis";
import { CredentialInfo, CredentialKey, CredentialProvider, CredentialRecord, CredentialRecordEntry, CredentialRecordInfo, CredentialRef, ResolvedCredential } from "@deepseek-ai/dsh-credentials";
import { LaunchEnvironmentEntry } from "@deepseek-ai/dsh-launch-environment";
import z from "@deepseek-ai/schemastery";
//#region src/domain/provider/model.d.ts
/** Public configuration accepted by the encrypted credential provider. */
interface ProviderConfig {
  path?: string;
  dshHome?: string;
  allowEnvFallback?: boolean;
  passwordEnv?: string;
  watch?: boolean;
  debounceMs?: number;
  rememberDays?: number;
  rememberChannel?: "cookie" | "header";
  leakGuard?: boolean;
  leakMinMaskLength?: number;
  leakMaxMaskLength?: number;
  maxUnlockAttempts?: number;
  lockoutBaseMs?: number;
  lockoutMaxMs?: number;
}
/** Resolved filesystem and watcher configuration. */
interface ProviderSpec {
  filename: string;
  stateFile: string;
  allowEnvFallback: boolean;
  passwordEnv: string;
  watch: boolean;
  debounceMs: number;
}
type NormalizedProviderConfig = ProviderConfig & Required<Omit<ProviderConfig, "path" | "dshHome">>;
/** One newly issued remembered-login ticket. */
interface RememberIssue {
  secret: string;
  days: number;
  issuedAt: number;
  expiresAt: number | null;
}
/** Web-facing provider state without credential material. */
interface ProviderStatus {
  format: "plain" | "encrypted";
  unlocked: boolean;
  plaintextForbidden: boolean;
  remember: {
    days: number;
    active: boolean;
    issuedAt: number | null;
    expiresAt: number | null;
  };
  lockout: {
    failures: number;
    lockedUntil: number;
    retryAfterMs: number;
    locked: boolean;
  };
  leakGuard: {
    enabled: boolean;
    masks: number;
  };
  rememberChannel: "cookie" | "header";
}
declare const CREDENTIALS_FILENAME: ".credentials.yaml";
declare const DEFAULT_PASSWORD_ENV: "DSH_CREDENTIAL_PASSWORD";
//#endregion
//#region src/infrastructure/persistence/secure-file.d.ts
/** Reject unsafe file types, ownership and POSIX permissions without following links. */
declare function assertOwnerOnly(filename: string): Promise<void>;
//#endregion
//#region src/infrastructure/runtime/provider-config.d.ts
/** Resolve the credential and runtime-state files from provider config. */
declare function resolveSpec(config?: ProviderConfig): ProviderSpec;
//#endregion
//#region src/index.d.ts
/**
 * dsh-encrypt — single-file, WebUI-managed encrypted credentials.
 *
 * One file, `$DSH_HOME/.credentials.yaml`, carries the credentials in two
 * forms:
 *
 * ```text
 * no password set (default; the versioned layout shared with credentials-local):
 *   version: 1                                   ← plaintext YAML document
 *   refs:
 *     OPENCODE_GO_API_KEY: sk-…                  ← references
 *   records:
 *     client-connection/browser-session: …       ← credential records
 *
 * after a password is set in Settings → 加密安全:
 *   { "format": "dsh-encrypt-credentials",      ← the same file's contents
 *     "version": 4, "kdf": "argon2id", …,        replaced by an encrypted
 *     "entries": { REF: { data, sha3 } },        JSON document (SHA3-256
 *     "records": { KEY: { kind, seal, … } } }     fingerprints + GCM tags)
 * ```
 *
 * The pre-port flat plaintext layout (references at the root) is still read
 * and migrates to the versioned one on the first write.
 *
 * State machine:
 *
 * ```text
 *             set-password                    (restart)            unlock
 *  plain ──────────────────► encrypted+unlocked ──────► encrypted+locked ──► unlocked
 *                                 ▲                                        │
 *                                 └──────────── change-password ───────────┘
 * ```
 *
 * While locked the provider activates normally (the web server stays up),
 * `resolve` throws `VAULT_LOCKED` and `describe` reports `source: "locked"` —
 * the Settings page is the unlock surface. Credentials are decrypted per
 * model request; plaintext is never cached between operations.
 *
 * Records arrive in two seals: `password`-sealed records are ciphertext
 * under the vault key, unreadable while locked exactly like entries, while
 * `machine`-sealed records (the local browser-session secret) are sealed
 * under an installation key kept in the runtime state file, so boot-time
 * consumers keep working while the vault is locked.
 *
 * Password APIs: `status()` / `unlock(digest)` / `setPassword(digest)` /
 * `changePassword(oldDigest, digest)`, also exposed to the browser
 * as `/api/credentials.{status,unlock,set-password,change-password,config}`
 * (exact routes behind the Host trust fence, served while a webServer
 * service exists; headless compositions simply have no HTTP surface).
 * `$DSH_CREDENTIAL_PASSWORD` unlocks a locked store at startup for automation.
 * @module dsh-encrypt
 */
type UnlockResult = Awaited<ReturnType<typeof unlockEncryptedStore>>;
/**
 * Single-file encrypted credentials provider with a WebUI-managed password.
 */
declare class EncryptedCredentialProvider extends CredentialProvider {
  config: NormalizedProviderConfig;
  static Config: ReturnType<typeof z.object>;
  spec: ProviderSpec;
  /** Current on-disk form: `plain` while no password is set. */
  format: "plain" | "encrypted";
  /** Whether the encrypted form is currently unlocked (always true in plain form). */
  unlocked: boolean;
  /** The derived key while unlocked; zeroized on lock/dispose. */
  key: Buffer | undefined;
  /** KDF salt and cost parameters of the current encrypted document. */
  salt: Buffer | undefined;
  params: KdfParams | undefined;
  /**
   * The current document's key verifier, kept so a locked rewrite (a
   * machine-sealed record, a deletion) can reproduce the document without
   * the password key.
   */
  verifier: EntryRecord | undefined;
  /** KDF of the current encrypted document: "argon2id" or legacy "scrypt". */
  kdf: KdfName;
  /**
   * The in-memory snapshot: plaintext values in the plain form, ciphertext
   * records in the encrypted form. Never both, never plaintext alongside a
   * lockable key.
   */
  entries: Map<string, string | EntryRecord>;
  /**
   * Record snapshot: plaintext records in the plain form, sealed records in
   * the encrypted form. Never mixes the two.
   */
  records: Map<string, RecordValue>;
  /**
   * The installation records key, sealing and opening `machine`-sealed
   * records (kept in the state file, so it survives a locked restart). Not
   * password-derived and not part of the lock state.
   */
  recordsKey: Buffer | undefined;
  /**
   * Raw text of the last read or persisted document; `undefined` while the
   * file is absent. Watcher events whose content equals this cache are
   * no-ops, which is also the self-write suppression.
   */
  text: string | undefined;
  /** Current remembered-login block from the encrypted document, if any. */
  remember: RememberBlock | undefined;
  /** Runtime-overridden remembered-login window from the state file. */
  stateRememberDays: number | undefined;
  /** The ciphertext-only policy flag persisted in the state file. */
  stateEncrypted: boolean | undefined;
  /** True while the file holds plaintext against the ciphertext-only policy. */
  refusePlain: boolean;
  /** Public compatibility view of the exclusive operation chain. */
  operations: Promise<void>;
  /** Failure-isolated serial queue used to schedule document mutations. */
  private readonly operationQueue;
  /** Set at dispose: refuse new writes and let in-flight work no-op. */
  closed: boolean;
  /** Leak guard: masks resolved credential values in output streams. */
  leakGuard: LeakGuard;
  /** Consecutive failed unlock attempts (persisted in the state file). */
  unlockFailures: number;
  /** Epoch ms until which unlocks are refused (persisted in the state file). */
  unlockLockedUntil: number;
  /** Number of password checks admitted to the serial queue but not settled. */
  private pendingUnlocks;
  isClosed(): boolean;
  constructor(ctx: Context, config?: ProviderConfig);
  /** The WebUI-facing lockout snapshot (never secret-bearing). */
  lockoutSnapshot(now?: number): {
    failures: number;
    lockedUntil: number;
    retryAfterMs: number;
    locked: boolean;
  };
  /** Reject an unlock attempt while the lockout window is active. */
  assertUnlockAllowed(now?: number): void;
  /** Count one failed unlock and (re-)arm the exponential window. */
  recordUnlockFailure(): Promise<void>;
  /** Reset the failure counter after a successful unlock. */
  clearUnlockFailures(): Promise<void>;
  /**
   * Reconcile the leak guard's mask set with the current vault state:
   * plain form registers every entry value; a locked vault (or a refused
   * plaintext file) clears the set; an encrypted+unlocked vault keeps the
   * incrementally resolved values registered by resolve().
   */
  syncGuard(): void;
  /** The inherited-environment value for a reference, or `undefined` when empty or unset. */
  inherited(ref: CredentialRef): string | undefined;
  /** The read-only `.env` fallback — below the managed file, never above it. */
  dotenvFallback(ref: CredentialRef): LaunchEnvironmentEntry | undefined;
  private initializeService;
  /** Zeroize and release the derived key (lock). */
  dropKey(): void;
  /** Zeroize and release the installation records key (dispose only; a lock keeps it). */
  dropRecordsKey(): void;
  /** The installation records key, generated and kept in memory on first need. */
  requireRecordsKey(): Buffer;
  /**
   * The installation records key for opening a machine-sealed record. A
   * machine slot whose key is gone is unrecoverable, so refuse loudly rather
   * than guessing with a fresh key.
   */
  machineRecordsKey(): Buffer;
  /**
   * Assert the encrypted snapshot is complete enough to rewrite the document
   * — locked or not. Locked rewrites reuse the document's verifier, so the
   * password key is not required.
   */
  assertDocumentWritable(verb: string): asserts this is this & {
    format: "encrypted";
    salt: Buffer;
    params: KdfParams;
    text: string;
  };
  /** Serialize the current encrypted snapshot, reusing the document's verifier. */
  serializeSnapshot(entries: ReadonlyMap<string, string | EntryRecord>, records: ReadonlyMap<string, RecordValue>, remember: RememberBlock | undefined): string;
  /**
   * Adopt sealed records from a parsed document. A `machine`-sealed record
   * without the installation key is unreadable lost ciphertext: the key
   * would have to be forged, so the entries are dropped with an error and
   * rebuilt by the consumer that owns them.
   */
  adoptSealedRecords(records: ReadonlyMap<string, SealedRecordValue>): void;
  /** Open one sealed record payload into a validated record. */
  openRecord(key: string, entry: unknown, keyBuffer: Buffer): CredentialRecord;
  /**
   * Seal one record payload under its chosen seal. A password seal needs the
   * unlocked vault key; a machine seal needs only the installation key, so it
   * works while the vault is locked.
   */
  sealRecord(key: string, record: CredentialRecord, seal: RecordSeal, passwordKey: Buffer | undefined): SealedRecordValue;
  /**
   * Seal the current record snapshot for a new password key: plaintext
   * records take their policy seal, password-sealed records re-encrypt under
   * the new key, and machine-sealed records carry over untouched.
   */
  sealRecordsFor(passwordKey: Buffer): Map<string, SealedRecordValue>;
  /**
   * Seal a plaintext record snapshot for the encrypted form during an
   * external-edit re-encryption. A machine seal needs the installation key;
   * it is generated and persisted before the ciphertext that depends on it.
   */
  sealRecordsFromPlain(records: ReadonlyMap<string, CredentialRecord>, passwordKey: Buffer): Promise<Map<string, SealedRecordValue>>;
  /**
   * Generate and persist the installation records key before a transition
   * that will machine-seal records, so the ciphertext never precedes the key
   * that opens it.
   */
  persistRecordsKeyIfNeeded(): Promise<void>;
  /** Report top-level keys the versioned plaintext layout does not define. */
  logIgnoredPlainKeys(ignoredKeys: readonly string[]): void;
  /**
   * Boot read: an absent file is an empty plain store. A present encrypted
   * store must pass its SHA3-256 integrity checks before activation; it then
   * boots LOCKED (unless `$DSH_CREDENTIAL_PASSWORD` supplies the password —
   * a supplied-but-wrong password fails activation, never boots locked).
   */
  loadInitial(): Promise<void>;
  /** Apply an unlock result to the snapshot (used by boot env unlock and the API). */
  applyUnlock(unlocked: UnlockResult): void;
  /**
   * Resolve one reference per operation: plaintext value, or a decrypted
   * transient value while unlocked. Never cached between operations.
   * @param ref - the reference to resolve.
   * @returns value and source, or `undefined` while unconfigured.
   */
  resolve(ref: CredentialRef): Promise<ResolvedCredential | undefined>;
  /**
   * Run `fn` with one reference temporarily unlocked. The plaintext argument
   * lives for the callback and is dropped with it.
   * @param ref - the reference to unlock.
   * @param fn - the consumer; receives the plaintext or `undefined` while unconfigured.
   * @returns the callback's result.
   */
  withUnlocked<T>(ref: CredentialRef, fn: (value: string | undefined) => T | Promise<T>): Promise<T>;
  /**
   * Burn-after-read variant: run `fn` with the plaintext as a mutable
   * Buffer and zeroize it in a finally block once the callback settles.
   * JavaScript strings are immutable, so the string seam above can only
   * drop references — this buffer copy is the erasure-capable path.
   * @param ref - the reference to unlock.
   * @param fn - the consumer; receives the plaintext buffer or `undefined`.
   * @returns the callback's result.
   */
  withUnlockedBuffer<T>(ref: CredentialRef, fn: (value: Buffer | undefined) => T | Promise<T>): Promise<T>;
  /** The WebUI-facing snapshot: form, lock state, remembered-login, lockout and leak-guard state. */
  status(): Promise<ProviderStatus>;
  /**
   * Unlock the encrypted store with the password's SHA3-256 digest (the
   * WebUI derives it; the raw password never reaches this process).
   * @param digest - the lowercase hex SHA3-256 digest of the password.
   */
  unlock(digest: string): Promise<{
    unlocked: true;
  }>;
  /** Perform one admitted unlock inside the provider's exclusive operation queue. */
  private unlockQueued;
  /**
   * Re-encrypt a legacy scrypt (v2) store into the Argon2id (v3) format
   * after a password unlock: every entry is decrypted under the legacy key
   * and re-encrypted under a fresh Argon2id salt/key derived from the same
   * digest, then the document is replaced in place. The legacy key is
   * zeroized; a remembered-login block wrapping it is dropped.
   * @param digest - lowercase hex SHA3-256 digest of the password.
   */
  upgradeKdf(digest: string): Promise<void>;
  /**
   * Set the first password: the file's plaintext contents are replaced by
   * the encrypted document in place, and the provider stays unlocked. Any
   * previous remembered-login block dies with the old plain form.
   * @param digest - lowercase hex SHA3-256 digest of the new password.
   */
  setPassword(digest: string): Promise<void>;
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
  changePassword(oldDigest: string, digest: string): Promise<void>;
  /** Assert the encrypted store is unlocked before a password transition. */
  assertUnlocked(verb: string): asserts this is this & {
    format: "encrypted";
    unlocked: true;
    key: Buffer;
    salt: Buffer;
    params: KdfParams;
    text: string;
    entries: Map<string, EntryRecord>;
  };
  /** Shared queue+lock+reconcile wrapper for password transitions. */
  passwordTransition<T>(operation: () => Promise<T>): Promise<T>;
  describe(ref: CredentialRef): Promise<CredentialInfo>;
  /** True while password-sealed records can be decrypted right now. */
  recordsReadable(): boolean;
  /**
   * Read one record. Password-sealed records read as `undefined` while the
   * vault is locked — boot-time consumers must keep working — and the same
   * holds while a plaintext file is refused; machine-sealed records always
   * read.
   * @param key - the record to read.
   * @returns the record, or `undefined` while absent or unreadable.
   */
  readRecord(key: CredentialKey): Promise<CredentialRecord | undefined>;
  /**
   * Describe one record without reading it.
   * @param key - the record to describe.
   * @returns configuration, the record kind (clear metadata), and whether a
   *   modification would currently succeed.
   */
  describeRecord(key: CredentialKey): Promise<CredentialRecordInfo>;
  /**
   * List every stored record's address and kind — never its value.
   * @returns the records, sorted by key.
   */
  listRecords(): Promise<readonly CredentialRecordEntry[]>;
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
  modifyRecord(key: CredentialKey, mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>): Promise<CredentialRecord | undefined>;
  /**
   * Remove one record under the store's file lock; removing an absent record
   * is a no-op. Works while locked — dropping ciphertext needs no key.
   * @param key - the record to remove.
   */
  deleteRecord(key: CredentialKey): Promise<void>;
  /**
   * Fan the reference event out under the current name and, contained, under
   * the legacy `credentials/updated` name older dsh lines still listen to.
   * @param ref - the reference whose stored value changed.
   */
  protected override notifyUpdated(ref: CredentialRef): void;
  /** Report one failed legacy `credentials/updated` listener without changing the committed outcome. */
  private warnLegacyListenerFailure;
  set(ref: CredentialRef, value: string): Promise<void>;
  unset(ref: CredentialRef): Promise<void>;
  /** Queue one exclusive document operation behind every earlier one. */
  enqueue<T>(operation: () => T | Promise<T>): Promise<T>;
  /** Queue a reload; only an invariant violation escaping the fan-out can reject it. */
  queueRefresh(): void;
  /** Queue one entry edit; entry checks reject early, the queue re-judges them at run time. */
  write(ref: CredentialRef, value: string | undefined): Promise<void>;
  /**
   * Reject a write the inherited environment would shadow into apparent
   * no-effect. Only that layer can shadow a write.
   */
  assertUnshadowed(ref: CredentialRef, verb: string): void;
  /**
   * Re-read the document after a watcher event. Unchanged content (including
   * this provider's own writes) is a no-op; an unreadable or corrupt
   * document keeps the last good snapshot and warns — a live hot-reload must
   * never take the process down.
   */
  refresh(): Promise<void>;
  /**
   * Compare the on-disk text against the cache and publish any difference
   * into the seam. Absence publishes the empty plain store; an unreadable or
   * invalid document throws, so each caller picks its policy. An external
   * form switch (plain→encrypted or back) is adopted: a newly encrypted file
   * boots locked, a decrypted one clears the key.
   */
  reconcileFromDisk(): Promise<void>;
  /** The effective remembered-login window: runtime state file over patch config. */
  effectiveDays(): number;
  /** The WebUI-facing remembered-login snapshot. */
  rememberState(): {
    days: number;
    active: boolean;
    issuedAt: number | null;
    expiresAt: number | null;
  };
  /** Load the runtime state file ({ rememberDays }) if present and valid. */
  loadStateFile(): Promise<void>;
  /**
   * Write the runtime state file: the remembered-login window, the
   * ciphertext-only policy flag, and the installation records key. Never
   * throws — state persistence must not break credential operations.
   */
  persistState(): Promise<void>;
  /**
   * Change the remembered-login window (0 = every time, 1..30 days, -1 =
   * forever). Persists in the runtime state file and invalidates any stored
   * block; when the store is currently unlocked a fresh ticket is issued
   * immediately under the new window.
   * @param {number} days - the new window.
   * @returns {Promise<{ secret: string, days: number, issuedAt: number, expiresAt: number|null }|null>}
   */
  setRememberDays(days: number): Promise<RememberIssue | null>;
  /**
   * Issue a remembered-login ticket wrapping the current master key. No-op
   * unless the store is encrypted, unlocked, and the window is non-zero.
   * @returns {Promise<{ secret: string, days: number, issuedAt: number, expiresAt: number|null }|null>}
   */
  issueRemember(): Promise<RememberIssue | null>;
  /** Rewrite the store with a fresh remember block and return the ticket. */
  persistRemember(days: number): Promise<RememberIssue>;
  /**
   * Unlock with the browser-held remembered-login ticket. Fails with
   * REMEMBER_EXPIRED / REMEMBER_INVALID when the ticket is stale or does
   * not match — the web layer then falls back to the password form.
   * @param {string} secretText - the base64url ticket.
   */
  unlockWithRemember(secretText: string): Promise<{
    unlocked: true;
  }>;
  /**
   * Drop a persisted remembered-login block the runtime window no longer
   * allows (the slider moved to 0 while the store was locked, when the
   * block could not be rewritten without the key). Runs right after a
   * password or ticket unlock; a no-op when nothing is stale.
   */
  revokeRememberIfDisabled(): Promise<void>;
}
//#endregion
export { CREDENTIALS_FILENAME, DEFAULT_PASSWORD_ENV, EncryptedCredentialProvider, EncryptedCredentialProvider as default, type ProviderConfig, type ProviderSpec, type ProviderStatus, type RememberIssue, VaultError, assertOwnerOnly, parsePlainDocument, renderPlainDocument, resolveSpec };
//# sourceMappingURL=index.d.ts.map