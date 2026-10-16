import type { ParsedEncryptedStore, RememberBlock } from '../domain/vault/model.js'
import { createHash, randomBytes } from 'node:crypto'
import {
  KEY_FILE_VERIFIER_REF,
  MASTER_KEY_BYTES,
  REMEMBER_BLOCK_VERSION,
  REMEMBER_DAY_MS,
  REMEMBER_KEY_REF,
  VaultError,
} from '../domain/vault/model.js'
import {
  decryptEntry,
  encodeMasterKey,
  encryptEntry,
  generatePasswordSalt,
  parseMasterKey,
  zeroizeBuffer,
} from '../infrastructure/crypto/vault-crypto.js'
import { parseEncryptedStore } from '../infrastructure/persistence/vault-document.js'

const REMEMBER_TICKET_DOMAIN = 'dsh-encrypt-remember-ticket'

/** Whether a remembered-login block remains inside its configured window. */
export function rememberActive(remember: RememberBlock, now: number = Date.now()): boolean {
  if (remember.issuedAt > now) return false
  return remember.days === -1 || now - remember.issuedAt <= remember.days * REMEMBER_DAY_MS
}

/** Wrap a master key under a fresh browser-held remembered-login ticket. */
export function createRememberBlock(
  key: Buffer,
  days: number,
  now: number = Date.now(),
): { block: RememberBlock; secret: string } {
  if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) {
    throw new VaultError('MASTER_KEY_INVALID', 'a master key must be a 32-byte buffer')
  }
  if (!Number.isInteger(days) || (days !== -1 && (days < 1 || days > 30))) {
    throw new VaultError('PASSWORD_INVALID', 'remembered-login days must be 1..30 or -1 (forever)')
  }
  const salt = generatePasswordSalt()
  const secret = randomBytes(MASTER_KEY_BYTES)
  const blockBase = { version: REMEMBER_BLOCK_VERSION, salt: salt.toString('base64url'), issuedAt: now, days }
  const wrappingKey = ticketKey(salt, secret)
  try {
    const cipher = encryptEntry(wrappingKey, rememberKeyReference(blockBase), encodeMasterKey(key))
    return {
      block: { ...blockBase, cipher },
      secret: secret.toString('base64url'),
    }
  } finally {
    zeroizeBuffer(wrappingKey)
    zeroizeBuffer(secret)
  }
}

/** Recover and authenticate a master key from a remembered-login ticket. */
export function recoverKeyFromRemember(
  text: string,
  secretText: string,
): Omit<ParsedEncryptedStore, 'documentSha3'> & { key: Buffer; remember: RememberBlock } {
  const parsed = parseEncryptedStore(text)
  if (parsed.remember === void 0) {
    throw new VaultError('REMEMBER_INVALID', 'this credential store has no remembered login')
  }
  if (parsed.remember.version !== REMEMBER_BLOCK_VERSION) {
    throw new VaultError('REMEMBER_INVALID', 'the remembered login uses an expired ticket format')
  }
  if (!rememberActive(parsed.remember)) {
    throw new VaultError('REMEMBER_EXPIRED', 'the remembered login has expired; enter the password again')
  }
  const secret = parseRememberSecret(secretText)
  let key: Buffer
  let wrappingKey: Buffer | undefined
  try {
    wrappingKey = ticketKey(Buffer.from(parsed.remember.salt, 'base64url'), secret)
    key = parseMasterKey(decryptEntry(wrappingKey, rememberKeyReference(parsed.remember), parsed.remember.cipher))
  } catch (error) {
    throwRememberInvalid(error)
  } finally {
    if (wrappingKey !== void 0) zeroizeBuffer(wrappingKey)
    zeroizeBuffer(secret)
  }
  try {
    decryptEntry(key, KEY_FILE_VERIFIER_REF, parsed.verifier)
  } catch (error) {
    zeroizeBuffer(key)
    throwRememberInvalid(error)
  }
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

function parseRememberSecret(secretText: string): Buffer {
  if (typeof secretText !== 'string' || secretText.length === 0) {
    throw new VaultError('REMEMBER_INVALID', 'the remembered-login ticket is empty')
  }
  let secret: Buffer
  try {
    secret = Buffer.from(secretText, 'base64url')
  } catch {
    throw new VaultError('REMEMBER_INVALID', 'the remembered-login ticket is not valid base64url')
  }
  if (secret.length !== MASTER_KEY_BYTES) {
    throw new VaultError('REMEMBER_INVALID', 'the remembered-login ticket must decode to 32 bytes')
  }
  return secret
}

function ticketKey(salt: Buffer, secret: Buffer): Buffer {
  return createHash('sha3-256')
    .update(Buffer.concat([Buffer.from(REMEMBER_TICKET_DOMAIN, 'utf8'), salt, secret]))
    .digest()
}

/** Bind every expiry-policy field to the GCM tag through a credential-safe AAD reference. */
function rememberKeyReference(remember: Pick<RememberBlock, 'version' | 'salt' | 'issuedAt' | 'days'>): string {
  const metadata = JSON.stringify({
    version: remember.version,
    salt: remember.salt,
    issuedAt: remember.issuedAt,
    days: remember.days,
  })
  return `${REMEMBER_KEY_REF}_${createHash('sha3-256').update(metadata, 'utf8').digest('hex')}`
}

function throwRememberInvalid(error: unknown): never {
  if (error instanceof VaultError && (error.code === 'VAULT_KEY_MISMATCH' || error.code === 'VAULT_CORRUPTED')) {
    throw new VaultError('REMEMBER_INVALID', 'the remembered-login ticket does not match this credential store')
  }
  throw error
}
