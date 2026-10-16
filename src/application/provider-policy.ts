import type { RecordSeal, RememberBlock } from '../domain/vault/model.js'
import { REMEMBER_BLOCK_VERSION, REMEMBER_DAY_MS } from '../domain/vault/model.js'
import { rememberActive } from './remember-service.js'

/**
 * The record the local browser-session secret lives in. Boot-time consumers
 * read or write this record before any vault password can be supplied, so it
 * is always `machine`-sealed and never password-sealed — otherwise a locked
 * vault would break the Web UI's own login.
 */
const LOCKED_BOOT_RECORD_KEY = 'client-connection/browser-session' as const

/**
 * Choose the seal for a record entering encrypted storage. Existing records
 * keep their seal; this decides new ones. While the vault is locked no
 * password key exists, so the record is machine-sealed and stays usable.
 * @param key - the record's credential key.
 * @param passwordAvailable - whether a password key seals this write.
 * @returns the seal to assign.
 */
export function sealForRecord(key: string, passwordAvailable: boolean): RecordSeal {
  return key === LOCKED_BOOT_RECORD_KEY || !passwordAvailable ? 'machine' : 'password'
}

export interface LockoutSnapshot {
  failures: number
  lockedUntil: number
  retryAfterMs: number
  locked: boolean
}

export interface RememberSnapshot {
  days: number
  active: boolean
  issuedAt: number | null
  expiresAt: number | null
}

/** Build a Web-safe lockout view. */
export function lockoutSnapshot(failures: number, lockedUntil: number, now: number = Date.now()): LockoutSnapshot {
  const retryAfterMs = Math.max(0, lockedUntil - now)
  return { failures, lockedUntil, retryAfterMs, locked: retryAfterMs > 0 }
}

/** Select and bound the runtime remember setting over its configured default. */
export function effectiveRememberDays(runtimeDays: number | undefined, configuredDays: number): number {
  const value = runtimeDays ?? configuredDays
  return Number.isInteger(value) && value >= -1 && value <= 30 ? value : 0
}

/** Build a Web-safe remembered-login view. */
export function rememberSnapshot(
  days: number,
  block: RememberBlock | undefined,
  now: number = Date.now(),
): RememberSnapshot {
  const active =
    days !== 0 &&
    block !== void 0 &&
    block.version === REMEMBER_BLOCK_VERSION &&
    block.days === days &&
    rememberActive(block, now)
  return {
    days,
    active,
    issuedAt: block?.issuedAt ?? null,
    expiresAt: block !== void 0 && block.days !== -1 ? block.issuedAt + block.days * REMEMBER_DAY_MS : null,
  }
}
