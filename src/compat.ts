/**
 * Runtime identification for diagnostics. dsh-encrypt is built for flowing
 * compatibility with the dsh runtime: it no longer refuses to load on a
 * version it was not built against, and an incompatible runtime surfaces as a
 * clear error at the seam it actually uses. This module still discovers which
 * dsh release launched the plugin so the version is visible in the session
 * log whenever a combination misbehaves.
 * @module dsh-encrypt/compat
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { isPlainRecord } from './shared/validation/primitives.js'

export interface DshRuntime {
  /** Absolute path of the dsh package manifest the runtime was launched from. */
  path: string
  /** The running dsh release version. */
  version: string
}

/**
 * Find the running dsh runtime version from the process entry point.
 * @param argv - the process argv (injectable for tests).
 * @returns the runtime, or null when this process was not launched through
 *   the dsh CLI (tests, embeds).
 */
export function detectDshRuntime(argv: string[] = process.argv): DshRuntime | null {
  const entry = argv?.[1]
  if (typeof entry !== 'string' || entry.length === 0) return null
  const binDir = dirname(entry)
  try {
    const doc: unknown = JSON.parse(readFileSync(join(binDir, '..', 'package.json'), 'utf8'))
    if (isPlainRecord(doc) && doc.name === '@deepseek-ai/dsh' && typeof doc.version === 'string') {
      return { path: join(binDir, '..', 'package.json'), version: doc.version }
    }
  } catch {
    return null
  }
  return null
}
