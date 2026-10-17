/**
 * Shipped-file consistency self-check for dsh-encrypt installations.
 *
 * The package ships a manifest ({@link MANIFEST_FILE}) holding the SHA3-256
 * of every generated file under lib/ and of cordis.patch.yml. A plugin in
 * tsdown.config.ts generates the manifest after each build.
 * At import time the provider row re-hashes each listed file and refuses to
 * load when a generated file is missing, added or differs from the build
 * manifest. This detects incomplete installs and accidental local edits.
 *
 * Honest limits: the manifest itself is a shipped file, so an attacker who
 * can rewrite the installed plugin directory can also regenerate it. The
 * check catches changes that do not also replace the manifest and forces a
 * legitimate rebuild to pass through `pnpm build` first. It is not
 * obfuscation, code signing, or a trust root.
 *
 * Line endings: every hash is computed over {@link normalizeForHashing}
 * output (UTF-8 BOM stripped, CRLF / lone CR folded to LF). Git transports
 * commonly rewrite line endings per `core.autocrlf` / .gitattributes, and a
 * byte-exact hash would flag every fresh clone as tampered. Whitespace-folding
 * only blinds the check to line-ending rewrites — semantic code tampering is
 * still a byte change and still fails the check.
 * @module dsh-encrypt/integrity
 */
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { check, literal, pipe, record, safeParse, strictObject, string } from 'valibot'
import { sha3_256HexOfBytes } from './infrastructure/crypto/sha3.js'
import { isAsciiLowerHex, normalizeLineEndings } from './shared/validation/primitives.js'

/** Manifest format marker. */
export const INTEGRITY_FORMAT = 'dsh-encrypt-integrity'
/** Manifest schema version. */
export const INTEGRITY_VERSION = 1
/** Manifest filename, shipped inside lib/. */
export const MANIFEST_FILE = 'integrity-manifest.json'

export interface IntegrityManifest {
  format: string
  version: number
  files: Record<string, string>
}

export interface IntegrityVerdict {
  ok: boolean
  mismatches: string[]
}

const integrityManifestSchema = strictObject({
  format: literal(INTEGRITY_FORMAT),
  version: literal(INTEGRITY_VERSION),
  files: record(
    pipe(
      string(),
      check(value => isSafeManifestPath(value)),
    ),
    pipe(
      string(),
      check(value => isAsciiLowerHex(value, 64)),
    ),
  ),
})

/**
 * Canonicalize file bytes before hashing: strip a UTF-8 BOM and fold CRLF /
 * lone CR line endings to LF. Both manifest generation and runtime
 * verification hash through this function, so a git checkout on any platform
 * (LF or CRLF) verifies against the same manifest.
 * @param {Buffer} bytes - the raw file bytes.
 * @returns {Buffer} the canonical bytes.
 */
export function normalizeForHashing(bytes: Buffer): Buffer {
  let text = bytes.toString('utf8')
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1)
  return Buffer.from(normalizeLineEndings(text), 'utf8')
}

/** SHA3-256 hex digest of one file's canonicalized bytes. */
export function sha3File(path: string): string {
  return sha3_256HexOfBytes(normalizeForHashing(readFileSync(path)))
}

/**
 * Build a manifest over the given relative file paths (keys are stored in
 * sorted order so the JSON is stable across platforms).
 * @param {string} baseDir - the package root the relative paths resolve from.
 * @param {string[]} relFiles - relative file paths to cover.
 * @returns {{ format: string, version: number, files: Record<string, string> }} the manifest.
 */
export function computeIntegrityManifest(baseDir: string, relFiles: string[]): IntegrityManifest {
  const files: Record<string, string> = {}
  for (const rel of [...relFiles].sort()) {
    if (!isSafeManifestPath(rel)) throw new Error(`dsh-encrypt: unsafe integrity manifest path ${JSON.stringify(rel)}`)
    files[rel] = sha3File(join(baseDir, rel))
  }
  return { format: INTEGRITY_FORMAT, version: INTEGRITY_VERSION, files }
}

/** Accept only shipped package-relative files from the two generated roots. */
function isSafeManifestPath(relativePath: string): boolean {
  if (relativePath === 'cordis.patch.yml') return true
  if (!relativePath.startsWith('lib/') || relativePath.includes('\\')) return false
  const segments = relativePath.split('/')
  return segments.every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
}

/**
 * Verify a manifest against the files on disk.
 * @param {string} baseDir - the installed package root.
 * @param {unknown} manifest - the parsed manifest document.
 * @param {{ fail?: boolean }} [options] - fail=true throws on mismatch.
 * @returns {{ ok: boolean, mismatches: string[] }} the verdict.
 */
export function verifyIntegrityManifest(
  baseDir: string,
  manifest: unknown,
  options: { fail?: boolean } = {},
): IntegrityVerdict {
  const fail = options.fail ?? true
  const mismatches: string[] = []
  const parsed = safeParse(integrityManifestSchema, manifest)
  if (!parsed.success) {
    mismatches.push(`${MANIFEST_FILE} itself is missing or not a dsh-encrypt integrity manifest`)
  } else {
    const listed = new Set(Object.keys(parsed.output.files))
    try {
      for (const rel of collectShippedLibFiles(baseDir)) {
        if (!listed.has(rel)) mismatches.push(`${rel}: shipped file is absent from the integrity manifest`)
      }
    } catch {
      mismatches.push('lib/: unable to enumerate shipped files')
    }
    for (const [rel, expected] of Object.entries(parsed.output.files)) {
      let actual
      try {
        actual = sha3File(join(baseDir, rel))
      } catch {
        actual = '<unreadable-or-missing>'
      }
      if (actual !== expected) mismatches.push(`${rel}: expected ${String(expected)}, got ${actual}`)
    }
  }
  if (mismatches.length > 0 && fail) {
    const error = new Error(
      `dsh-encrypt: shipped-code integrity check FAILED — refusing to load tampered or incomplete files. For a source checkout rebuilt legitimately, run "pnpm build" to regenerate the manifest; for an installed plugin package, reinstall it from the original tarball.\n  - ${mismatches.join(
        '\n  - ',
      )}`,
    )
    ;(error as NodeJS.ErrnoException).code = 'INTEGRITY_FAILED'
    throw error
  }
  return { ok: mismatches.length === 0, mismatches }
}

function collectShippedLibFiles(baseDir: string): string[] {
  const output: string[] = []
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) throw new Error('symbolic links are not valid shipped files')
      if (entry.isDirectory()) {
        visit(path)
      } else if (entry.isFile()) {
        const rel = relative(baseDir, path).split(sep).join('/')
        if (rel !== `lib/${MANIFEST_FILE}`) output.push(rel)
      }
    }
  }
  visit(join(baseDir, 'lib'))
  return output
}

/**
 * Load the manifest shipped next to this module and verify it against the
 * installed tree. Called at import time by the provider and web rows — a
 * mismatch throws before the plugin can activate (fail-closed).
 * @param {string} importMetaUrl - the importing module's import.meta.url.
 * @returns {{ ok: boolean, mismatches: string[] }} the verdict.
 */
export function loadAndVerifyIntegrity(importMetaUrl: string): IntegrityVerdict {
  // The manifest ships inside lib/ (read from the module's own directory),
  // but its keys are package-relative ("lib/index.js", "cordis.patch.yml"):
  // verification runs against the package ROOT, one level above lib/.
  const moduleDir = dirname(fileURLToPath(importMetaUrl))
  const baseDir = resolve(moduleDir, '..')
  let manifest: unknown
  try {
    manifest = JSON.parse(readFileSync(join(moduleDir, MANIFEST_FILE), 'utf8'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException | null)?.code === 'ENOENT') {
      const missing = new Error(
        `dsh-encrypt: ${MANIFEST_FILE} is missing from the installed plugin; run "pnpm build" to generate it`,
      )
      ;(missing as NodeJS.ErrnoException).code = 'INTEGRITY_FAILED'
      throw missing
    }
    throw error
  }
  return verifyIntegrityManifest(baseDir, manifest)
}
