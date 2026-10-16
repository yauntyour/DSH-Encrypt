/**
 * The plaintext form of the credential store: one YAML document in the
 * versioned layout shared with credentials-local (`version: 1`, then `refs`
 * and `records` sections). Reads also accept the pre-port flat layout
 * (reference → value at the root); the first write migrates the recognized
 * flat layout to the versioned one by nesting the original lines under
 * `refs:`, so comments and blank lines survive (YAML may normalize spacing).
 * Any other unmigrated text is rebuilt from its parsed references on write,
 * and unknown top-level keys in a versioned document are reported to the
 * caller instead of being dropped.
 * @module dsh-encrypt/infrastructure/persistence/plain-credential-document
 */
import type { CredentialRecord } from '@deepseek-ai/dsh-credentials'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { Document, isMap, isScalar, parseDocument as parseYaml } from 'yaml'
import { credentialRecordIssue } from '../../domain/vault/records.js'
import { isCredentialKeyName, isPlainRecord } from '../../shared/validation/primitives.js'

/** Document layout version for the versioned plaintext form. */
export const PLAIN_DOCUMENT_VERSION = 1 as const

/** Everything one plaintext document holds. */
export interface PlainCredentialDocument {
  refs: Map<string, string>
  records: Map<string, CredentialRecord>
  /** Top-level keys this build does not define; the caller reports them. */
  ignoredKeys: string[]
}

/** One edit to apply to the plaintext document. */
export type PlainDocumentEdit =
  | { kind: 'ref'; ref: string; value: string | undefined }
  | { kind: 'record'; key: string; record: CredentialRecord | undefined }

/**
 * Parse a plaintext credential document in either layout.
 * @param text - the document's text.
 * @param filename - absolute path, quoted in errors.
 * @returns the parsed references, records, and ignored top-level keys.
 * @throws Error or TypeError naming the document and the defect; no stored
 *   value is quoted in a diagnostic.
 */
export function parsePlainDocument(text: string, filename: string): PlainCredentialDocument {
  const document = parseYaml(text, { prettyErrors: true, uniqueKeys: true })
  if (document.errors.length > 0) {
    throw new Error(
      `dsh-encrypt: invalid document at ${filename}: ${document.errors
        .map(error => {
          const at = error.linePos?.[0]
          return `${error.code}${at === void 0 ? '' : ` at line ${String(at.line)}, column ${String(at.col)}`}`
        })
        .join('; ')}`,
    )
  }
  const root: unknown = document.toJS() ?? {}
  if (!isPlainRecord(root)) {
    throw new TypeError(`dsh-encrypt: ${filename} must be a mapping of credential reference to value`)
  }
  const keys = Object.keys(root)
  if (keys.length === 0) return { refs: new Map(), records: new Map(), ignoredKeys: [] }
  if (typeof root.version === 'number') {
    if (root.version !== PLAIN_DOCUMENT_VERSION) {
      throw new Error(
        `dsh-encrypt: ${filename} declares version ${JSON.stringify(root.version)};` +
          ` this build reads version ${PLAIN_DOCUMENT_VERSION}`,
      )
    }
    return {
      refs: parseRefs(root.refs, filename),
      records: parseRecords(root.records, filename),
      ignoredKeys: keys.filter(key => key !== 'version' && key !== 'refs' && key !== 'records'),
    }
  }
  return { refs: parseRefs(root, filename), records: new Map(), ignoredKeys: [] }
}

/**
 * Render one plaintext edit in the versioned layout while preserving YAML
 * comments of an already-versioned or recognized flat document.
 * @param text - the current document text, or `undefined` for a new document.
 * @param edit - the reference or record to set, or to remove when its value
 *   is `undefined`.
 * @returns the rendered document text.
 */
export function renderPlainDocument(text: string | undefined, edit: PlainDocumentEdit): string {
  const document = baseDocument(text)
  if (edit.kind === 'ref') {
    if (edit.value === void 0) document.deleteIn(['refs', edit.ref])
    else document.setIn(['refs', edit.ref], edit.value)
  } else if (edit.record === void 0) {
    document.deleteIn(['records', edit.key])
  } else {
    document.setIn(['records', edit.key], edit.record)
  }
  dropEmptySections(document)
  return document.toString()
}

/**
 * Pick the document to edit: a fresh versioned skeleton, the migrated flat
 * layout when it is recognized exactly, the versioned layout in place, or —
 * for accepted-but-unrecognized text such as a document with directives — a
 * fresh versioned document rebuilt from its parsed references.
 */
function baseDocument(text: string | undefined): Document {
  if (text === void 0) return versionedDocument()
  const migrated = migratedFlatLayout(text)
  if (migrated !== void 0) return parseYaml(migrated)
  const parsed = parseYaml(text, { prettyErrors: true, uniqueKeys: true })
  const root: unknown = parsed.errors.length === 0 ? (parsed.toJS() ?? {}) : void 0
  if (isPlainRecord(root) && root.version === PLAIN_DOCUMENT_VERSION) return parsed
  const rebuilt = versionedDocument()
  for (const [ref, value] of parsePlainDocument(text, 'the plaintext credential document').refs) {
    rebuilt.setIn(['refs', ref], value)
  }
  return rebuilt
}

/** A fresh `version: 1` document. */
function versionedDocument(): Document {
  const document = new Document({})
  document.setIn(['version'], PLAIN_DOCUMENT_VERSION)
  return document
}

/**
 * Render the versioned layout for the pre-port flat document, or `undefined`
 * for anything else. The layout is recognized exactly: a non-empty top-level
 * mapping of reference names to non-empty string scalars, no numeric
 * `version` marker, and no document directives. Anything else keeps whatever
 * base document the caller selected.
 */
function migratedFlatLayout(text: string): string | undefined {
  const document = parseYaml(text, { prettyErrors: true, uniqueKeys: true })
  if (document.errors.length > 0) return void 0
  const flat = document.contents
  if (!isMap(flat) || flat.items.length === 0) return void 0
  for (const line of text.split('\n')) {
    if (line.startsWith('%') || line.startsWith('---') || line.startsWith('...')) return void 0
  }
  for (const pair of flat.items) {
    if (!isScalar(pair.key) || typeof pair.key.value !== 'string') return void 0
    if (pair.key.value === 'version' && isScalar(pair.value) && typeof pair.value.value === 'number') return void 0
    try {
      credentialRef(pair.key.value)
    } catch {
      return void 0
    }
    if (!isScalar(pair.value) || typeof pair.value.value !== 'string' || pair.value.value.length === 0) return void 0
  }
  const body = text
    .split('\n')
    .map(line => (line.length === 0 ? line : `  ${line}`))
    .join('\n')
  return `version: ${PLAIN_DOCUMENT_VERSION}\nrefs:\n${body}${text.endsWith('\n') ? '' : '\n'}`
}

/** Drop a `refs` or `records` section the last edit emptied. */
function dropEmptySections(document: Document): void {
  for (const section of ['refs', 'records']) {
    const contents = document.getIn([section])
    if (isMap(contents) && contents.items.length === 0) document.deleteIn([section])
  }
}

/** Parse one `refs` (or flat root) section: reference names to non-empty strings. */
function parseRefs(section: unknown, filename: string): Map<string, string> {
  const refs = new Map<string, string>()
  for (const [ref, value] of Object.entries(asSection(section, 'refs', filename))) {
    credentialRef(ref)
    if (typeof value !== 'string') {
      throw new TypeError(`dsh-encrypt: the value for "${ref}" in ${filename} must be a string`)
    }
    if (value.length === 0) {
      throw new Error(`dsh-encrypt: the value for "${ref}" in ${filename} is empty; remove the key instead`)
    }
    refs.set(ref, value)
  }
  return refs
}

/** Parse the `records` section: credential keys to validated records. */
function parseRecords(section: unknown, filename: string): Map<string, CredentialRecord> {
  const records = new Map<string, CredentialRecord>()
  for (const [key, value] of Object.entries(asSection(section, 'records', filename))) {
    if (!isCredentialKeyName(key)) {
      throw new TypeError(`dsh-encrypt: record key "${key}" in ${filename} is not a credential key (scope/id)`)
    }
    const issue = credentialRecordIssue(value)
    if (issue !== undefined) throw new TypeError(`dsh-encrypt: record "${key}" in ${filename} ${issue}`)
    records.set(key, value as CredentialRecord)
  }
  return records
}

/** Read one document section as a mapping, absent sections being empty. */
function asSection(section: unknown, name: string, filename: string): Record<string, unknown> {
  if (section === void 0 || section === null) return {}
  if (!isPlainRecord(section)) {
    throw new TypeError(`dsh-encrypt: the ${name} section in ${filename} must be a mapping`)
  }
  return section
}
