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
import { isCredentialReference, isPlainRecord } from '../../shared/validation/primitives.js'

/**
 * Check one candidate record.
 * @param value - the candidate, from a document or a seam consumer.
 * @returns `undefined` when the value is a valid record; otherwise a message
 *   naming the defect without repeating any stored value.
 */
export function credentialRecordIssue(value: unknown): string | undefined {
  if (!isPlainRecord(value)) return 'must be a mapping'
  const kind = value.kind
  if (kind === 'api-key') {
    const extra = unknownFieldIssue(value, ['kind', 'key', 'env'])
    if (extra !== undefined) return extra
    const key = value.key
    if (key !== undefined && (typeof key !== 'string' || key.length === 0)) return 'has a non-string or empty key'
    return envIssue(value.env)
  }
  if (kind === 'grant') {
    const extra = unknownFieldIssue(value, ['kind', 'payload'])
    if (extra !== undefined) return extra
    if (!('payload' in value)) return 'has no payload'
    return jsonValueIssue('payload', value.payload, new Set<object>())
  }
  if (kind === undefined) return 'has no kind'
  return `has unknown kind ${JSON.stringify(kind)}`
}

/** Reject a field the tag does not define. */
function unknownFieldIssue(value: Record<string, unknown>, allowed: readonly string[]): string | undefined {
  for (const field of Object.keys(value)) {
    if (!allowed.includes(field)) return `has unknown field "${field}"`
  }
  return void 0
}

/** Admit an api-key record's provider environment: POSIX names over non-empty strings. */
function envIssue(env: unknown): string | undefined {
  if (env === undefined) return void 0
  if (!isPlainRecord(env)) return 'has a non-mapping env'
  for (const [name, value] of Object.entries(env)) {
    if (!isCredentialReference(name)) return `env name "${name}" is not a credential reference`
    if (typeof value !== 'string' || value.length === 0) return `env "${name}" must be a non-empty string`
  }
  return void 0
}

/**
 * Reject a payload that cannot survive a JSON round trip: a double that
 * JSON cannot spell, an alias cycle, or a class instance, `Date`, or `bigint`
 * this document has no faithful JSON spelling for. Neither the value nor any
 * nested value is quoted in a diagnostic.
 */
function jsonValueIssue(where: string, value: unknown, seen: Set<object>): string | undefined {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return void 0
  if (typeof value === 'number') {
    return Number.isFinite(value) ? void 0 : `${where} holds a non-finite number`
  }
  if (typeof value === 'object') {
    if (seen.has(value)) return `${where} is cyclic`
    if (Object.getPrototypeOf(value) === Object.prototype || Array.isArray(value)) {
      seen.add(value)
      for (const nested of Object.values(value)) {
        const issue = jsonValueIssue(where, nested, seen)
        if (issue !== undefined) return issue
      }
      seen.delete(value)
      return void 0
    }
  }
  return `${where} holds a value JSON cannot represent`
}
