import { boolean, check, finite, integer, maxValue, minValue, number, pipe, safeParse, string } from 'valibot'
import { isPlainRecord } from '../../shared/validation/primitives.js'
import { parseMasterKey } from '../crypto/vault-crypto.js'

export interface ProviderRuntimeState {
  rememberDays?: number | undefined
  encrypted?: boolean | undefined
  unlockFailures?: number | undefined
  unlockLockedUntil?: number | undefined
  /**
   * The installation records key (base64url), sealing `machine`-sealed
   * credential records: the record half of the store that must stay readable
   * while the vault is locked. Kept here rather than in the credential
   * document so the key and the ciphertext it opens live in different files.
   */
  recordsKey?: string | undefined
}

export interface ParsedProviderRuntimeState {
  state: ProviderRuntimeState
  invalidFields: string[]
}

const rememberDaysSchema = pipe(number(), integer(), minValue(-1), maxValue(30))
const failuresSchema = pipe(number(), integer(), minValue(0))
const timestampSchema = pipe(number(), finite(), minValue(0))
const encryptedSchema = boolean()
const recordsKeySchema = pipe(
  string(),
  check<string>(value => {
    try {
      parseMasterKey(value)
      return true
    } catch {
      return false
    }
  }),
)

/** Validate each state field independently so one bad field cannot erase good state. */
export function parseProviderRuntimeState(input: unknown): ParsedProviderRuntimeState {
  if (!isPlainRecord(input)) return { state: {}, invalidFields: ['document'] }
  const state: ProviderRuntimeState = {}
  const invalidFields: string[] = []
  copyField(input, state, invalidFields, 'rememberDays', rememberDaysSchema)
  copyField(input, state, invalidFields, 'encrypted', encryptedSchema)
  copyField(input, state, invalidFields, 'unlockFailures', failuresSchema)
  copyField(input, state, invalidFields, 'unlockLockedUntil', timestampSchema)
  copyField(input, state, invalidFields, 'recordsKey', recordsKeySchema)
  return { state, invalidFields }
}

/** Serialize only meaningful provider state fields. */
export function serializeProviderRuntimeState(state: ProviderRuntimeState): string {
  const document: ProviderRuntimeState = {}
  if (state.rememberDays !== void 0 && safeParse(rememberDaysSchema, state.rememberDays).success) {
    document.rememberDays = state.rememberDays
  }
  if (state.encrypted === true) document.encrypted = true
  if (
    state.unlockFailures !== void 0 &&
    state.unlockFailures > 0 &&
    safeParse(failuresSchema, state.unlockFailures).success
  ) {
    document.unlockFailures = state.unlockFailures
  }
  if (
    state.unlockLockedUntil !== void 0 &&
    state.unlockLockedUntil > 0 &&
    safeParse(timestampSchema, state.unlockLockedUntil).success
  ) {
    document.unlockLockedUntil = state.unlockLockedUntil
  }
  if (state.recordsKey !== void 0 && safeParse(recordsKeySchema, state.recordsKey).success) {
    document.recordsKey = state.recordsKey
  }
  return `${JSON.stringify(document, null, 2)}\n`
}

function copyField(
  input: Record<string, unknown>,
  output: ProviderRuntimeState,
  invalidFields: string[],
  field: keyof ProviderRuntimeState,
  schema: Parameters<typeof safeParse>[0],
): void {
  const value = input[field]
  if (value === void 0) return
  const parsed = safeParse(schema, value)
  if (parsed.success) output[field] = parsed.output as never
  else invalidFields.push(field)
}
