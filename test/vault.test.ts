import type { SealedRecordValue } from '../lib/vault.js'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { describe, it } from 'vitest'
import {
  RECORD_VAULT_VERSION,
  VAULT_ALGORITHM,
  VAULT_VERSION,
  VaultError,
  argon2Defaults,
  createPasswordKeyFile,
  decryptEntry,
  decryptRecordPayload,
  deriveArgon2idKey,
  deriveMasterKey,
  deriveScryptKey,
  detectCredentialStore,
  encodeMasterKey,
  encryptCredentialStore,
  encryptEntry,
  encryptRecordPayload,
  generateMasterKey,
  generatePasswordSalt,
  isPasswordKeyFile,
  parseDocument,
  parseEncryptedStore,
  parseMasterKey,
  parsePasswordKeyFile,
  serializeDocument,
  sha3_256Hex,
  unlockEncryptedStore,
  verifyDocument,
  zeroizeBuffer,
} from '../lib/vault.js'

const key = generateMasterKey()
const KEY_B64 = encodeMasterKey(key)

/** The v4 store fields the tampering test edits; parsed JSON is untrusted but typed for the assertions. */
interface TamperableStore {
  version: number
  sha3: string
  records: Record<'demo/account', { data: string }>
  [field: string]: unknown
}

describe('master key encoding', () => {
  it('round-trips through base64url', () => {
    assert.deepEqual(parseMasterKey(KEY_B64), key)
  })
  it('accepts bare hex', () => {
    assert.deepEqual(parseMasterKey(key.toString('hex')), key)
  })
  it('trims surrounding whitespace', () => {
    assert.deepEqual(parseMasterKey(`  ${KEY_B64}\n`), key)
  })
  it('rejects wrong lengths and junk', () => {
    assert.throws(() => parseMasterKey(''), { code: 'MASTER_KEY_INVALID' })
    assert.throws(() => parseMasterKey('abc'), { code: 'MASTER_KEY_INVALID' })
    assert.throws(() => parseMasterKey('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'), { code: 'MASTER_KEY_INVALID' })
    assert.throws(() => parseMasterKey('f'.repeat(63)), { code: 'MASTER_KEY_INVALID' })
  })
  it('zeroizes buffers', () => {
    const k = generateMasterKey()
    zeroizeBuffer(k)
    assert.ok(k.every(byte => byte === 0))
  })
})

describe('entry encryption', () => {
  it('round-trips plaintext', () => {
    const record = encryptEntry(key, 'DEEPSEEK_API_KEY', 'sk-secret-value')
    assert.equal(decryptEntry(key, 'DEEPSEEK_API_KEY', record), 'sk-secret-value')
  })
  it('stores nothing resembling plaintext', () => {
    const record = encryptEntry(key, 'OPENCODE_GO_API_KEY', 'sk-very-secret-12345')
    assert.ok(!record.data.includes('sk-very-secret'))
    assert.ok(!record.data.includes('secret'))
    assert.match(record.sha3, /^[0-9a-f]{64}$/)
  })
  it('draws a fresh nonce per encryption (same value, different ciphertext)', () => {
    const a = encryptEntry(key, 'TEST', 'same-value')
    const b = encryptEntry(key, 'TEST', 'same-value')
    assert.notEqual(a.data, b.data)
    assert.notEqual(a.sha3, b.sha3)
  })
  it('rejects empty plaintext and invalid references', () => {
    assert.throws(() => encryptEntry(key, 'TEST', ''), { code: 'VAULT_INVALID' })
    assert.throws(() => encryptEntry(key, '9BAD', 'value'), { code: 'VAULT_INVALID' })
  })
  it('detects a flipped ciphertext byte via entry SHA3-256 (corruption, not keyed tampering)', () => {
    const record = encryptEntry(key, 'CORRUPT_ME', 'value')
    const flipped = { ...record, data: `${record.data.slice(0, -1)}${record.data.endsWith('A') ? 'B' : 'A'}` }
    assert.throws(
      () => decryptEntry(key, 'CORRUPT_ME', flipped),
      error => {
        assert.ok(error instanceof VaultError)
        assert.equal(error.code, 'VAULT_CORRUPTED')
        assert.match(error.message, /CORRUPT_ME/)
        return true
      },
    )
  })
  it('fails when the master key does not match (GCM authentication)', () => {
    const record = encryptEntry(key, 'WRONG_KEY', 'value')
    assert.throws(() => decryptEntry(generateMasterKey(), 'WRONG_KEY', record), { code: 'VAULT_KEY_MISMATCH' })
  })
  it("rejects a ciphertext swapped into another entry's slot (reference is GCM AAD)", () => {
    const a = encryptEntry(key, 'REF_A', 'value-a')
    assert.throws(
      () => decryptEntry(key, 'REF_B', a),
      error => {
        assert.ok(error instanceof VaultError)
        assert.ok(error.code === 'VAULT_KEY_MISMATCH' || error.code === 'VAULT_CORRUPTED')
        return true
      },
    )
  })
  it('rejects a recomputed-fingerprint tampered blob (attacker fixed the SHA3, GCM tag still fails)', () => {
    const record = encryptEntry(key, 'TAMPER', 'value')
    // Flip one ciphertext character and recompute the fingerprint the way an
    // attacker without the key would: entry SHA3 passes, GCM must reject.
    const flippedData = `${record.data.slice(0, -1)}${record.data.endsWith('A') ? 'B' : 'A'}`
    const fingerprint = createHash('sha3-256').update(flippedData, 'utf8').digest('hex')
    const forged = { data: flippedData, sha3: fingerprint }
    assert.throws(() => decryptEntry(key, 'TAMPER', forged), { code: 'VAULT_KEY_MISMATCH' })
  })
})

describe('document serialization and startup verification', () => {
  it('produces a verifiable canonical document', () => {
    const entries = new Map([
      ['B_KEY', encryptEntry(key, 'B_KEY', 'b')],
      ['A_KEY', encryptEntry(key, 'A_KEY', 'a')],
    ])
    const text = serializeDocument(entries)
    const parsed = parseDocument(text)
    assert.equal(parsed.entries.size, 2)
    assert.equal(decryptEntry(key, 'A_KEY', parsed.entries.get('A_KEY')), 'a')
    assert.equal(decryptEntry(key, 'B_KEY', parsed.entries.get('B_KEY')), 'b')
  })
  it('is stable regardless of map insertion order', () => {
    const recordA = encryptEntry(key, 'A', 'x')
    const recordB = encryptEntry(key, 'B', 'y')
    const text1 = serializeDocument(
      new Map([
        ['A', recordA],
        ['B', recordB],
      ]),
    )
    const text2 = serializeDocument(
      new Map([
        ['B', recordB],
        ['A', recordA],
      ]),
    )
    assert.equal(text1, text2)
  })
  it('detects an altered entry through the document-level SHA3-256', () => {
    const entries = new Map([['KEY', encryptEntry(key, 'KEY', 'value')]])
    const text = serializeDocument(entries)
    const doc = JSON.parse(text)
    doc.entries.KEY.data = `${doc.entries.KEY.data.slice(0, -1)}${doc.entries.KEY.data.endsWith('A') ? 'B' : 'A'}`
    assert.throws(() => parseDocument(`${JSON.stringify(doc, null, 2)}\n`), { code: 'VAULT_CORRUPTED' })
  })
  it('detects a whole added entry not covered by the document fingerprint', () => {
    const text = serializeDocument(new Map([['KEY', encryptEntry(key, 'KEY', 'value')]]))
    const doc = JSON.parse(text)
    doc.entries.SNEAKY = encryptEntry(key, 'SNEAKY', 'injected')
    assert.throws(() => parseDocument(`${JSON.stringify(doc, null, 2)}\n`), { code: 'VAULT_CORRUPTED' })
  })
  it('rejects structurally invalid documents', () => {
    assert.throws(() => parseDocument('not json'), { code: 'VAULT_INVALID' })
    assert.throws(() => parseDocument('[]'), { code: 'VAULT_INVALID' })
    assert.throws(
      () => parseDocument(JSON.stringify({ version: 99, algorithm: VAULT_ALGORITHM, sha3: '', entries: {} })),
      { code: 'VAULT_INVALID' },
    )
    assert.throws(
      () => parseDocument(JSON.stringify({ version: VAULT_VERSION, algorithm: 'rot13', sha3: '', entries: {} })),
      { code: 'VAULT_INVALID' },
    )
    assert.throws(
      () =>
        parseDocument(
          JSON.stringify({ version: VAULT_VERSION, algorithm: VAULT_ALGORITHM, sha3: '', entries: { '9bad': {} } }),
        ),
      { code: 'VAULT_INVALID' },
    )
    // structurally valid entry, wrong fingerprint → corruption, not invalidity
    assert.throws(
      () =>
        parseDocument(
          JSON.stringify({
            version: VAULT_VERSION,
            algorithm: VAULT_ALGORITHM,
            sha3: '',
            entries: { GOOD: { data: 'x', sha3: 'y' } },
          }),
        ),
      { code: 'VAULT_CORRUPTED' },
    )
  })
  it('verifyDocument is a green path for a fresh document', () => {
    verifyDocument(serializeDocument(new Map([['KEY', encryptEntry(key, 'KEY', 'value')]])))
  })
})

describe('password-derived master keys', () => {
  const PASSWORD = 'correct horse battery staple'
  it('derives a key, round-trips the password key file, and never stores the password', async () => {
    const salt = generatePasswordSalt()
    const derived = await deriveArgon2idKey(PASSWORD, salt, argon2Defaults())
    assert.equal(derived.length, 32)
    const text = createPasswordKeyFile(derived, salt)
    assert.ok(isPasswordKeyFile(text))
    assert.ok(!text.includes(PASSWORD), 'the password must never be stored')
    const again = await parsePasswordKeyFile(text, PASSWORD)
    assert.deepEqual(again, derived)
    const entries = new Map([['KEY', encryptEntry(derived, 'KEY', 'value')]])
    assert.equal(decryptEntry(again, 'KEY', entries.get('KEY')), 'value')
    zeroizeBuffer(derived)
    zeroizeBuffer(again)
  })
  it('rejects a wrong password with PASSWORD_WRONG', async () => {
    const salt = generatePasswordSalt()
    const derived = await deriveArgon2idKey(PASSWORD, salt, argon2Defaults())
    const text = createPasswordKeyFile(derived, salt)
    await assert.rejects(parsePasswordKeyFile(text, 'wrong password'), { code: 'PASSWORD_WRONG' })
    zeroizeBuffer(derived)
  })
  it('different salts derive different keys from the same password', async () => {
    const a = await deriveArgon2idKey(PASSWORD, generatePasswordSalt(), argon2Defaults())
    const b = await deriveArgon2idKey(PASSWORD, generatePasswordSalt(), argon2Defaults())
    assert.notDeepEqual(a, b)
    zeroizeBuffer(a)
    zeroizeBuffer(b)
  })
  it('rejects password-derivation parameters above the generated document limits', async () => {
    const salt = generatePasswordSalt()
    await assert.rejects(deriveArgon2idKey(sha3_256Hex(PASSWORD), salt, { m: 65537, t: 3, p: 1 }), {
      code: 'MASTER_KEY_INVALID',
    })
    await assert.rejects(deriveArgon2idKey(sha3_256Hex(PASSWORD), salt, { m: 65536, t: 4, p: 1 }), {
      code: 'MASTER_KEY_INVALID',
    })
    await assert.rejects(deriveScryptKey(sha3_256Hex(PASSWORD), salt, { n: 131072, r: 8, p: 2 }), {
      code: 'MASTER_KEY_INVALID',
    })
  })
  it('rejects empty passwords, empty salts, and garbage key files', async () => {
    await assert.rejects(deriveMasterKey('', generatePasswordSalt()), { code: 'PASSWORD_INVALID' })
    await assert.rejects(deriveMasterKey(sha3_256Hex(PASSWORD), Buffer.alloc(0)), { code: 'MASTER_KEY_INVALID' })
    assert.equal(isPasswordKeyFile('not json'), false)
    assert.equal(isPasswordKeyFile(`${encodeMasterKey(generateMasterKey())}\n`), false)
    await assert.rejects(parsePasswordKeyFile('not json', PASSWORD), { code: 'MASTER_KEY_INVALID' })
    await assert.rejects(parsePasswordKeyFile(JSON.stringify({ kdf: 'pbkdf2' }), PASSWORD), {
      code: 'MASTER_KEY_INVALID',
    })
  })
  it('a tampered key-file verifier reports PASSWORD_WRONG, not a crash', async () => {
    const salt = generatePasswordSalt()
    const derived = await deriveArgon2idKey(PASSWORD, salt, argon2Defaults())
    const text = createPasswordKeyFile(derived, salt)
    const doc = JSON.parse(text)
    doc.verifier.data = `${doc.verifier.data.slice(0, -1)}${doc.verifier.data.endsWith('A') ? 'B' : 'A'}`
    await assert.rejects(parsePasswordKeyFile(`${JSON.stringify(doc, null, 2)}\n`, PASSWORD), {
      code: 'PASSWORD_WRONG',
    })
    zeroizeBuffer(derived)
  })
})

describe('single-file encrypted credential store', () => {
  const PASSWORD = 'webui password eleven'
  const DIGEST = sha3_256Hex(PASSWORD)
  it('detectCredentialStore separates the two forms', async () => {
    const created = await encryptCredentialStore(new Map([['KEY', 'value']]), DIGEST)
    assert.equal(detectCredentialStore(created.text), 'encrypted')
    assert.equal(detectCredentialStore('KEY: value\n'), 'plain')
    assert.equal(detectCredentialStore(''), 'plain')
    assert.equal(detectCredentialStore('not json at all'), 'plain')
    assert.equal(detectCredentialStore('{"kdf":"scrypt"}'), 'plain')
    zeroizeBuffer(created.key)
  })
  it('encrypts in place: ciphertext without plaintext, unlock round-trips', async () => {
    const plaintexts = new Map([
      ['A_KEY', 'sk-a'],
      ['B_KEY', 'sk-b'],
    ])
    const created = await encryptCredentialStore(plaintexts, DIGEST)
    assert.ok(!created.text.includes('sk-a'))
    assert.ok(!created.text.includes(PASSWORD))
    assert.equal(created.entries.size, 2)
    const unlocked = await unlockEncryptedStore(created.text, DIGEST)
    assert.equal(decryptEntry(unlocked.key, 'A_KEY', unlocked.entries.get('A_KEY')), 'sk-a')
    assert.equal(decryptEntry(unlocked.key, 'B_KEY', unlocked.entries.get('B_KEY')), 'sk-b')
    zeroizeBuffer(created.key)
    zeroizeBuffer(unlocked.key)
  })
  it('rejects a wrong password with PASSWORD_WRONG before any entry is touched', async () => {
    const created = await encryptCredentialStore(new Map([['KEY', 'value']]), DIGEST)
    await assert.rejects(unlockEncryptedStore(created.text, sha3_256Hex('wrong password')), { code: 'PASSWORD_WRONG' })
    zeroizeBuffer(created.key)
  })
  it('document fingerprint covers the header: tampering salt or cost params is CORRUPTED', async () => {
    const created = await encryptCredentialStore(new Map([['KEY', 'value']]), DIGEST)
    const doc = JSON.parse(created.text)
    doc.salt = `${doc.salt.slice(0, -1)}${doc.salt.endsWith('A') ? 'B' : 'A'}`
    assert.throws(() => parseEncryptedStore(`${JSON.stringify(doc, null, 2)}\n`), { code: 'VAULT_CORRUPTED' })
    const doc2 = JSON.parse(created.text)
    doc2.n = doc2.n - 1
    assert.throws(() => parseEncryptedStore(`${JSON.stringify(doc2, null, 2)}\n`), { code: 'VAULT_CORRUPTED' })
    zeroizeBuffer(created.key)
  })
  it('tampering a ciphertext entry is VAULT_CORRUPTED with the reference named', async () => {
    const created = await encryptCredentialStore(new Map([['CORRUPT_ME', 'value']]), DIGEST)
    // Plain tampering is caught by the document fingerprint first (no entry
    // name, the header-level message). An attacker who recomputes the
    // document fingerprint falls through to the entry-level check, which
    // names the entry.
    const doc = JSON.parse(created.text)
    doc.entries.CORRUPT_ME.data = `${doc.entries.CORRUPT_ME.data.slice(0, -1)}${doc.entries.CORRUPT_ME.data.endsWith('A') ? 'B' : 'A'}`
    assert.throws(() => parseEncryptedStore(`${JSON.stringify(doc, null, 2)}\n`), { code: 'VAULT_CORRUPTED' })
    const forged = JSON.parse(created.text)
    forged.entries.CORRUPT_ME.data = `${forged.entries.CORRUPT_ME.data.slice(0, -1)}${forged.entries.CORRUPT_ME.data.endsWith('A') ? 'B' : 'A'}`
    const fingerprintFields = [
      'format',
      'version',
      'algorithm',
      'kdf',
      'kdfInput',
      'n',
      'r',
      'm',
      't',
      'p',
      'salt',
      'verifier',
      'remember',
      'entries',
    ]
    const fingerprintTarget = Object.fromEntries(
      fingerprintFields.filter(field => forged[field] !== undefined).map(field => [field, forged[field]]),
    )
    forged.sha3 = createHash('sha3-256').update(JSON.stringify(fingerprintTarget), 'utf8').digest('hex')
    assert.throws(
      () => parseEncryptedStore(`${JSON.stringify(forged, null, 2)}\n`),
      error => {
        assert.ok(error instanceof VaultError)
        assert.equal(error.code, 'VAULT_CORRUPTED')
        assert.match(error.message, /CORRUPT_ME/)
        return true
      },
    )
    zeroizeBuffer(created.key)
  })
  it('rejects empty passwords and structurally invalid stores', async () => {
    await assert.rejects(encryptCredentialStore(new Map(), ''), { code: 'PASSWORD_INVALID' })
    assert.throws(() => parseEncryptedStore('not json'), { code: 'VAULT_INVALID' })
    assert.throws(() => parseEncryptedStore(JSON.stringify({ format: 'dsh-encrypt-credentials' })), {
      code: 'VAULT_INVALID',
    })
    assert.throws(
      () =>
        parseEncryptedStore(
          JSON.stringify({
            format: 'dsh-encrypt-credentials',
            version: 99,
            algorithm: VAULT_ALGORITHM,
            kdf: 'scrypt',
            n: 1,
            r: 1,
            p: 1,
            salt: '',
            verifier: {},
            entries: {},
            sha3: '',
          }),
        ),
      { code: 'VAULT_INVALID' },
    )
  })
})

describe('credential record payloads and versioned stores', () => {
  const PASSWORD = 'records password six'
  const DIGEST = sha3_256Hex(PASSWORD)
  const RECORD_KEY = 'demo/account'
  const RECORD_JSON = JSON.stringify({ kind: 'api-key', key: 'sk-record-1' })

  const sealOne = (
    key: Buffer,
    seal: 'password' | 'machine',
    kind: 'api-key' | 'grant',
  ): Map<string, SealedRecordValue> =>
    new Map<string, SealedRecordValue>([
      [RECORD_KEY, { form: 'sealed', kind, seal, entry: encryptRecordPayload(key, RECORD_KEY, RECORD_JSON) }],
    ])

  it('round-trips a record payload bound to its key as GCM AAD', () => {
    const masterKey = generateMasterKey()
    const sealed = encryptRecordPayload(masterKey, RECORD_KEY, RECORD_JSON)
    assert.equal(decryptRecordPayload(masterKey, RECORD_KEY, sealed), RECORD_JSON)
    assert.ok(!sealed.data.includes('sk-record-1'))
    assert.throws(() => decryptRecordPayload(masterKey, 'demo/other', sealed), { code: 'VAULT_KEY_MISMATCH' })
    assert.throws(() => encryptRecordPayload(masterKey, 'DEMO_ACCOUNT', RECORD_JSON), { code: 'VAULT_INVALID' })
    assert.throws(() => encryptRecordPayload(masterKey, RECORD_KEY, ''), { code: 'VAULT_INVALID' })
    zeroizeBuffer(masterKey)
  })
  it('writes version 4 only when records exist, and unlock returns them', async () => {
    const bare = await encryptCredentialStore(new Map([['KEY', 'value']]), DIGEST)
    assert.equal(JSON.parse(bare.text).version, VAULT_VERSION, 'a record-less store stays readable by older builds')
    const withRecords = await encryptCredentialStore(new Map([['KEY', 'value']]), DIGEST, argon2Defaults(), key =>
      sealOne(key, 'password', 'api-key'),
    )
    const doc = JSON.parse(withRecords.text) as {
      version: number
      records: Record<'demo/account', { seal: string; kind: string }>
    }
    assert.equal(doc.version, RECORD_VAULT_VERSION)
    assert.deepEqual(Object.keys(doc.records), [RECORD_KEY])
    assert.equal(doc.records[RECORD_KEY].seal, 'password')
    assert.equal(doc.records[RECORD_KEY].kind, 'api-key')
    const unlocked = await unlockEncryptedStore(withRecords.text, DIGEST)
    const slot = unlocked.records.get(RECORD_KEY)
    assert.ok(slot !== undefined && slot.form === 'sealed')
    assert.equal(decryptRecordPayload(unlocked.key, RECORD_KEY, slot.entry), RECORD_JSON)
    zeroizeBuffer(bare.key)
    zeroizeBuffer(withRecords.key)
    zeroizeBuffer(unlocked.key)
  })
  it('covers records with the document fingerprint and the record-level check', async () => {
    const created = await encryptCredentialStore(new Map([['KEY', 'value']]), DIGEST, argon2Defaults(), key =>
      sealOne(key, 'machine', 'grant'),
    )
    const flipped = (data: string) => `${data.slice(0, -1)}${data.endsWith('A') ? 'B' : 'A'}`
    const doc = JSON.parse(created.text) as TamperableStore
    doc.records[RECORD_KEY].data = flipped(doc.records[RECORD_KEY].data)
    assert.throws(() => parseEncryptedStore(`${JSON.stringify(doc, null, 2)}\n`), { code: 'VAULT_CORRUPTED' })
    // An attacker who recomputes the document fingerprint falls through to the
    // record-level SHA3-256 check, which names the record.
    const forged = JSON.parse(created.text) as TamperableStore
    forged.records[RECORD_KEY].data = flipped(forged.records[RECORD_KEY].data)
    const fingerprintFields = [
      'format',
      'version',
      'algorithm',
      'kdf',
      'kdfInput',
      'n',
      'r',
      'm',
      't',
      'p',
      'salt',
      'verifier',
      'remember',
      'entries',
      'records',
    ]
    const fingerprintTarget = Object.fromEntries(
      fingerprintFields.filter(field => forged[field] !== undefined).map(field => [field, forged[field]]),
    )
    forged.sha3 = createHash('sha3-256').update(JSON.stringify(fingerprintTarget), 'utf8').digest('hex')
    assert.throws(
      () => parseEncryptedStore(`${JSON.stringify(forged, null, 2)}\n`),
      error => {
        assert.ok(error instanceof VaultError)
        assert.equal(error.code, 'VAULT_CORRUPTED')
        assert.match(error.message, /demo\/account/)
        return true
      },
    )
    zeroizeBuffer(created.key)
  })
})
