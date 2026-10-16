import type { ProviderConfig } from '../lib/index.js'
import type { CredentialRecord, CredentialRef } from '@deepseek-ai/dsh-credentials'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { credentialKey, credentialRef } from '@deepseek-ai/dsh-credentials'
import { describe, it } from 'vitest'
import { EncryptedCredentialProvider } from '../lib/index.js'

// The legacy reference event older dsh lines listen to; the pinned seam only
// declares the current `credentials/reference-updated` name.
declare module '@deepseek-ai/cordis' {
  interface Events {
    'credentials/updated': (ref: CredentialRef) => void
  }
}

/** Boot a provider over a fresh harness home and return its contexts. */
async function bootProvider(home: string, overrides: ProviderConfig = {}) {
  const ctx = new Context()
  const fiber = ctx.plugin(EncryptedCredentialProvider, {
    dshHome: home,
    watch: false,
    ...overrides,
  })
  await fiber
  const provider = await ctx.get('credentials')
  assert.ok(provider instanceof EncryptedCredentialProvider)
  return { ctx, fiber, provider }
}

const passwordDigest = (password: string) => createHash('sha3-256').update(password, 'utf8').digest('hex')
const PASSWORD = 'records password'
const PASSWORD_DIGEST = passwordDigest(PASSWORD)
const storePath = (home: string) => join(home, '.credentials.yaml')
const statePath = (home: string) => join(home, '.dsh-encrypt.json')
const browserKey = credentialKey('client-connection', 'browser-session')

describe('credential records', () => {
  it('plain form: records live in the versioned layout and round-trip across a restart', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-record-'))
    try {
      const first = await bootProvider(home)
      const key = credentialKey('demo', 'account')
      const record: CredentialRecord = { kind: 'api-key', key: 'sk-record-1', env: { AWS_PROFILE: 'demo' } }
      assert.equal(await first.provider.readRecord(key), undefined)
      assert.deepEqual(await first.provider.describeRecord(key), { configured: false, writable: true })
      assert.deepEqual(await first.provider.listRecords(), [])
      assert.deepEqual(await first.provider.modifyRecord(key, async () => record), record)
      assert.deepEqual(await first.provider.readRecord(key), record)
      assert.deepEqual(await first.provider.describeRecord(key), { configured: true, kind: 'api-key', writable: true })
      assert.deepEqual(await first.provider.listRecords(), [{ key, kind: 'api-key' }])
      // a declined mutation leaves the record untouched
      assert.deepEqual(await first.provider.modifyRecord(key, async () => undefined), record)
      const text = await readFile(storePath(home), 'utf8')
      assert.ok(text.startsWith('version: 1\n'), 'records force the versioned plaintext layout')
      assert.ok(text.includes('records:'), 'the record section is present')
      assert.ok(text.includes('sk-record-1'), 'the plain form stores the record verbatim')
      first.fiber.dispose()
      const second = await bootProvider(home)
      assert.deepEqual(await second.provider.readRecord(key), record)
      await second.provider.deleteRecord(key)
      assert.equal(await second.provider.readRecord(key), undefined)
      assert.ok(!(await readFile(storePath(home), 'utf8')).includes('sk-record-1'))
      second.fiber.dispose()
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('migrates a flat plaintext file to the versioned layout without losing comments', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-record-'))
    try {
      await writeFile(storePath(home), 'FIRST: keep-me  # a comment\n')
      const first = await bootProvider(home)
      assert.equal((await first.provider.resolve(credentialRef('FIRST')))?.value, 'keep-me')
      await first.provider.set(credentialRef('SECOND'), 'second-value')
      const text = await readFile(storePath(home), 'utf8')
      assert.ok(text.startsWith('version: 1\n'))
      assert.ok(text.includes('refs:'))
      assert.ok(text.includes('FIRST: keep-me'), 'the original value survives')
      assert.ok(text.includes('# a comment'), 'the original comment survives')
      assert.ok(text.includes('SECOND: second-value'))
      first.fiber.dispose()
      const second = await bootProvider(home)
      assert.equal((await second.provider.resolve(credentialRef('FIRST')))?.value, 'keep-me')
      assert.equal((await second.provider.resolve(credentialRef('SECOND')))?.value, 'second-value')
      second.fiber.dispose()
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('keeps unknown top-level keys of a versioned document across writes', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-record-'))
    try {
      await writeFile(storePath(home), 'version: 1\nrefs:\n  KNOWN: known-value\nfuture-tool:\n  hint: keep\n')
      const first = await bootProvider(home)
      assert.equal((await first.provider.resolve(credentialRef('KNOWN')))?.value, 'known-value')
      await first.provider.set(credentialRef('OTHER'), 'other-value')
      const text = await readFile(storePath(home), 'utf8')
      assert.ok(text.includes('future-tool:'), 'unknown sections survive the write')
      assert.ok(text.includes('known-value'))
      assert.ok(text.includes('other-value'))
      first.fiber.dispose()
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('encrypted form: policy seals — machine records stay readable while locked, password records refuse', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-record-'))
    try {
      const first = await bootProvider(home)
      await first.provider.set(credentialRef('KEY'), 'secret')
      await first.provider.setPassword(PASSWORD_DIGEST)
      const account = credentialKey('demo', 'account')
      const accountRecord: CredentialRecord = { kind: 'api-key', key: 'sk-account' }
      const browserRecord: CredentialRecord = { kind: 'grant', payload: { token: 't-1', issuedAt: 1 } }
      await first.provider.modifyRecord(account, async () => accountRecord)
      await first.provider.modifyRecord(browserKey, async () => browserRecord)
      const doc = JSON.parse(await readFile(storePath(home), 'utf8')) as {
        version: number
        records: Record<string, { seal: string; kind: string; data: string }>
      }
      assert.equal(doc.version, 4)
      assert.equal(doc.records['demo/account']?.seal, 'password')
      assert.equal(doc.records['demo/account']?.kind, 'api-key')
      assert.equal(doc.records['client-connection/browser-session']?.seal, 'machine')
      assert.ok(!doc.records['demo/account']?.data.includes('sk-account'), 'record payloads are ciphertext')
      first.fiber.dispose()

      const second = await bootProvider(home)
      assert.deepEqual(await second.provider.readRecord(browserKey), browserRecord)
      assert.equal(
        await second.provider.readRecord(account),
        undefined,
        'password-sealed records read as absent while locked',
      )
      assert.deepEqual(await second.provider.describeRecord(account), {
        configured: true,
        kind: 'api-key',
        writable: false,
      })
      assert.deepEqual(await second.provider.describeRecord(browserKey), {
        configured: true,
        kind: 'grant',
        writable: true,
      })
      assert.deepEqual(await second.provider.listRecords(), [
        { key: browserKey, kind: 'grant' },
        { key: account, kind: 'api-key' },
      ])
      await assert.rejects(
        second.provider.modifyRecord(account, async () => accountRecord),
        { code: 'VAULT_LOCKED' },
      )
      // a record created while locked is machine-sealed and rewrites the document without the password key
      const fresh = credentialKey('demo', 'fresh')
      const freshRecord: CredentialRecord = { kind: 'grant', payload: { refresh: 'r-1' } }
      assert.deepEqual(await second.provider.modifyRecord(fresh, async () => freshRecord), freshRecord)
      assert.deepEqual(await second.provider.readRecord(fresh), freshRecord)
      assert.equal(
        (JSON.parse(await readFile(storePath(home), 'utf8')) as { records: Record<string, { seal: string }> }).records[
          'demo/fresh'
        ]?.seal,
        'machine',
      )
      // deleting a record while locked needs no key either
      await second.provider.deleteRecord(fresh)
      assert.equal(await second.provider.readRecord(fresh), undefined)
      // an absent record with a declining mutation stays absent
      assert.equal(await second.provider.modifyRecord(fresh, async () => undefined), undefined)
      assert.deepEqual(await second.provider.describeRecord(fresh), { configured: false, writable: true })
      await second.provider.unlock(PASSWORD_DIGEST)
      assert.deepEqual(
        await second.provider.readRecord(account),
        accountRecord,
        'unlock restores password-sealed records',
      )
      second.fiber.dispose()
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('emits record updates while locked, re-announces on unlock, and dual-emits reference events', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-record-'))
    try {
      const first = await bootProvider(home)
      await first.provider.set(credentialRef('KEY'), 'secret')
      await first.provider.setPassword(PASSWORD_DIGEST)
      const account = credentialKey('demo', 'account')
      await first.provider.modifyRecord(account, async () => ({ kind: 'api-key', key: 'sk-account' }))
      await first.provider.modifyRecord(browserKey, async () => ({ kind: 'grant', payload: { token: 't-1' } }))
      first.fiber.dispose()

      const second = await bootProvider(home)
      const recordEvents: string[] = []
      const refEvents: string[] = []
      const legacyEvents: string[] = []
      second.ctx.on('credentials/record-updated', key => recordEvents.push(key))
      second.ctx.on('credentials/reference-updated', ref => refEvents.push(ref))
      second.ctx.on('credentials/updated', ref => legacyEvents.push(ref))
      await second.provider.modifyRecord(browserKey, async () => ({ kind: 'grant', payload: { token: 't-2' } }))
      assert.deepEqual(recordEvents, [browserKey], 'the locked write emits the record event')
      await second.provider.unlock(PASSWORD_DIGEST)
      assert.deepEqual(recordEvents, [browserKey, account], 'unlock re-announces only password-sealed records')
      assert.deepEqual(refEvents, [])
      await second.provider.set(credentialRef('KEY'), 'secret-2')
      assert.deepEqual(refEvents, ['KEY'], 'the current reference event name is emitted')
      assert.deepEqual(legacyEvents, ['KEY'], 'the legacy reference event name is emitted too')
      second.fiber.dispose()
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('drops unreadable machine records when the state file lost the records key, then rebuilds them', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-record-'))
    try {
      const first = await bootProvider(home)
      await first.provider.set(credentialRef('KEY'), 'secret')
      await first.provider.setPassword(PASSWORD_DIGEST)
      await first.provider.modifyRecord(browserKey, async () => ({ kind: 'grant', payload: { token: 't-1' } }))
      first.fiber.dispose()

      const state = JSON.parse(await readFile(statePath(home), 'utf8')) as Record<string, unknown>
      assert.equal(typeof state.recordsKey, 'string')
      delete state.recordsKey
      await writeFile(statePath(home), JSON.stringify(state))

      const second = await bootProvider(home)
      assert.equal(
        await second.provider.readRecord(browserKey),
        undefined,
        'lost machine ciphertext is dropped, not guessed at',
      )
      const rebuilt: CredentialRecord = { kind: 'grant', payload: { token: 't-2' } }
      assert.deepEqual(await second.provider.modifyRecord(browserKey, async () => rebuilt), rebuilt)
      const regenerated = JSON.parse(await readFile(statePath(home), 'utf8')) as Record<string, unknown>
      assert.equal(
        typeof regenerated.recordsKey,
        'string',
        'a new records key is persisted before the document that needs it',
      )
      second.fiber.dispose()

      const third = await bootProvider(home)
      assert.deepEqual(await third.provider.readRecord(browserKey), rebuilt)
      third.fiber.dispose()
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('refuses record access while a plaintext file is forbidden (encrypted file removed)', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-record-'))
    try {
      const { provider } = await bootProvider(home)
      await provider.set(credentialRef('KEY'), 'secret')
      await provider.setPassword(PASSWORD_DIGEST)
      const key = credentialKey('demo', 'account')
      const record: CredentialRecord = { kind: 'api-key', key: 'sk-account' }
      await provider.modifyRecord(key, async () => record)
      await rm(storePath(home))
      await assert.rejects(provider.set(credentialRef('NEW_KEY'), 'must-not-be-plain'), { code: 'VAULT_INVALID' })
      assert.equal(await provider.readRecord(key), undefined)
      assert.deepEqual(await provider.listRecords(), [])
      assert.deepEqual(await provider.describeRecord(key), { configured: false, writable: false })
      await assert.rejects(
        provider.modifyRecord(key, async () => record),
        { code: 'VAULT_INVALID' },
      )
      await assert.rejects(provider.deleteRecord(key), { code: 'VAULT_INVALID' })
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
})
