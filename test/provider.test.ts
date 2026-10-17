import type { ProviderConfig } from '../lib/index.js'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { describe, it } from 'vitest'
import { EncryptedCredentialProvider } from '../lib/index.js'

/** Boot a provider over a fresh harness home and return its disposal helper. */
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
const PASSWORD = 'correct horse battery staple'
const PASSWORD_DIGEST = passwordDigest(PASSWORD)
const storePath = (home: string) => join(home, '.credentials.yaml')

async function assertStatus(provider: EncryptedCredentialProvider, format: 'plain' | 'encrypted', unlocked: boolean) {
  const status = await provider.status()
  assert.equal(status.format, format)
  assert.equal(status.unlocked, unlocked)
}

describe('dsh-encrypt single-file provider', () => {
  it('default plain form: full seam contract, plaintext YAML on disk', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const { provider } = await bootProvider(home)
      await assertStatus(provider, 'plain', true)
      const ref = credentialRef('TEST_KEY')
      assert.equal(await provider.resolve(ref), undefined)
      assert.deepEqual(await provider.describe(ref), { configured: false, writable: true })
      await provider.set(ref, 'sk-plain-value-1')
      const text = await readFile(storePath(home), 'utf8')
      assert.ok(text.includes('sk-plain-value-1'), 'plain form stores the value verbatim')
      const hit = await provider.resolve(ref)
      assert.ok(hit)
      assert.equal(hit.value, 'sk-plain-value-1')
      assert.equal(hit.source, 'file')
      await provider.unset(ref)
      assert.equal(await provider.resolve(ref), undefined)
      // unset of an absent ref is a no-op
      await provider.unset(ref)
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('setPassword replaces the file contents with ciphertext in place and stays unlocked', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const { provider } = await bootProvider(home)
      await provider.set(credentialRef('KEY_A'), 'sk-super-secret-42')
      await provider.setPassword(PASSWORD_DIGEST)
      await assertStatus(provider, 'encrypted', true)
      const text = await readFile(storePath(home), 'utf8')
      assert.ok(!text.includes('sk-super-secret-42'), 'ciphertext must not contain the plaintext')
      assert.ok(text.includes('"dsh-encrypt-credentials"'))
      assert.ok(text.includes('"sha3"'))
      // still resolvable while unlocked
      assert.equal((await provider.resolve(credentialRef('KEY_A')))?.value, 'sk-super-secret-42')
      // new writes encrypt too
      await provider.set(credentialRef('KEY_B'), 'another-secret')
      assert.ok(!(await readFile(storePath(home), 'utf8')).includes('another-secret'))
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('restart after setPassword boots LOCKED: resolve throws VAULT_LOCKED, writes refused, describe reports locked', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const first = await bootProvider(home)
      await first.provider.set(credentialRef('KEY'), 'secret')
      await first.provider.setPassword(PASSWORD_DIGEST)
      first.fiber.dispose()
      const second = await bootProvider(home)
      await assertStatus(second.provider, 'encrypted', false)
      await assert.rejects(second.provider.resolve(credentialRef('KEY')), { code: 'VAULT_LOCKED' })
      await assert.rejects(second.provider.set(credentialRef('KEY'), 'new'), { code: 'VAULT_LOCKED' })
      // Existence is not a secret (entry names are stored in the clear), and
      // reporting it keeps boot-time consumers such as the desktop welcome gate
      // from treating a locked vault as unconfigured. The value stays unreadable.
      assert.deepEqual(await second.provider.describe(credentialRef('KEY')), {
        configured: true,
        source: 'locked',
        writable: false,
      })
      assert.deepEqual(await second.provider.describe(credentialRef('MISSING')), {
        configured: false,
        source: 'locked',
        writable: false,
      })
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('keeps ciphertext-only mode after the encrypted file is removed', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const { provider } = await bootProvider(home)
      await provider.set(credentialRef('KEY'), 'secret')
      await provider.setPassword(PASSWORD_DIGEST)
      await rm(storePath(home))
      await assert.rejects(provider.set(credentialRef('NEW_KEY'), 'must-not-be-plain'), { code: 'VAULT_INVALID' })
      const status = await provider.status()
      assert.equal(status.format, 'plain')
      assert.equal(status.plaintextForbidden, true)
      await assert.rejects(readFile(storePath(home), 'utf8'), { code: 'ENOENT' })
      await provider.setPassword(passwordDigest('replacement password'))
      const replacement = await readFile(storePath(home), 'utf8')
      assert.ok(!replacement.includes('must-not-be-plain'))
      assert.equal((await provider.status()).format, 'encrypted')
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('unlock: wrong password → PASSWORD_WRONG, right password → credentials decrypt', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const first = await bootProvider(home)
      await first.provider.set(credentialRef('KEY'), 'unlock-me')
      await first.provider.setPassword(PASSWORD_DIGEST)
      first.fiber.dispose()
      const second = await bootProvider(home)
      await assert.rejects(second.provider.unlock(passwordDigest('wrong password')), { code: 'PASSWORD_WRONG' })
      assert.equal((await second.provider.status()).unlocked, false)
      const result = await second.provider.unlock(PASSWORD_DIGEST)
      assert.equal(result.unlocked, true)
      assert.equal((await second.provider.resolve(credentialRef('KEY')))?.value, 'unlock-me')
      await assertStatus(second.provider, 'encrypted', true)
      // idempotent
      assert.equal((await second.provider.unlock(PASSWORD_DIGEST)).unlocked, true)
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('serializes concurrent password checks before applying the lockout policy', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const first = await bootProvider(home)
      await first.provider.set(credentialRef('KEY'), 'secret')
      await first.provider.setPassword(PASSWORD_DIGEST)
      first.fiber.dispose()
      const second = await bootProvider(home, {
        maxUnlockAttempts: 2,
        lockoutBaseMs: 1000,
        lockoutMaxMs: 1000,
      })
      const wrong = passwordDigest('wrong password')
      const attempts = await Promise.allSettled([
        second.provider.unlock(wrong),
        second.provider.unlock(wrong),
        second.provider.unlock(wrong),
      ])
      const codes = attempts.map(result =>
        result.status === 'rejected' ? (result.reason as { code?: string }).code : 'UNEXPECTED_SUCCESS',
      )
      assert.deepEqual(codes, ['PASSWORD_WRONG', 'PASSWORD_WRONG', 'TOO_MANY_ATTEMPTS'])
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('changePassword re-encrypts: the new password unlocks after restart, the old one does not', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const { provider, fiber } = await bootProvider(home)
      await provider.set(credentialRef('KEY'), 'rotate-me')
      await provider.setPassword(PASSWORD_DIGEST)
      const NEW = 'new password nine chars'
      const NEW_DIGEST = passwordDigest(NEW)
      await provider.changePassword(PASSWORD_DIGEST, NEW_DIGEST)
      fiber.dispose()
      const second = await bootProvider(home)
      await assert.rejects(second.provider.unlock(PASSWORD_DIGEST), { code: 'PASSWORD_WRONG' })
      await second.provider.unlock(NEW_DIGEST)
      assert.equal((await second.provider.resolve(credentialRef('KEY')))?.value, 'rotate-me')
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('password transitions on the wrong form fail with the stable codes', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const { provider } = await bootProvider(home)
      await assert.rejects(provider.unlock(PASSWORD_DIGEST), { code: 'VAULT_NOT_ENCRYPTED' })
      await assert.rejects(provider.changePassword(PASSWORD_DIGEST, passwordDigest('other password')), {
        code: 'VAULT_NOT_ENCRYPTED',
      })
      await provider.setPassword(PASSWORD_DIGEST)
      await assert.rejects(provider.setPassword(passwordDigest('other password')), { code: 'VAULT_ALREADY_ENCRYPTED' })
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('boot auto-unlocks with DSH_CREDENTIAL_PASSWORD and fails loud on a wrong one', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    const old = process.env.DSH_CREDENTIAL_PASSWORD
    try {
      const first = await bootProvider(home)
      await first.provider.set(credentialRef('KEY'), 'env-unlock')
      await first.provider.setPassword(PASSWORD_DIGEST)
      first.fiber.dispose()
      process.env.DSH_CREDENTIAL_PASSWORD = PASSWORD
      const second = await bootProvider(home)
      await assertStatus(second.provider, 'encrypted', true)
      assert.equal((await second.provider.resolve(credentialRef('KEY')))?.value, 'env-unlock')
      second.fiber.dispose()
      process.env.DSH_CREDENTIAL_PASSWORD = 'definitely wrong'
      const ctx = new Context()
      const fiber = ctx.plugin(EncryptedCredentialProvider, { dshHome: home, watch: false })
      await assert.rejects(
        async () => {
          await fiber
        },
        { code: 'PASSWORD_WRONG' },
      )
    } finally {
      if (old === undefined) delete process.env.DSH_CREDENTIAL_PASSWORD
      else process.env.DSH_CREDENTIAL_PASSWORD = old
      await rm(home, { recursive: true, force: true })
    }
  })
  it('a corrupted encrypted file fails activation (never treated as empty)', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const { provider, fiber } = await bootProvider(home)
      await provider.set(credentialRef('KEY'), 'value')
      await provider.setPassword(PASSWORD_DIGEST)
      fiber.dispose()
      const path = storePath(home)
      const doc = JSON.parse(await readFile(path, 'utf8'))
      doc.entries.KEY.data = `${doc.entries.KEY.data.slice(0, -1)}${doc.entries.KEY.data.endsWith('A') ? 'B' : 'A'}`
      await writeFile(path, `${JSON.stringify(doc, null, 2)}\n`)
      const ctx = new Context()
      const failing = ctx.plugin(EncryptedCredentialProvider, { dshHome: home, watch: false })
      await assert.rejects(
        async () => {
          await failing
        },
        { code: 'VAULT_CORRUPTED' },
      )
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('external plain edits hot-publish; external encryption locks the provider', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      const { provider, fiber } = await bootProvider(home, { watch: true, debounceMs: 50 })
      await provider.set(credentialRef('KEY'), 'old-value')
      // external plain edit
      await writeFile(storePath(home), 'KEY: new-value\n')
      const deadline = Date.now() + 5000
      while (Date.now() < deadline) {
        try {
          if ((await provider.resolve(credentialRef('KEY')))?.value === 'new-value') break
        } catch {}
        await new Promise(resolve => setTimeout(resolve, 50))
      }
      assert.equal((await provider.resolve(credentialRef('KEY')))?.value, 'new-value')
      // external encryption (via a helper provider) locks this one
      const helper = await bootProvider(home)
      await helper.provider.setPassword(PASSWORD_DIGEST)
      helper.fiber.dispose()
      const deadline2 = Date.now() + 5000
      while (Date.now() < deadline2 && (await provider.status()).format !== 'encrypted') {
        await new Promise(resolve => setTimeout(resolve, 50))
      }
      await assertStatus(provider, 'encrypted', false)
      await assert.rejects(provider.resolve(credentialRef('KEY')), { code: 'VAULT_LOCKED' })
      fiber.dispose()
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
  it('rejects an empty stored value and environment-shadowed writes', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    const old = process.env.SHADOWED_KEY
    try {
      const { provider } = await bootProvider(home)
      await assert.rejects(provider.set(credentialRef('EMPTY'), ''), /empty value/)
      process.env.SHADOWED_KEY = 'from-env'
      await assert.rejects(
        provider.set(credentialRef('SHADOWED_KEY'), 'value'),
        /read-only by the launching environment/,
      )
      const hit = await provider.resolve(credentialRef('SHADOWED_KEY'))
      assert.ok(hit)
      assert.equal(hit.value, 'from-env')
      assert.equal(hit.source, 'env')
    } finally {
      if (old === undefined) delete process.env.SHADOWED_KEY
      else process.env.SHADOWED_KEY = old
      await rm(home, { recursive: true, force: true })
    }
  })
  it('plain form rejects structurally invalid YAML at startup', async () => {
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-'))
    try {
      await writeFile(storePath(home), '9BAD: value\n')
      const ctx = new Context()
      const fiber = ctx.plugin(EncryptedCredentialProvider, { dshHome: home, watch: false })
      await assert.rejects(async () => {
        await fiber
      })
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
})
