import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'vitest'
import { assertOwnerOnly } from '../lib/index.js'
import { LeakGuard, REDACTION_MARKER, WsFrameFilter, buildServerFrame, readServerFrame } from '../lib/leak-guard.js'
import { isLoopbackSocket } from '../lib/trust.js'
import {
  createRememberBlock,
  encryptCredentialStore,
  recoverKeyFromRemember,
  rememberActive,
  serializeEncryptedStore,
  sha3_256Hex,
  zeroizeBuffer,
} from '../lib/vault.js'
import { armSocketRedaction, redactingHttpHandler } from '../lib/web.js'

type HeaderValue = string | number | string[]
type Headers = Record<string, HeaderValue>

interface CapturingResponse {
  write: (chunk: string | Buffer | Uint8Array) => boolean
  end: (chunk?: string | Buffer | Uint8Array) => unknown
  writeHead: (code: number, statusMessageOrHeaders?: string | Headers, supplied?: Headers) => unknown
  setHeader: (name: string, value: HeaderValue) => unknown
  getHeader: (name: string) => HeaderValue | undefined
  removeHeader: (name: string) => void
  headersSent: boolean
}

function emptyRequest() {
  return {
    headers: {} as Record<string, string>,
    async *[Symbol.asyncIterator](): AsyncGenerator<Buffer> {
      return yield* []
    },
  }
}

function capturingResponse(options: { compressOnWriteHead?: boolean } = {}) {
  let body = ''
  let status = 0
  let headers: Headers = {}
  let sent = false
  const pending = new Map<string, HeaderValue>()
  const response: CapturingResponse = {
    headersSent: false,
    write(chunk: string | Buffer | Uint8Array): boolean {
      body += Buffer.isBuffer(chunk) || chunk instanceof Uint8Array ? Buffer.from(chunk).toString('utf8') : chunk
      return true
    },
    end(chunk: string | Buffer | Uint8Array = ''): void {
      body += Buffer.isBuffer(chunk) || chunk instanceof Uint8Array ? Buffer.from(chunk).toString('utf8') : chunk
    },
    writeHead(code: number, statusMessageOrHeaders?: string | Headers, supplied?: Headers): void {
      status = code
      headers = {
        ...Object.fromEntries(pending),
        ...(typeof statusMessageOrHeaders === 'string' ? supplied : statusMessageOrHeaders),
      }
      sent = true
      response.headersSent = true
      if (options.compressOnWriteHead === true) {
        // Mimic the host gzip middleware: it engages underneath the wrapper
        // while the real writeHead runs and records its encoding on the response.
        pending.set('content-encoding', 'gzip')
        headers = { ...headers, 'content-encoding': 'gzip' }
      }
    },
    setHeader(name: string, value: HeaderValue): void {
      if (sent) throw new Error('ERR_HTTP_HEADERS_SENT')
      pending.set(name.toLowerCase(), value)
    },
    getHeader(name: string): HeaderValue | undefined {
      return pending.get(name.toLowerCase())
    },
    removeHeader(name: string): void {
      if (sent) throw new Error('ERR_HTTP_HEADERS_SENT')
      pending.delete(name.toLowerCase())
    },
  }
  return {
    response,
    result: () => ({ body, headers, status }),
  }
}

function documentFingerprint(document: Record<string, unknown>): string {
  const fields = [
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
  const target: Record<string, unknown> = {}
  for (const field of fields) {
    if (document[field] !== void 0) target[field] = document[field]
  }
  return createHash('sha3-256').update(JSON.stringify(target), 'utf8').digest('hex')
}

describe('security regression coverage', () => {
  it('redacts a credential first registered while the HTTP handler is running', async () => {
    const guard = new LeakGuard()
    const secret = 'first-response-secret'
    const captured = capturingResponse()
    const wrapped = redactingHttpHandler(async (_req, res) => {
      guard.add(secret, 'FIRST')
      res.writeHead(200, {
        'content-type': 'application/json',
        'content-length': String(secret.length),
        etag: 'stale-after-redaction',
      })
      res.end(secret)
    }, guard)
    await wrapped(emptyRequest(), captured.response)
    const result = captured.result()
    assert.equal(result.body, REDACTION_MARKER)
    assert.equal(result.status, 200)
    assert.equal(
      Object.keys(result.headers).some(name => name.toLowerCase() === 'content-length'),
      false,
    )
    assert.equal(
      Object.keys(result.headers).some(name => name.toLowerCase() === 'etag'),
      false,
    )
  })

  it('redacts one text message split across WebSocket continuation frames', () => {
    const guard = new LeakGuard({ minMaskLength: 4 })
    const filter = new WsFrameFilter(text => guard.mask(text))
    const first = buildServerFrame(1, 'fragment-')
    first[0] = (first[0] ?? 0) & 0x7f
    const second = buildServerFrame(0, 'secret')
    guard.add('fragment-secret', 'WS')
    const output = filter.push(Buffer.concat([first, second]))
    assert.equal(output.length, 1)
    const frame = readServerFrame(output[0] as Buffer)
    assert.ok(frame !== null && !frame.passthrough)
    assert.equal(
      frame.raw.subarray(frame.headerLen, frame.headerLen + frame.payloadLen).toString('utf8'),
      REDACTION_MARKER,
    )
  })

  it('blocks encoded HTTP output without throwing into the host server', async () => {
    const guard = new LeakGuard()
    const secret = 'encoded-secret-value'
    guard.add(secret, 'ENCODED')
    const captured = capturingResponse()
    const wrapped = redactingHttpHandler(async (_req, res) => {
      res.writeHead(200, {
        'content-type': 'text/plain',
        'content-encoding': 'gzip',
      })
      res.end(Buffer.from(secret))
    }, guard)
    await wrapped(emptyRequest(), captured.response)
    const result = captured.result()
    assert.equal(result.status, 500)
    assert.equal(result.body.includes(secret), false)
    assert.equal(result.body.includes('encoded response blocked'), true)
  })

  it('keeps redacting when the carrier negotiates compression beneath the wrapper', async () => {
    const guard = new LeakGuard()
    const secret = 'compressed-carrier-secret'
    guard.add(secret, 'CARRIER')
    const captured = capturingResponse({ compressOnWriteHead: true })
    const wrapped = redactingHttpHandler(async (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(secret)
    }, guard)
    await wrapped(emptyRequest(), captured.response)
    const result = captured.result()
    assert.equal(result.status, 200)
    assert.equal(result.body, REDACTION_MARKER)
    assert.equal(result.headers['content-encoding'], 'gzip')
  })

  it('closes an oversized WebSocket upgrade response instead of disabling filtering', () => {
    const guard = new LeakGuard()
    let destroyed: Error | undefined
    const socket = {
      write(_chunk?: string | Buffer | Uint8Array): boolean {
        return true
      },
      destroy(error?: Error): void {
        destroyed = error
      },
    }
    armSocketRedaction(socket, guard)
    assert.equal(socket.write(Buffer.alloc(16 * 1024 + 1, 65)), false)
    assert.equal((destroyed?.message ?? '').includes('exceed 16 KiB'), true)
  })

  it('authenticates remembered-login expiry metadata and rejects future issue times', async () => {
    const store = await encryptCredentialStore(new Map(), 'a'.repeat(64))
    try {
      const remembered = createRememberBlock(store.key, 1, 0)
      assert.equal(rememberActive(remembered.block, 0), true)
      assert.equal(rememberActive({ ...remembered.block, issuedAt: 1 }, 0), false)
      const text = serializeEncryptedStore(store.entries, store.key, store.salt, store.params, remembered.block)
      assert.throws(() => recoverKeyFromRemember(text, remembered.secret), { code: 'REMEMBER_EXPIRED' })
      const document = JSON.parse(text) as Record<string, unknown> & {
        remember: { issuedAt: number }
        sha3: string
      }
      document.remember.issuedAt = Date.now()
      document.sha3 = documentFingerprint(document)
      assert.throws(() => recoverKeyFromRemember(`${JSON.stringify(document)}\n`, remembered.secret), {
        code: 'REMEMBER_INVALID',
      })
    } finally {
      zeroizeBuffer(store.key)
    }
  })

  it('rejects a credential file reached through a symbolic link', async () => {
    if (process.platform === 'win32') return
    const home = await mkdtemp(join(tmpdir(), 'dsh-enc-link-'))
    try {
      const target = join(home, 'target')
      const link = join(home, 'credentials')
      await writeFile(target, 'KEY: value\n')
      await chmod(target, 0o600)
      await symlink(target, link)
      await assert.rejects(
        assertOwnerOnly(link),
        error => error instanceof Error && error.message.includes('symbolic link'),
      )
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })

  it('does not treat a forwarded request as a local socket request', () => {
    assert.equal(
      isLoopbackSocket({
        headers: { 'x-forwarded-for': '203.0.113.10' },
        socket: { remoteAddress: '127.0.0.1' },
      }),
      false,
    )
  })

  it('retains the public SHA3 helper behavior used by browser password derivation', () => {
    assert.equal(sha3_256Hex('abc'), '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532')
  })
})
