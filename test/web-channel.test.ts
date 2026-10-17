import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import {
  apply,
  REMEMBER_CHANNEL_HEADER,
  REMEMBER_COOKIE,
  REMEMBER_TICKET_HEADER,
  requestUsesHeaderChannel,
} from '../lib/web.js'

const TICKET = 'ticket-from-the-browser'
const DIGEST = 'a'.repeat(64)

type Handler = (req: FakeRequest, res: FakeResponse) => unknown

interface FakeRequest {
  method: string
  headers: Record<string, string>
  socket: { remoteAddress: string }
  [Symbol.asyncIterator]: () => AsyncGenerator<string>
}

interface FakeResponse {
  headersSent: boolean
  setHeader: (name: string, value: string) => unknown
  removeHeader: (name: string) => unknown
  getHeader: (name: string) => string | undefined
  writeHead: (status: number, headers?: Record<string, string>) => unknown
  write: (chunk: string) => boolean
  end: (chunk?: string) => unknown
}

interface Captured {
  status: number
  headers: Record<string, string>
  body: string
}

interface FakeContext {
  webServer: {
    host: string
    exact: Map<string, unknown>
    prefixes: Map<string, unknown>
    register: (route: { kind: string; path: string; handler: Handler }) => unknown
  }
  credentials: {
    leakGuard: { enabled: boolean }
    format: string
    config: { rememberChannel: 'cookie' | 'header' }
    status: () => Promise<Record<string, unknown>>
    unlock: (digest: string) => Promise<Record<string, unknown>>
    unlockWithRemember: (ticket: string) => Promise<Record<string, unknown>>
    setPassword: (digest: string) => Promise<Record<string, unknown>>
    changePassword: (oldDigest: string, digest: string) => Promise<Record<string, unknown>>
    issueRemember: () => Promise<{ secret: string; days: number; issuedAt: number; expiresAt: number | null }>
    setRememberDays: (
      days: unknown,
    ) => Promise<{ secret: string; days: number; issuedAt: number; expiresAt: number | null } | null>
  }
  logger: Record<string, unknown>
  effect: (factory: () => unknown, description: string) => unknown
}

function makeContext(options: { channel?: 'cookie' | 'header'; unlocked?: boolean; issueOnSet?: boolean } = {}): {
  ctx: FakeContext
  routes: Map<string, Handler>
  rememberCalls: string[]
} {
  const routes = new Map<string, Handler>()
  const rememberCalls: string[] = []
  const issue = { secret: 'issued-ticket', days: 7, issuedAt: 1, expiresAt: 2 }
  const ctx: FakeContext = {
    webServer: {
      host: '127.0.0.1',
      exact: new Map(),
      prefixes: new Map(),
      register(route) {
        routes.set(route.path, route.handler)
      },
    },
    credentials: {
      leakGuard: { enabled: false },
      format: 'encrypted',
      config: { rememberChannel: options.channel ?? 'cookie' },
      status: async () => ({
        format: 'encrypted',
        unlocked: options.unlocked ?? false,
        remember: { days: 7, active: true, issuedAt: 1, expiresAt: null },
        lockout: { failures: 0, lockedUntil: 0, retryAfterMs: 0, locked: false },
        leakGuard: { enabled: true, masks: 0 },
        rememberChannel: options.channel ?? 'cookie',
      }),
      unlock: async () => ({ unlocked: true }),
      unlockWithRemember: async ticket => {
        rememberCalls.push(ticket)
        return { unlocked: true }
      },
      setPassword: async () => ({ unlocked: true }),
      changePassword: async () => ({ unlocked: true }),
      issueRemember: async () => issue,
      setRememberDays: async () => (options.issueOnSet === false ? null : issue),
    },
    logger: {},
    effect: factory => factory(),
  }
  apply(ctx as unknown as Parameters<typeof apply>[0], {})
  return { ctx, routes, rememberCalls }
}

function request(headers: Record<string, string>, body: Record<string, unknown> = {}): FakeRequest {
  return {
    method: 'POST',
    headers: { host: '127.0.0.1:1234', 'content-type': 'application/json', ...headers },
    socket: { remoteAddress: '127.0.0.1' },
    async *[Symbol.asyncIterator]() {
      yield JSON.stringify(body)
    },
  }
}

function response(): { res: FakeResponse; captured: Captured } {
  const captured: Captured = { status: 0, headers: {}, body: '' }
  const res: FakeResponse = {
    headersSent: false,
    setHeader(name, value) {
      captured.headers[name.toLowerCase()] = value
      return res
    },
    removeHeader(name) {
      delete captured.headers[name.toLowerCase()]
      return res
    },
    getHeader(name) {
      return captured.headers[name.toLowerCase()]
    },
    writeHead(status, headers) {
      captured.status = status
      for (const [name, value] of Object.entries(headers ?? {})) captured.headers[name.toLowerCase()] = value
      res.headersSent = true
      return res
    },
    write(chunk) {
      captured.body += chunk
      return true
    },
    end(chunk) {
      if (chunk !== undefined) captured.body += chunk
      res.headersSent = true
      return res
    },
  }
  return { res, captured }
}

async function call(
  routes: Map<string, Handler>,
  path: string,
  req: FakeRequest,
): Promise<{ captured: Captured; value: Record<string, unknown> }> {
  const handler = routes.get(path)
  assert.ok(handler !== undefined, `route ${path} is not registered`)
  const { res, captured } = response()
  await handler(req, res)
  assert.equal(captured.status, 200)
  const parsed = JSON.parse(captured.body) as { ok: boolean; value: Record<string, unknown> }
  assert.equal(parsed.ok, true)
  return { captured, value: parsed.value }
}

describe('remembered-login channel negotiation', () => {
  it('selects the header channel from config or from an explicit same-origin hint', () => {
    assert.equal(requestUsesHeaderChannel({}, undefined), false)
    assert.equal(requestUsesHeaderChannel({}, 'cookie'), false)
    assert.equal(requestUsesHeaderChannel({}, 'header'), true)
    assert.equal(requestUsesHeaderChannel({ headers: { [REMEMBER_CHANNEL_HEADER]: 'header' } }, 'cookie'), true)
    assert.equal(requestUsesHeaderChannel({ headers: { [REMEMBER_CHANNEL_HEADER]: '  HEADER  ' } }, 'cookie'), true)
    assert.equal(requestUsesHeaderChannel({ headers: { [REMEMBER_CHANNEL_HEADER]: 'cookie' } }, 'cookie'), false)
    assert.equal(requestUsesHeaderChannel({ headers: { [REMEMBER_CHANNEL_HEADER]: ['header'] } }, 'cookie'), false)
  })

  it('consumes a header ticket only when the request opts into the header channel', async () => {
    const { routes, rememberCalls } = makeContext()
    const plain = await call(routes, '/api/credentials.status', request({ [REMEMBER_TICKET_HEADER]: TICKET }))
    assert.deepEqual(rememberCalls, [])
    assert.equal(plain.value.rememberChannel, 'cookie')

    const hinted = await call(
      routes,
      '/api/credentials.status',
      request({ [REMEMBER_CHANNEL_HEADER]: 'header', [REMEMBER_TICKET_HEADER]: TICKET }),
    )
    assert.deepEqual(rememberCalls, [TICKET])
    assert.equal(hinted.value.rememberChannel, 'header')
    assert.equal(hinted.value.ticketRejected, false)
  })

  it('still consumes the HttpOnly cookie ticket on the default channel', async () => {
    const { routes, rememberCalls } = makeContext()
    const result = await call(routes, '/api/credentials.status', request({ cookie: `${REMEMBER_COOKIE}=${TICKET}` }))
    assert.deepEqual(rememberCalls, [TICKET])
    assert.equal(result.value.rememberChannel, 'cookie')
  })

  it('returns the issued ticket in the body only on the header channel', async () => {
    const { routes } = makeContext()
    const cookie = await call(routes, '/api/credentials.unlock', request({}, { digest: DIGEST }))
    assert.equal(cookie.value.rememberChannel, 'cookie')
    assert.equal('ticket' in cookie.value, false)
    assert.match(String(cookie.captured.headers['set-cookie']), new RegExp(`^${REMEMBER_COOKIE}=issued-ticket`))

    const header = await call(
      routes,
      '/api/credentials.unlock',
      request({ [REMEMBER_CHANNEL_HEADER]: 'header' }, { digest: DIGEST }),
    )
    assert.equal(header.value.rememberChannel, 'header')
    assert.equal(header.value.ticket, 'issued-ticket')
  })

  it('returns a newly issued ticket from the config route on the header channel', async () => {
    const { routes } = makeContext({ unlocked: true })
    const result = await call(
      routes,
      '/api/credentials.config',
      request({ [REMEMBER_CHANNEL_HEADER]: 'header' }, { action: 'set', rememberDays: 7 }),
    )
    assert.equal(result.value.rememberChannel, 'header')
    assert.equal(result.value.ticket, 'issued-ticket')
  })

  it('reports a config set that could not issue a ticket as not remembered', async () => {
    const { routes } = makeContext({ issueOnSet: false })
    const result = await call(
      routes,
      '/api/credentials.config',
      request({ [REMEMBER_CHANNEL_HEADER]: 'header' }, { action: 'set', rememberDays: 7 }),
    )
    assert.equal(result.value.remembered, false)
    assert.equal('ticket' in result.value, false)
  })

  it('honors the configured header channel without a per-request hint', async () => {
    const { routes, rememberCalls } = makeContext({ channel: 'header' })
    const status = await call(routes, '/api/credentials.status', request({ [REMEMBER_TICKET_HEADER]: TICKET }))
    assert.deepEqual(rememberCalls, [TICKET])
    assert.equal(status.value.rememberChannel, 'header')

    const unlock = await call(routes, '/api/credentials.unlock', request({}, { digest: DIGEST }))
    assert.equal(unlock.value.ticket, 'issued-ticket')
  })
})
