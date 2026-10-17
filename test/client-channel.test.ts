import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import { apiPost, browserUsesHeaderChannel } from '../src/client/api.js'

const TICKET_KEY = 'dsh-encrypt-remember'

type GlobalName = 'location' | 'localStorage' | 'fetch'

interface FetchCall {
  url: string
  headers: Record<string, string>
}

function withLocation(protocol: string, run: () => void): void {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'location')
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { protocol } })
  try {
    run()
  } finally {
    restore('location', original)
  }
}

function restore(name: GlobalName, descriptor: PropertyDescriptor | undefined): void {
  if (descriptor === undefined) Reflect.deleteProperty(globalThis, name)
  else Object.defineProperty(globalThis, name, descriptor)
}

async function captureStatusPost(protocol: string, ticket: string | null): Promise<FetchCall> {
  const calls: FetchCall[] = []
  const previous = {
    location: Object.getOwnPropertyDescriptor(globalThis, 'location'),
    localStorage: Object.getOwnPropertyDescriptor(globalThis, 'localStorage'),
    fetch: Object.getOwnPropertyDescriptor(globalThis, 'fetch'),
  }
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { protocol } })
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => (key === TICKET_KEY ? ticket : null),
      setItem: () => {},
      removeItem: () => {},
    },
  })
  Object.defineProperty(globalThis, 'fetch', {
    configurable: true,
    value: async (url: string, init: { headers: Record<string, string> }) => {
      calls.push({ url, headers: init.headers })
      return { json: async () => ({ ok: true, value: {} }) }
    },
  })
  try {
    await apiPost('/api/credentials.status')
  } finally {
    restore('location', previous.location)
    restore('localStorage', previous.localStorage)
    restore('fetch', previous.fetch)
  }
  const call = calls[0]
  assert.ok(call !== undefined)
  return call
}

describe('client remembered-login channel detection', () => {
  it('keeps HttpOnly cookie semantics on ordinary http(s) pages', () => {
    withLocation('http:', () => assert.equal(browserUsesHeaderChannel(), false))
    withLocation('https:', () => assert.equal(browserUsesHeaderChannel(), false))
  })

  it('switches to the header channel on the desktop custom scheme', () => {
    withLocation('dsh-app:', () => assert.equal(browserUsesHeaderChannel(), true))
  })

  it('falls back to the cookie channel without a page location', () => {
    assert.equal(browserUsesHeaderChannel(), false)
  })

  it('asks for the header channel and sends the stored ticket on a desktop page', async () => {
    const call = await captureStatusPost('dsh-app:', 'ticket-value')
    assert.equal(call.url, '/api/credentials.status')
    assert.equal(call.headers['x-dsh-encrypt-remember-channel'], 'header')
    assert.equal(call.headers['x-dsh-encrypt-remember'], 'ticket-value')
  })

  it('keeps the cookie channel on ordinary http pages', async () => {
    const call = await captureStatusPost('http:', 'ticket-value')
    assert.equal('x-dsh-encrypt-remember-channel' in call.headers, false)
    assert.equal(call.headers['x-dsh-encrypt-remember'], 'ticket-value')
  })
})
