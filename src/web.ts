import type { LeakGuard } from './leak-guard.js'
import type {
  HttpHandler,
  HttpRequestLike as RequestLike,
  HttpResponseLike as ResponseLike,
  HttpRoute,
  UpgradeRoute,
  UpgradeSocketLike as SocketLike,
} from './transport/http/model.js'
/**
 * Browser-facing password surface of dsh-encrypt: exact HTTP routes over the
 * webServer service, dispatching to the `credentials` provider's password
 * operations. A separate composition row (`dsh-encrypt/web`) keeps the core
 * provider free of a webServer dependency, so headless compositions load the
 * provider without this surface.
 *
 * Authentication model:
 * - The browser never sends the raw password. It derives the lowercase hex
 *   SHA3-256 digest and POSTs `{ digest }`; the provider stretches the
 *   digest with Argon2id and checks it against the AEAD verifier.
 * - Every route passes a Host-header trust fence (see ./trust.js): a
 *   request whose Host is neither loopback nor a configured trustedHosts
 *   authority is rejected with FORBIDDEN_HOST before any operation runs.
 *   Every password-bearing operation and the remembered-login window are
 *   pinned to a loopback connection (Host AND socket).
 * - Remembered logins: on a successful loopback password unlock the server
 *   issues a 256-bit ticket in an HttpOnly, SameSite=Strict cookie and
 *   persists only an AEAD-wrapped copy of the key in the store document.
 *   The ticket is never echoed in a response body unless the deployment
 *   opts into the localStorage-backed header channel
 *   (rememberChannel: "header"); non-loopback requests never use it.
 *
 * Routes (POST application/json only — the same cross-site write fence the
 * official /api uses, plus the Host trust fence above; response:
 * `{ ok, value }` or `{ ok: false, code, message }`, messages never carrying
 * the password or any key material):
 *
 *   /api/credentials.status            → state + local + remember snapshot
 *                                         (attempts ticket unlock on loopback)
 *   /api/credentials.unlock            { digest }        → loopback only
 *   /api/credentials.set-password      { digest }        → loopback Host only
 *   /api/credentials.change-password   { oldDigest, digest } → loopback only
 *   /api/credentials.config            { action, rememberDays } → get/set
 *
 * @module dsh-encrypt/web
 */
import z from '@deepseek-ai/schemastery'
import { loadAndVerifyIntegrity } from './integrity.js'
import {
  armSocketRedaction as armSocketRedactionImpl,
  installLeakRedaction as installLeakRedactionImpl,
  redactingHttpHandler as redactingHttpHandlerImpl,
  redactingUpgradeRoute as redactingUpgradeRouteImpl,
} from './security/redaction/web-redaction.js'
import { readCredentialJsonBody } from './transport/http/request-body.js'
import {
  parseChangePasswordRequest,
  parseConfigRequest,
  parseDigestRequest,
  parseEmptyRequest,
} from './transport/http/request-schemas.js'
import { assertTrustedAuthority, isLoopbackRequest, isLoopbackSocket, isTrustedRequest } from './trust.js'
import { VaultError } from './vault.js'

type JsonObject = Record<string, unknown>

interface RememberIssue {
  secret: string
  days: number
  issuedAt: number
  expiresAt: number | null
}

interface WebCredentials {
  leakGuard: LeakGuard
  format?: string
  config?: { rememberChannel?: 'cookie' | 'header' }
  status: () => Promise<JsonObject>
  unlock: (digest: string) => Promise<JsonObject>
  unlockWithRemember: (ticket: string) => Promise<unknown>
  setPassword: (digest: string) => Promise<JsonObject>
  changePassword: (oldDigest: string, digest: string) => Promise<JsonObject>
  issueRemember: () => Promise<RememberIssue | null>
  setRememberDays: (days: unknown) => Promise<RememberIssue | null>
}

interface LoggerLike {
  warn?: (...args: unknown[]) => void
}

interface WebServerLike {
  host?: string
  exact: Map<string, HttpRoute>
  prefixes: Map<string, HttpRoute>
  upgrades?: Map<string, UpgradeRoute> | undefined
  register: (route: { kind: 'exact'; path: string; handler: HttpHandler }) => unknown
}

interface WebContext {
  credentials: WebCredentials
  webServer: WebServerLike
  logger: LoggerLike
  effect: (factory: () => unknown, description: string) => unknown
}

interface CookieJar {
  value: string | undefined
  set: (header: string) => void
  clear: () => void
}

type JsonOperation = (payload: unknown, req: RequestLike, cookies: CookieJar) => unknown | Promise<unknown>
type AccessCheck = (req: RequestLike) => void

export interface WebConfig {
  trustedHosts?: string[]
}

// Re-check shipped-file consistency for web-only compositions. The adjacent
// manifest detects incomplete builds; it is not a signature or trust root.
loadAndVerifyIntegrity(import.meta.url)

export const name = 'dsh-encrypt-web'
export const inject = ['webServer', 'credentials'] as const

/** Cookie carrying the browser-held remembered-login ticket. */
export const REMEMBER_COOKIE = 'dsh-encrypt-remember'
/** Cookie max-age for a forever remembered login (100 years in seconds). */
const FOREVER_MAX_AGE = 3153600000

/**
 * Whether a request is genuinely local: its Host names the loopback interface
 * AND its socket arrived from loopback. The Host half is the DNS-rebinding
 * fence (a rebound page's socket IS loopback, so socket alone is not enough);
 * the socket half closes the inverse spoof (a non-browser LAN client forging
 * a loopback Host). Password mutations and remembered-login issuance require
 * both halves.
 */
export function isLocalRequest(req: unknown): boolean {
  return isLoopbackRequest(req) && isLoopbackSocket(req)
}

/** Read the remembered-login ticket from the request cookies, if present. */
export function readRememberCookie(req: unknown): string | undefined {
  const header = (req as Partial<RequestLike> | null)?.headers?.cookie
  if (typeof header !== 'string' || header.length === 0) return void 0
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const key = part.slice(0, eq).trim()
    if (key === REMEMBER_COOKIE) return part.slice(eq + 1).trim()
  }
  return void 0
}

/**
 * Read the remembered-login ticket from the explicit request header the
 * WebUI attaches. Only honored when the deployment opts into the
 * localStorage-backed header channel (rememberChannel: "header") — the
 * HttpOnly cookie is the default carrier.
 */
export function readRememberHeader(req: unknown): string | undefined {
  const header = (req as Partial<RequestLike> | null)?.headers?.['x-dsh-encrypt-remember']
  if (typeof header !== 'string' || header.length === 0) return void 0
  return header.trim()
}

/** Build the Set-Cookie header issuing a remembered login. */
export function rememberCookieHeader(secret: string, days: number): string {
  const maxAge = days === -1 ? FOREVER_MAX_AGE : Math.max(0, Math.floor(days * 86400))
  return `${REMEMBER_COOKIE}=${secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`
}

/** Build the Set-Cookie header clearing a remembered login. */
export function clearRememberCookieHeader(): string {
  return `${REMEMBER_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`
}

/** Build the common successful result for password operations and issue its browser ticket. */
function rememberedPasswordResult(
  value: JsonObject,
  issued: RememberIssue | null,
  cookies: CookieJar,
  channel: 'cookie' | 'header',
): JsonObject {
  if (issued !== null) cookies.set(rememberCookieHeader(issued.secret, issued.days))
  const result: JsonObject = {
    ...value,
    local: true,
    remembered: issued !== null,
    expiresAt: issued?.expiresAt ?? null,
  }
  if (channel === 'header') result.ticket = issued?.secret
  return result
}

/** Reject a non-localhost caller before a password modification runs. */
function assertLocal(req: unknown): void {
  if (!isLocalRequest(req)) {
    throw new VaultError(
      'LOCAL_ONLY',
      'password operations and remembered-login settings are only allowed from localhost',
    )
  }
}

// ── leak-guard output redaction (prompt-injection / exfiltration defense) ──
//
// While the vault is unlocked, the credentials provider registers the
// plaintext of every credential it resolves in its LeakGuard. This row wraps
// the web server's route tables so every response body — the /api fetch RPC
// surface (session history, tool results, model text) and the WebSocket
// event downlinks (streaming deltas) — passes through the guard before it
// reaches the browser: a credential value a compromised prompt tricked the
// model into echoing is replaced with a redaction marker before it leaves
// the host.
//
// Honest limits: only resolved values are masked; binary WebSocket frames and
// the static fallback are not scanned; and the marker substitution cannot
// stop a model that exfiltrates a secret through a tool call (web_search,
// bash, …). This layer closes the echo/leak-in-output surface, not the
// tool-use surface.

/**
 * Wrap one HTTP route handler so everything it writes is redacted through
 * the guard. No-op (bare passthrough) when the guard is disabled or holds no
 * secrets, so locked vaults pay nothing.
 * @param {(req: unknown, res: unknown) => unknown} handler - the route handler.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 * @returns the wrapped handler.
 */
export function redactingHttpHandler(handler: HttpHandler, guard: LeakGuard): HttpHandler {
  return redactingHttpHandlerImpl(handler, guard)
}

/**
 * Patch a raw upgrade socket so that, once the 101 handshake response has
 * been written, every outgoing WebSocket frame passes through the guard
 * (text frames only; the downlink server sends unmasked, uncompressed
 * frames, see {@link WsFrameFilter}). The handshake response itself is
 * buffered only until its header terminator arrives, then forwarded intact.
 * @param {import("node:net").Socket} socket - the raw socket.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 */
export function armSocketRedaction(socket: SocketLike, guard: LeakGuard): void {
  armSocketRedactionImpl(socket, guard)
}

/**
 * Wrap one upgrade route handler so its socket frames are redacted after the
 * handshake completes.
 * @param {object} route - the registered upgrade route.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 * @returns the wrapped route.
 */
export function redactingUpgradeRoute(route: UpgradeRoute, guard: LeakGuard): UpgradeRoute {
  return redactingUpgradeRouteImpl(route, guard)
}

/**
 * Install response redaction over the web server's route tables: existing
 * routes are wrapped in place and future registrations are wrapped on insert
 * (the Proxy set trap), covering the /api prefix owned by client-connection
 * and any route registered later. Returns a disposer restoring the original
 * tables.
 * @param {unknown} ctx - the row context.
 * @returns {() => void} the disposer.
 */
export function installLeakRedaction(ctx: WebContext): () => void {
  return installLeakRedactionImpl(ctx)
}

/** Wrap one password operation into a JSON HTTP handler with the write fence. */
function jsonHandler(operation: JsonOperation, logger?: LoggerLike, accessCheck?: AccessCheck): HttpHandler {
  return async (req: RequestLike, res: ResponseLike) => {
    /** Cookie to attach to the response; the last assignment wins. */
    const cookies: CookieJar = {
      value: void 0,
      set(header: string) {
        cookies.value = header
      },
      clear() {
        cookies.value = clearRememberCookieHeader()
      },
    }
    const write = (status: number, body: unknown, extraHeaders: Record<string, string> = {}): unknown => {
      const headers: Record<string, string> = { 'content-type': 'application/json', ...extraHeaders }
      if (cookies.value !== void 0) {
        headers['set-cookie'] = cookies.value
        if (typeof res.setHeader === 'function') res.setHeader('Set-Cookie', cookies.value)
      }
      res.writeHead(status, headers)
      return res.end(JSON.stringify(body))
    }
    const fail = (error: unknown): unknown => {
      const cause = error as { code?: unknown; retryAfterMs?: unknown } | null
      const code = typeof cause?.code === 'string' ? cause.code : 'internal'
      const message = error instanceof VaultError ? error.message : 'internal server error'
      if (!(error instanceof VaultError)) {
        logger?.warn?.(
          'dsh-encrypt: credentials route failed: %s',
          error instanceof Error ? (error.stack ?? error.message) : String(error),
        )
      }
      if (code === 'TOO_MANY_ATTEMPTS') {
        const retryAfterSeconds = Math.max(
          1,
          Math.ceil((typeof cause?.retryAfterMs === 'number' ? cause.retryAfterMs : 0) / 1000),
        )
        return write(
          429,
          { ok: false, code, message, retryAfterMs: retryAfterSeconds * 1000 },
          { 'retry-after': String(retryAfterSeconds) },
        )
      }
      if (code === 'FORBIDDEN_HOST' || code === 'LOCAL_ONLY') return write(403, { ok: false, code, message })
      if (code === 'PAYLOAD_TOO_LARGE') return write(413, { ok: false, code, message })
      if (code === 'REQUEST_TIMEOUT') return write(408, { ok: false, code, message })
      if (code === 'internal') return write(500, { ok: false, code, message })
      return write(400, { ok: false, code, message })
    }
    if (req.method !== 'POST') return write(405, { ok: false, code: 'method-not-allowed', message: 'POST required' })
    try {
      accessCheck?.(req)
    } catch (error) {
      return fail(error)
    }
    const mediaType = (String(req.headers['content-type'] ?? '').split(';', 1)[0] ?? '').trim().toLowerCase()
    if (mediaType !== 'application/json')
      return write(415, { ok: false, code: 'unsupported-media', message: 'content type must be application/json' })
    let payload: unknown
    try {
      payload = await readCredentialJsonBody(req)
    } catch (error) {
      return fail(error)
    }
    try {
      const value = await operation(payload, req, cookies)
      return write(200, { ok: true, value: value === void 0 ? {} : value })
    } catch (error) {
      return fail(error)
    }
  }
}

/**
 * Web-row configuration: `trustedHosts` lists non-loopback authorities
 * (host or host:port) accepted by the trust fence.
 */
export const Config: ReturnType<typeof z.object> = z.object({
  trustedHosts: z.array(String).default([]),
})

export function apply(ctx: WebContext, config: WebConfig = {}): void {
  const trustedHosts = config?.trustedHosts ?? []
  for (const entry of trustedHosts) assertTrustedAuthority(entry)
  if (ctx.webServer?.host === '0.0.0.0') {
    ctx.logger.warn?.(
      'dsh-encrypt: the web server is bound to all interfaces; password operations remain local-only, and remote status access still requires an explicit trustedHosts entry',
    )
  }
  if (ctx.webServer?.host === '0.0.0.0' && ctx.credentials?.format === 'plain') {
    ctx.logger.warn?.(
      'dsh-encrypt: the web server is bound to all interfaces while credentials are still PLAINTEXT; set a password before exposing the server to the network',
    )
  }
  // Wire the credential leak guard over every HTTP response and WebSocket
  // downlink frame the web server writes. Install FIRST so the routes below
  // (and anything registered later) pass through the redaction proxy too.
  ctx.effect(() => installLeakRedaction(ctx), 'dsh-encrypt: leak-guard output redaction')
  const channel = ctx.credentials?.config?.rememberChannel ?? 'cookie'
  const trustedAccess: AccessCheck = req => {
    if (!isTrustedRequest(req, trustedHosts))
      throw new VaultError('FORBIDDEN_HOST', "this request's Host is not a trusted authority")
  }
  const routes: Array<{ path: string; operation: JsonOperation; accessCheck: AccessCheck }> = [
    {
      path: '/api/credentials.status',
      accessCheck: trustedAccess,
      operation: async (payload: unknown, req: RequestLike, cookies: CookieJar) => {
        parseEmptyRequest(payload)
        const local = isLocalRequest(req)
        let ticketRejected = false
        if (local) {
          // The cookie channel ignores the header ticket entirely, so
          // legacy localStorage copies stop working on upgrade.
          const ticket =
            channel === 'header' ? (readRememberHeader(req) ?? readRememberCookie(req)) : readRememberCookie(req)
          if (ticket !== void 0) {
            try {
              await ctx.credentials.unlockWithRemember(ticket)
            } catch (error) {
              const code = (error as { code?: unknown } | null)?.code
              if (code === 'REMEMBER_EXPIRED' || code === 'REMEMBER_INVALID') {
                ctx.logger.warn?.('dsh-encrypt: remembered-login ticket rejected (%s); clearing the cookie', code)
                cookies.clear()
                ticketRejected = true
              } else if (code !== 'VAULT_NOT_ENCRYPTED') {
                throw error
              }
            }
          }
        }
        const status = await ctx.credentials.status()
        return { ...status, local, ticketRejected }
      },
    },
    {
      path: '/api/credentials.unlock',
      accessCheck: assertLocal,
      operation: async (payload: unknown, _req: RequestLike, cookies: CookieJar) => {
        const request = parseDigestRequest(payload)
        const value = await ctx.credentials.unlock(request.digest)
        return rememberedPasswordResult(value, await ctx.credentials.issueRemember(), cookies, channel)
      },
    },
    {
      path: '/api/credentials.set-password',
      accessCheck: assertLocal,
      operation: async (payload: unknown, _req: RequestLike, cookies: CookieJar) => {
        const request = parseDigestRequest(payload)
        const value = await ctx.credentials.setPassword(request.digest)
        return rememberedPasswordResult(value, await ctx.credentials.issueRemember(), cookies, channel)
      },
    },
    {
      path: '/api/credentials.change-password',
      accessCheck: assertLocal,
      operation: async (payload: unknown, _req: RequestLike, cookies: CookieJar) => {
        const request = parseChangePasswordRequest(payload)
        cookies.clear()
        const value = await ctx.credentials.changePassword(request.oldDigest, request.digest)
        return rememberedPasswordResult(value, await ctx.credentials.issueRemember(), cookies, channel)
      },
    },

    {
      path: '/api/credentials.config',
      accessCheck: trustedAccess,
      operation: async (payload: unknown, req: RequestLike, cookies: CookieJar) => {
        const request = parseConfigRequest(payload)
        let ticket
        if (request.action === 'set') {
          assertLocal(req)
          const issued = await ctx.credentials.setRememberDays(request.rememberDays)
          if (issued !== null) {
            cookies.set(rememberCookieHeader(issued.secret, issued.days))
            ticket = issued.secret
          } else {
            cookies.clear()
          }
        }
        const status = await ctx.credentials.status()
        const result: JsonObject = { ...status, local: isLocalRequest(req) }
        if (channel === 'header') result.ticket = ticket
        return result
      },
    },
  ]
  for (const { path, operation, accessCheck } of routes) {
    ctx.effect(
      () =>
        ctx.webServer.register({
          kind: 'exact',
          path,
          handler: jsonHandler(operation, ctx.logger, accessCheck),
        }),
      `dsh-encrypt: ${path}`,
    )
  }
}
