import type { LeakGuard } from '../../leak-guard.js'
import type {
  CompletionCallback,
  HttpChunk,
  HttpHandler,
  HttpRequestLike as RequestLike,
  HttpResponseLike as ResponseLike,
  HttpRoute,
  ResponseHeaderValue,
  UpgradeRoute,
  UpgradeSocketLike as SocketLike,
} from '../../transport/http/model.js'
import { WsFrameFilter } from '../../leak-guard.js'

interface RedactionWebServer {
  exact: Map<string, HttpRoute>
  prefixes: Map<string, HttpRoute>
  upgrades?: Map<string, UpgradeRoute> | undefined
}

interface RedactionContext {
  credentials: { leakGuard: LeakGuard }
  webServer: RedactionWebServer
}

/**
 * Wrap an HTTP handler so every emitted text piece passes through the guard.
 *
 * The wrapper must coexist with a compressing carrier *beneath* it — the host
 * webserver's gzip middleware engages inside `writeHead` and can turn the
 * response into an encoded one after the handler supplied plaintext headers.
 * Redaction runs before that layer, so the pieces fed through the captured
 * write/end stay plaintext; but once the head is on the wire the wrapper stops
 * re-checking `Content-Encoding`, because an encoding observed then belongs to
 * the carrier wrapping our redacted text, not to a handler emitting
 * pre-encoded bytes. Blocking stays confined to the window before the head is
 * sent, where the headers are still ours to replace.
 */
export function redactingHttpHandler(handler: HttpHandler, guard: LeakGuard): HttpHandler {
  return async (req: RequestLike, res: ResponseLike) => {
    if (!guard.enabled || typeof res.write !== 'function' || typeof res.end !== 'function') {
      return handler(req, res)
    }
    delete req.headers['accept-encoding']
    const stream = guard.stream()
    const originalWrite = res.write.bind(res)
    const originalEnd = res.end.bind(res)
    const originalWriteHead = res.writeHead.bind(res)
    const originalSetHeader = res.setHeader?.bind(res)
    let bodyMode: 'redact' | 'passthrough' | 'blocked' = 'redact'
    let blockedHeadWritten = false
    let blockedEndWritten = false
    const headSent = (): boolean => res.headersSent === true
    res.removeHeader?.('Content-Length')
    res.removeHeader?.('ETag')
    if (originalSetHeader !== void 0) {
      res.setHeader = (name: string, value: ResponseHeaderValue) => {
        const lower = name.toLowerCase()
        if (lower === 'content-length' || lower === 'etag') return res
        return originalSetHeader(name, value)
      }
    }
    const blockEncodedResponse = (): void => {
      bodyMode = 'blocked'
      if (headSent()) return
      res.removeHeader?.('Content-Encoding')
      res.removeHeader?.('Content-Length')
      res.removeHeader?.('ETag')
      if (blockedHeadWritten) return
      blockedHeadWritten = true
      originalWriteHead(500, {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
        connection: 'close',
      })
    }
    res.writeHead = (
      status: number,
      statusMessageOrHeaders?: string | Record<string, ResponseHeaderValue>,
      headers?: Record<string, ResponseHeaderValue>,
    ) => {
      const supplied = typeof statusMessageOrHeaders === 'string' ? headers : statusMessageOrHeaders
      if (responseIsEncoded(supplied, res)) {
        blockEncodedResponse()
        return res
      }
      bodyMode = responseIsText(supplied, res) ? 'redact' : 'passthrough'
      const cleaned = bodyMode === 'redact' && supplied !== void 0 ? stripChangedBodyHeaders(supplied) : supplied
      if (!headSent()) {
        res.removeHeader?.('Content-Length')
        res.removeHeader?.('ETag')
      }
      return typeof statusMessageOrHeaders === 'string'
        ? originalWriteHead(status, statusMessageOrHeaders, cleaned)
        : originalWriteHead(status, cleaned)
    }
    res.write = (chunk: HttpChunk, encoding?: BufferEncoding | CompletionCallback, callback?: CompletionCallback) => {
      if (bodyMode !== 'blocked' && !headSent() && responseIsEncoded(void 0, res)) blockEncodedResponse()
      if (bodyMode === 'blocked') {
        const cb = typeof encoding === 'function' ? encoding : typeof callback === 'function' ? callback : void 0
        if (cb !== void 0) cb()
        return true
      }
      if (bodyMode === 'passthrough') return originalWrite(chunk, encoding, callback)
      const cb = typeof encoding === 'function' ? encoding : typeof callback === 'function' ? callback : void 0
      const enc = typeof encoding === 'string' && Buffer.isEncoding(encoding) ? encoding : void 0
      for (const piece of stream.push(chunk)) originalWrite(piece, enc)
      if (cb !== void 0) cb()
      return true
    }
    res.end = (chunk?: HttpChunk, encoding?: BufferEncoding | CompletionCallback, callback?: CompletionCallback) => {
      if (bodyMode !== 'blocked' && !headSent() && responseIsEncoded(void 0, res)) blockEncodedResponse()
      if (bodyMode === 'blocked') {
        const cb = typeof encoding === 'function' ? encoding : typeof callback === 'function' ? callback : void 0
        if (!blockedEndWritten) {
          blockedEndWritten = true
          originalEnd('dsh-encrypt: encoded response blocked by output redaction')
        }
        if (cb !== void 0) cb()
        return res
      }
      if (bodyMode === 'passthrough') return originalEnd(chunk, encoding, callback)
      const cb = typeof encoding === 'function' ? encoding : typeof callback === 'function' ? callback : void 0
      const enc = typeof encoding === 'string' && Buffer.isEncoding(encoding) ? encoding : void 0
      if (chunk !== void 0 && chunk !== null) {
        const pieces = stream.push(chunk)
        const tail = stream.flush()
        const last = pieces.length > 0 ? (pieces[pieces.length - 1] as string) + tail : tail
        for (const piece of pieces.slice(0, -1)) originalWrite(piece, enc)
        originalEnd(last, enc)
      } else {
        const tail = stream.flush()
        if (tail.length > 0) originalWrite(tail, enc)
        originalEnd()
      }
      if (cb !== void 0) cb()
      return res
    }
    try {
      return await handler(req, res)
    } finally {
      res.write = originalWrite
      res.end = originalEnd
      res.writeHead = originalWriteHead
      if (originalSetHeader !== void 0) res.setHeader = originalSetHeader
    }
  }
}

/** Whether an outgoing body is safe to interpret as uncompressed UTF-8 text. */
function responseIsText(headers: Record<string, ResponseHeaderValue> | undefined, res: ResponseLike): boolean {
  const rawType = headerValue(headers, 'content-type') ?? res.getHeader?.('Content-Type')
  if (rawType === void 0) return true
  const type = String(rawType).split(';', 1)[0]?.trim().toLowerCase() ?? ''
  return (
    type.startsWith('text/') ||
    type === 'application/json' ||
    type.endsWith('+json') ||
    type === 'application/javascript' ||
    type === 'application/xml' ||
    type.endsWith('+xml') ||
    type === 'application/yaml' ||
    type === 'application/x-yaml' ||
    type === 'application/toml' ||
    type === 'application/graphql-response+json' ||
    type === 'application/x-www-form-urlencoded'
  )
}

function responseIsEncoded(headers: Record<string, ResponseHeaderValue> | undefined, res: ResponseLike): boolean {
  const encoding = headerValue(headers, 'content-encoding') ?? res.getHeader?.('Content-Encoding')
  return encoding !== void 0 && String(encoding).trim().toLowerCase() !== 'identity'
}

function headerValue(
  headers: Record<string, ResponseHeaderValue> | undefined,
  name: string,
): ResponseHeaderValue | undefined {
  if (headers === void 0) return void 0
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name) return value
  }
  return void 0
}

function stripChangedBodyHeaders(headers: Record<string, ResponseHeaderValue>): Record<string, ResponseHeaderValue> {
  const cleaned: Record<string, ResponseHeaderValue> = {}
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase()
    if (lower !== 'content-length' && lower !== 'etag') cleaned[key] = value
  }
  return cleaned
}

/** Arm a raw socket after its successful WebSocket upgrade handshake. */
export function armSocketRedaction(socket: SocketLike, guard: LeakGuard): void {
  if (!guard.enabled || typeof socket.write !== 'function') return
  const original = socket.write.bind(socket)
  let filter: WsFrameFilter | null = null
  let pre: Buffer = Buffer.alloc(0)
  let dead = false
  socket.write = function (
    chunk: HttpChunk,
    encoding?: BufferEncoding | CompletionCallback,
    callback?: CompletionCallback,
  ): boolean {
    const cb = typeof encoding === 'function' ? encoding : callback
    const enc: BufferEncoding = typeof encoding === 'string' && Buffer.isEncoding(encoding) ? encoding : 'utf8'
    const buffer = Buffer.isBuffer(chunk)
      ? chunk
      : typeof chunk === 'string'
        ? Buffer.from(chunk, enc)
        : Buffer.from(chunk)
    if (filter === null && !dead) {
      pre = Buffer.concat([pre, buffer])
      const terminator = pre.indexOf('\r\n\r\n')
      if (terminator !== -1) {
        const isUpgrade = pre.subarray(0, terminator).toString('latin1').startsWith('HTTP/1.1 101')
        if (isUpgrade) {
          original(pre.subarray(0, terminator + 4), enc)
          filter = new WsFrameFilter(text => guard.mask(text))
          const rest = pre.subarray(terminator + 4)
          pre = Buffer.alloc(0)
          try {
            for (const piece of filter.push(rest)) original(piece, enc)
          } catch (error) {
            socket.destroy?.(error instanceof Error ? error : new Error(String(error)))
            if (cb !== void 0) cb(error)
            return false
          }
          if (cb !== void 0) cb()
          return true
        }
        dead = true
      } else if (pre.length > 16 * 1024) {
        const error = new Error('dsh-encrypt: WebSocket upgrade response headers exceed 16 KiB')
        pre = Buffer.alloc(0)
        socket.destroy?.(error)
        if (cb !== void 0) cb(error)
        return false
      }
      if (dead) {
        original(pre, enc)
        pre = Buffer.alloc(0)
        if (cb !== void 0) cb()
        return true
      }
      if (cb !== void 0) cb()
      return true
    }
    if (dead || filter === null) return original(chunk, encoding, callback)
    try {
      for (const piece of filter.push(chunk)) original(piece, enc)
    } catch (error) {
      socket.destroy?.(error instanceof Error ? error : new Error(String(error)))
      if (cb !== void 0) cb(error)
      return false
    }
    if (cb !== void 0) cb()
    return true
  }
}

/** Wrap one WebSocket upgrade route. */
export function redactingUpgradeRoute(route: UpgradeRoute, guard: LeakGuard): UpgradeRoute {
  const handler = route.handler
  return {
    ...route,
    handler: (req: unknown, socket: SocketLike, head: Buffer) => {
      const headers = (req as { headers?: Record<string, unknown> } | null)?.headers
      if (headers !== void 0) delete headers['sec-websocket-extensions']
      armSocketRedaction(socket, guard)
      return handler(req, socket, head)
    },
  }
}

/** Install redaction over existing and future HTTP and WebSocket routes. */
export function installLeakRedaction(ctx: RedactionContext): () => void {
  const guard = ctx.credentials.leakGuard
  const webServer = ctx.webServer
  const wrappedHttp = new WeakMap<HttpRoute, HttpRoute>()
  const wrappedUpgrades = new WeakMap<UpgradeRoute, UpgradeRoute>()
  const wrapHttp = (route: HttpRoute): HttpRoute => {
    const wrapped = { ...route, handler: redactingHttpHandler(route.handler, guard) }
    wrappedHttp.set(wrapped, route)
    return wrapped
  }
  const wrapUpgrade = (route: UpgradeRoute): UpgradeRoute => {
    const wrapped = redactingUpgradeRoute(route, guard)
    wrappedUpgrades.set(wrapped, route)
    return wrapped
  }
  const restoreTable = <T extends object>(table: Map<string, T>, originals: WeakMap<T, T>): void => {
    for (const [path, route] of table) {
      const original = originals.get(route)
      if (original !== void 0) table.set(path, original)
    }
  }
  const proxyTable = <T>(table: Map<string, T>, wrap: (route: T) => T): Map<string, T> =>
    new Proxy(table, {
      get(target, key) {
        if (key === 'set') return (path: string, route: T) => target.set(path, wrap(route))
        const value: unknown = Reflect.get(target, key)
        return typeof value === 'function'
          ? (...args: unknown[]): unknown => Reflect.apply(value, target, args) as unknown
          : value
      },
    })
  const originalExact = webServer.exact
  const originalPrefixes = webServer.prefixes
  const originalUpgrades = webServer.upgrades
  for (const [path, route] of [...webServer.exact]) webServer.exact.set(path, wrapHttp(route))
  for (const [path, route] of [...webServer.prefixes]) webServer.prefixes.set(path, wrapHttp(route))
  if (webServer.upgrades !== void 0) {
    for (const [path, route] of [...webServer.upgrades]) webServer.upgrades.set(path, wrapUpgrade(route))
  }
  webServer.exact = proxyTable(originalExact, wrapHttp)
  webServer.prefixes = proxyTable(originalPrefixes, wrapHttp)
  if (originalUpgrades !== void 0) webServer.upgrades = proxyTable(originalUpgrades, wrapUpgrade)
  return () => {
    restoreTable(originalExact, wrappedHttp)
    restoreTable(originalPrefixes, wrappedHttp)
    if (originalUpgrades !== void 0) restoreTable(originalUpgrades, wrappedUpgrades)
    if (webServer.exact !== originalExact) webServer.exact = originalExact
    if (webServer.prefixes !== originalPrefixes) webServer.prefixes = originalPrefixes
    if (webServer.upgrades !== originalUpgrades) webServer.upgrades = originalUpgrades
  }
}
