/** Shared structural types for the plugin's Node HTTP integration. */

export type HttpChunk = string | Buffer | Uint8Array
export type CompletionCallback = (...args: unknown[]) => void
export type ResponseHeaderValue = string | number | string[]

export interface HttpRequestLike extends AsyncIterable<HttpChunk> {
  method?: string
  headers: Record<string, string | string[] | undefined>
  destroy?: (error?: Error) => unknown
}

export interface HttpResponseLike {
  write: (chunk: HttpChunk, encoding?: BufferEncoding | CompletionCallback, callback?: CompletionCallback) => boolean
  end: (chunk?: HttpChunk, encoding?: BufferEncoding | CompletionCallback, callback?: CompletionCallback) => unknown
  writeHead: (
    status: number,
    statusMessageOrHeaders?: string | Record<string, ResponseHeaderValue>,
    headers?: Record<string, ResponseHeaderValue>,
  ) => unknown
  setHeader?: (name: string, value: ResponseHeaderValue) => unknown
  getHeader?: (name: string) => ResponseHeaderValue | undefined
  removeHeader?: (name: string) => unknown
  /** True once the response head is on the wire (node sets this on ServerResponse). */
  headersSent?: boolean
}

export type HttpHandler = (req: HttpRequestLike, res: HttpResponseLike) => unknown | Promise<unknown>

export interface UpgradeSocketLike {
  write: (chunk: HttpChunk, encoding?: BufferEncoding | CompletionCallback, callback?: CompletionCallback) => boolean
  destroy?: (error?: Error) => unknown
}

type UpgradeHandler = (req: unknown, socket: UpgradeSocketLike, head: Buffer) => unknown

export interface HttpRoute {
  [key: string]: unknown
  handler: HttpHandler
}

export interface UpgradeRoute {
  [key: string]: unknown
  handler: UpgradeHandler
}
