import { t as LeakGuard } from "./leak-guard-BYcHOd2D.js";
import z from "@deepseek-ai/schemastery";
//#region src/transport/http/model.d.ts
/** Shared structural types for the plugin's Node HTTP integration. */
type HttpChunk = string | Buffer | Uint8Array;
type CompletionCallback = (...args: unknown[]) => void;
type ResponseHeaderValue = string | number | string[];
interface HttpRequestLike extends AsyncIterable<HttpChunk> {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  destroy?: (error?: Error) => unknown;
}
interface HttpResponseLike {
  write: (chunk: HttpChunk, encoding?: BufferEncoding | CompletionCallback, callback?: CompletionCallback) => boolean;
  end: (chunk?: HttpChunk, encoding?: BufferEncoding | CompletionCallback, callback?: CompletionCallback) => unknown;
  writeHead: (status: number, statusMessageOrHeaders?: string | Record<string, ResponseHeaderValue>, headers?: Record<string, ResponseHeaderValue>) => unknown;
  setHeader?: (name: string, value: ResponseHeaderValue) => unknown;
  getHeader?: (name: string) => ResponseHeaderValue | undefined;
  removeHeader?: (name: string) => unknown;
  /** True once the response head is on the wire (node sets this on ServerResponse). */
  headersSent?: boolean;
}
type HttpHandler = (req: HttpRequestLike, res: HttpResponseLike) => unknown | Promise<unknown>;
interface UpgradeSocketLike {
  write: (chunk: HttpChunk, encoding?: BufferEncoding | CompletionCallback, callback?: CompletionCallback) => boolean;
  destroy?: (error?: Error) => unknown;
}
type UpgradeHandler = (req: unknown, socket: UpgradeSocketLike, head: Buffer) => unknown;
interface HttpRoute {
  [key: string]: unknown;
  handler: HttpHandler;
}
interface UpgradeRoute {
  [key: string]: unknown;
  handler: UpgradeHandler;
}
//#endregion
//#region src/web.d.ts
type JsonObject = Record<string, unknown>;
interface RememberIssue {
  secret: string;
  days: number;
  issuedAt: number;
  expiresAt: number | null;
}
interface WebCredentials {
  leakGuard: LeakGuard;
  format?: string;
  config?: {
    rememberChannel?: "cookie" | "header";
  };
  status: () => Promise<JsonObject>;
  unlock: (digest: string) => Promise<JsonObject>;
  unlockWithRemember: (ticket: string) => Promise<unknown>;
  setPassword: (digest: string) => Promise<JsonObject>;
  changePassword: (oldDigest: string, digest: string) => Promise<JsonObject>;
  issueRemember: () => Promise<RememberIssue | null>;
  setRememberDays: (days: unknown) => Promise<RememberIssue | null>;
}
interface LoggerLike {
  warn?: (...args: unknown[]) => void;
}
interface WebServerLike {
  host?: string;
  exact: Map<string, HttpRoute>;
  prefixes: Map<string, HttpRoute>;
  upgrades?: Map<string, UpgradeRoute> | undefined;
  register: (route: {
    kind: "exact";
    path: string;
    handler: HttpHandler;
  }) => unknown;
}
interface WebContext {
  credentials: WebCredentials;
  webServer: WebServerLike;
  logger: LoggerLike;
  effect: (factory: () => unknown, description: string) => unknown;
}
interface WebConfig {
  trustedHosts?: string[];
}
declare const name = "dsh-encrypt-web";
declare const inject: readonly ["webServer", "credentials"];
/** Cookie carrying the browser-held remembered-login ticket. */
declare const REMEMBER_COOKIE = "dsh-encrypt-remember";
/** Request header carrying the ticket on the localStorage-backed channel. */
declare const REMEMBER_TICKET_HEADER = "x-dsh-encrypt-remember";
/** Request header that opts one request into the localStorage-backed channel. */
declare const REMEMBER_CHANNEL_HEADER = "x-dsh-encrypt-remember-channel";
/** Value of {@link REMEMBER_CHANNEL_HEADER} selecting the header channel. */
declare const REMEMBER_CHANNEL_HEADER_VALUE = "header";
/**
 * Whether a request is genuinely local: its Host names the loopback interface
 * AND its socket arrived from loopback. The Host half is the DNS-rebinding
 * fence (a rebound page's socket IS loopback, so socket alone is not enough);
 * the socket half closes the inverse spoof (a non-browser LAN client forging
 * a loopback Host). Password mutations and remembered-login issuance require
 * both halves.
 */
declare function isLocalRequest(req: unknown): boolean;
/** Read the remembered-login ticket from the request cookies, if present. */
declare function readRememberCookie(req: unknown): string | undefined;
/**
 * Read the remembered-login ticket from the explicit request header the
 * WebUI attaches. Only honored on the localStorage-backed header channel —
 * the HttpOnly cookie is the default carrier.
 */
declare function readRememberHeader(req: unknown): string | undefined;
/**
 * Whether this request participates in the localStorage-backed header
 * channel. The deployment config selects it globally, but a page on a carrier
 * that cannot keep cookies may ask for it per request: the dsh desktop shell
 * serves the WebUI from the `dsh-app:` scheme, replaces every request Cookie
 * with its own Host authentication cookie, and withholds `Set-Cookie` from
 * responses, so the HttpOnly ticket can neither be stored nor sent there.
 *
 * A cookie-mode deployment keeps its HttpOnly guarantee for ordinary browsers;
 * only a same-origin page script can add the hint (a cross-site addition
 * requires a CORS preflight these routes never answer), and the ticket itself
 * is only ever issued by a loopback password operation.
 */
declare function requestUsesHeaderChannel(req: unknown, configured: "cookie" | "header" | undefined): boolean;
/** Build the Set-Cookie header issuing a remembered login. */
declare function rememberCookieHeader(secret: string, days: number): string;
/** Build the Set-Cookie header clearing a remembered login. */
declare function clearRememberCookieHeader(): string;
/**
 * Wrap one HTTP route handler so everything it writes is redacted through
 * the guard. No-op (bare passthrough) when the guard is disabled or holds no
 * secrets, so locked vaults pay nothing.
 * @param {(req: unknown, res: unknown) => unknown} handler - the route handler.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 * @returns the wrapped handler.
 */
declare function redactingHttpHandler(handler: HttpHandler, guard: LeakGuard): HttpHandler;
/**
 * Patch a raw upgrade socket so that, once the 101 handshake response has
 * been written, every outgoing WebSocket frame passes through the guard
 * (text frames only; the downlink server sends unmasked, uncompressed
 * frames, see {@link WsFrameFilter}). The handshake response itself is
 * buffered only until its header terminator arrives, then forwarded intact.
 * @param {import("node:net").Socket} socket - the raw socket.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 */
declare function armSocketRedaction(socket: UpgradeSocketLike, guard: LeakGuard): void;
/**
 * Wrap one upgrade route handler so its socket frames are redacted after the
 * handshake completes.
 * @param {object} route - the registered upgrade route.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 * @returns the wrapped route.
 */
declare function redactingUpgradeRoute(route: UpgradeRoute, guard: LeakGuard): UpgradeRoute;
/**
 * Install response redaction over the web server's route tables: existing
 * routes are wrapped in place and future registrations are wrapped on insert
 * (the Proxy set trap), covering the /api prefix owned by client-connection
 * and any route registered later. Returns a disposer restoring the original
 * tables.
 * @param {unknown} ctx - the row context.
 * @returns {() => void} the disposer.
 */
declare function installLeakRedaction(ctx: WebContext): () => void;
/**
 * Web-row configuration: `trustedHosts` lists non-loopback authorities
 * (host or host:port) accepted by the trust fence.
 */
declare const Config: ReturnType<typeof z.object>;
declare function apply(ctx: WebContext, config?: WebConfig): void;
//#endregion
export { Config, REMEMBER_CHANNEL_HEADER, REMEMBER_CHANNEL_HEADER_VALUE, REMEMBER_COOKIE, REMEMBER_TICKET_HEADER, WebConfig, apply, armSocketRedaction, clearRememberCookieHeader, inject, installLeakRedaction, isLocalRequest, name, readRememberCookie, readRememberHeader, redactingHttpHandler, redactingUpgradeRoute, rememberCookieHeader, requestUsesHeaderChannel };
//# sourceMappingURL=web.d.ts.map