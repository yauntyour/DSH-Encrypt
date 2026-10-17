import { n as isAsciiLowerHex } from "./primitives-D0BudhaR.js";
import { st as VaultError } from "./vault-C7Wp8Tfo.js";
import { loadAndVerifyIntegrity } from "./integrity.js";
import { i as WsFrameFilter } from "./leak-guard-Demfexa5.js";
import { assertTrustedAuthority, isLoopbackRequest, isLoopbackSocket, isTrustedRequest } from "./trust.js";
import z from "@deepseek-ai/schemastery";
import { check, integer, literal, maxValue, minValue, number, pipe, safeParse, strictObject, string, union } from "valibot";
//#region src/security/redaction/web-redaction.ts
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
function redactingHttpHandler$1(handler, guard) {
	return async (req, res) => {
		if (!guard.enabled || typeof res.write !== "function" || typeof res.end !== "function") return handler(req, res);
		delete req.headers["accept-encoding"];
		const stream = guard.stream();
		const originalWrite = res.write.bind(res);
		const originalEnd = res.end.bind(res);
		const originalWriteHead = res.writeHead.bind(res);
		const originalSetHeader = res.setHeader?.bind(res);
		let bodyMode = "redact";
		let blockedHeadWritten = false;
		let blockedEndWritten = false;
		const headSent = () => res.headersSent === true;
		res.removeHeader?.("Content-Length");
		res.removeHeader?.("ETag");
		if (originalSetHeader !== void 0) res.setHeader = (name, value) => {
			const lower = name.toLowerCase();
			if (lower === "content-length" || lower === "etag") return res;
			return originalSetHeader(name, value);
		};
		const blockEncodedResponse = () => {
			bodyMode = "blocked";
			if (headSent()) return;
			res.removeHeader?.("Content-Encoding");
			res.removeHeader?.("Content-Length");
			res.removeHeader?.("ETag");
			if (blockedHeadWritten) return;
			blockedHeadWritten = true;
			originalWriteHead(500, {
				"content-type": "text/plain; charset=utf-8",
				"cache-control": "no-store",
				connection: "close"
			});
		};
		res.writeHead = (status, statusMessageOrHeaders, headers) => {
			const supplied = typeof statusMessageOrHeaders === "string" ? headers : statusMessageOrHeaders;
			if (responseIsEncoded(supplied, res)) {
				blockEncodedResponse();
				return res;
			}
			bodyMode = responseIsText(supplied, res) ? "redact" : "passthrough";
			const cleaned = bodyMode === "redact" && supplied !== void 0 ? stripChangedBodyHeaders(supplied) : supplied;
			if (!headSent()) {
				res.removeHeader?.("Content-Length");
				res.removeHeader?.("ETag");
			}
			return typeof statusMessageOrHeaders === "string" ? originalWriteHead(status, statusMessageOrHeaders, cleaned) : originalWriteHead(status, cleaned);
		};
		res.write = (chunk, encoding, callback) => {
			if (bodyMode !== "blocked" && !headSent() && responseIsEncoded(void 0, res)) blockEncodedResponse();
			if (bodyMode === "blocked") {
				const cb = typeof encoding === "function" ? encoding : typeof callback === "function" ? callback : void 0;
				if (cb !== void 0) cb();
				return true;
			}
			if (bodyMode === "passthrough") return originalWrite(chunk, encoding, callback);
			const cb = typeof encoding === "function" ? encoding : typeof callback === "function" ? callback : void 0;
			const enc = typeof encoding === "string" && Buffer.isEncoding(encoding) ? encoding : void 0;
			for (const piece of stream.push(chunk)) originalWrite(piece, enc);
			if (cb !== void 0) cb();
			return true;
		};
		res.end = (chunk, encoding, callback) => {
			if (bodyMode !== "blocked" && !headSent() && responseIsEncoded(void 0, res)) blockEncodedResponse();
			if (bodyMode === "blocked") {
				const cb = typeof encoding === "function" ? encoding : typeof callback === "function" ? callback : void 0;
				if (!blockedEndWritten) {
					blockedEndWritten = true;
					originalEnd("dsh-encrypt: encoded response blocked by output redaction");
				}
				if (cb !== void 0) cb();
				return res;
			}
			if (bodyMode === "passthrough") return originalEnd(chunk, encoding, callback);
			const cb = typeof encoding === "function" ? encoding : typeof callback === "function" ? callback : void 0;
			const enc = typeof encoding === "string" && Buffer.isEncoding(encoding) ? encoding : void 0;
			if (chunk !== void 0 && chunk !== null) {
				const pieces = stream.push(chunk);
				const tail = stream.flush();
				const last = pieces.length > 0 ? pieces[pieces.length - 1] + tail : tail;
				for (const piece of pieces.slice(0, -1)) originalWrite(piece, enc);
				originalEnd(last, enc);
			} else {
				const tail = stream.flush();
				if (tail.length > 0) originalWrite(tail, enc);
				originalEnd();
			}
			if (cb !== void 0) cb();
			return res;
		};
		try {
			return await handler(req, res);
		} finally {
			res.write = originalWrite;
			res.end = originalEnd;
			res.writeHead = originalWriteHead;
			if (originalSetHeader !== void 0) res.setHeader = originalSetHeader;
		}
	};
}
/** Whether an outgoing body is safe to interpret as uncompressed UTF-8 text. */
function responseIsText(headers, res) {
	const rawType = headerValue(headers, "content-type") ?? res.getHeader?.("Content-Type");
	if (rawType === void 0) return true;
	const type = String(rawType).split(";", 1)[0]?.trim().toLowerCase() ?? "";
	return type.startsWith("text/") || type === "application/json" || type.endsWith("+json") || type === "application/javascript" || type === "application/xml" || type.endsWith("+xml") || type === "application/yaml" || type === "application/x-yaml" || type === "application/toml" || type === "application/graphql-response+json" || type === "application/x-www-form-urlencoded";
}
function responseIsEncoded(headers, res) {
	const encoding = headerValue(headers, "content-encoding") ?? res.getHeader?.("Content-Encoding");
	return encoding !== void 0 && String(encoding).trim().toLowerCase() !== "identity";
}
function headerValue(headers, name) {
	if (headers === void 0) return void 0;
	for (const [key, value] of Object.entries(headers)) if (key.toLowerCase() === name) return value;
}
function stripChangedBodyHeaders(headers) {
	const cleaned = {};
	for (const [key, value] of Object.entries(headers)) {
		const lower = key.toLowerCase();
		if (lower !== "content-length" && lower !== "etag") cleaned[key] = value;
	}
	return cleaned;
}
/** Arm a raw socket after its successful WebSocket upgrade handshake. */
function armSocketRedaction$1(socket, guard) {
	if (!guard.enabled || typeof socket.write !== "function") return;
	const original = socket.write.bind(socket);
	let filter = null;
	let pre = Buffer.alloc(0);
	let dead = false;
	socket.write = function(chunk, encoding, callback) {
		const cb = typeof encoding === "function" ? encoding : callback;
		const enc = typeof encoding === "string" && Buffer.isEncoding(encoding) ? encoding : "utf8";
		const buffer = Buffer.isBuffer(chunk) ? chunk : typeof chunk === "string" ? Buffer.from(chunk, enc) : Buffer.from(chunk);
		if (filter === null && !dead) {
			pre = Buffer.concat([pre, buffer]);
			const terminator = pre.indexOf("\r\n\r\n");
			if (terminator !== -1) {
				if (pre.subarray(0, terminator).toString("latin1").startsWith("HTTP/1.1 101")) {
					original(pre.subarray(0, terminator + 4), enc);
					filter = new WsFrameFilter((text) => guard.mask(text));
					const rest = pre.subarray(terminator + 4);
					pre = Buffer.alloc(0);
					try {
						for (const piece of filter.push(rest)) original(piece, enc);
					} catch (error) {
						socket.destroy?.(error instanceof Error ? error : new Error(String(error)));
						if (cb !== void 0) cb(error);
						return false;
					}
					if (cb !== void 0) cb();
					return true;
				}
				dead = true;
			} else if (pre.length > 16384) {
				const error = /* @__PURE__ */ new Error("dsh-encrypt: WebSocket upgrade response headers exceed 16 KiB");
				pre = Buffer.alloc(0);
				socket.destroy?.(error);
				if (cb !== void 0) cb(error);
				return false;
			}
			if (dead) {
				original(pre, enc);
				pre = Buffer.alloc(0);
				if (cb !== void 0) cb();
				return true;
			}
			if (cb !== void 0) cb();
			return true;
		}
		if (dead || filter === null) return original(chunk, encoding, callback);
		try {
			for (const piece of filter.push(chunk)) original(piece, enc);
		} catch (error) {
			socket.destroy?.(error instanceof Error ? error : new Error(String(error)));
			if (cb !== void 0) cb(error);
			return false;
		}
		if (cb !== void 0) cb();
		return true;
	};
}
/** Wrap one WebSocket upgrade route. */
function redactingUpgradeRoute$1(route, guard) {
	const handler = route.handler;
	return {
		...route,
		handler: (req, socket, head) => {
			const headers = req?.headers;
			if (headers !== void 0) delete headers["sec-websocket-extensions"];
			armSocketRedaction$1(socket, guard);
			return handler(req, socket, head);
		}
	};
}
/** Install redaction over existing and future HTTP and WebSocket routes. */
function installLeakRedaction$1(ctx) {
	const guard = ctx.credentials.leakGuard;
	const webServer = ctx.webServer;
	const wrappedHttp = /* @__PURE__ */ new WeakMap();
	const wrappedUpgrades = /* @__PURE__ */ new WeakMap();
	const wrapHttp = (route) => {
		const wrapped = {
			...route,
			handler: redactingHttpHandler$1(route.handler, guard)
		};
		wrappedHttp.set(wrapped, route);
		return wrapped;
	};
	const wrapUpgrade = (route) => {
		const wrapped = redactingUpgradeRoute$1(route, guard);
		wrappedUpgrades.set(wrapped, route);
		return wrapped;
	};
	const restoreTable = (table, originals) => {
		for (const [path, route] of table) {
			const original = originals.get(route);
			if (original !== void 0) table.set(path, original);
		}
	};
	const proxyTable = (table, wrap) => new Proxy(table, { get(target, key) {
		if (key === "set") return (path, route) => target.set(path, wrap(route));
		const value = Reflect.get(target, key);
		return typeof value === "function" ? (...args) => Reflect.apply(value, target, args) : value;
	} });
	const originalExact = webServer.exact;
	const originalPrefixes = webServer.prefixes;
	const originalUpgrades = webServer.upgrades;
	for (const [path, route] of [...webServer.exact]) webServer.exact.set(path, wrapHttp(route));
	for (const [path, route] of [...webServer.prefixes]) webServer.prefixes.set(path, wrapHttp(route));
	if (webServer.upgrades !== void 0) for (const [path, route] of [...webServer.upgrades]) webServer.upgrades.set(path, wrapUpgrade(route));
	webServer.exact = proxyTable(originalExact, wrapHttp);
	webServer.prefixes = proxyTable(originalPrefixes, wrapHttp);
	if (originalUpgrades !== void 0) webServer.upgrades = proxyTable(originalUpgrades, wrapUpgrade);
	return () => {
		restoreTable(originalExact, wrappedHttp);
		restoreTable(originalPrefixes, wrappedHttp);
		if (originalUpgrades !== void 0) restoreTable(originalUpgrades, wrappedUpgrades);
		if (webServer.exact !== originalExact) webServer.exact = originalExact;
		if (webServer.prefixes !== originalPrefixes) webServer.prefixes = originalPrefixes;
		if (webServer.upgrades !== originalUpgrades) webServer.upgrades = originalUpgrades;
	};
}
//#endregion
//#region src/transport/http/request-body.ts
const MAX_BODY_BYTES = 4096;
const BODY_TIMEOUT_MS = 1e4;
/** Read and parse one small credential-route JSON body under fixed resource limits. */
async function readCredentialJsonBody(req) {
	let raw = "";
	let bytes = 0;
	let timedOut = false;
	const bodyTimeout = setTimeout(() => {
		timedOut = true;
		req.destroy?.(/* @__PURE__ */ new Error("dsh-encrypt: credential request body timed out"));
	}, BODY_TIMEOUT_MS);
	bodyTimeout.unref();
	try {
		for await (const chunk of req) {
			bytes += typeof chunk === "string" ? Buffer.byteLength(chunk) : chunk.length;
			if (bytes > MAX_BODY_BYTES) throw new VaultError("PAYLOAD_TOO_LARGE", "credential request body exceeds 4 KiB");
			raw += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
		}
	} catch (error) {
		if (timedOut) throw new VaultError("REQUEST_TIMEOUT", "credential request body timed out");
		throw error;
	} finally {
		clearTimeout(bodyTimeout);
	}
	if (raw.length === 0) return {};
	try {
		return JSON.parse(raw);
	} catch {
		throw new VaultError("BAD_REQUEST", "credential request body is not valid JSON");
	}
}
//#endregion
//#region src/transport/http/request-schemas.ts
const digestSchema = pipe(string(), check((value) => isAsciiLowerHex(value, 64)));
const emptyRequestSchema = strictObject({});
const digestRequestSchema = strictObject({ digest: digestSchema });
const changePasswordRequestSchema = strictObject({
	oldDigest: digestSchema,
	digest: digestSchema
});
const configRequestSchema = union([
	strictObject({}),
	strictObject({ action: literal("get") }),
	strictObject({
		action: literal("set"),
		rememberDays: pipe(number(), integer(), minValue(-1), maxValue(30))
	})
]);
/** Validate an operation that accepts no request fields. */
function parseEmptyRequest(input) {
	return parseBoundary(emptyRequestSchema, input, "the request body must be an empty JSON object");
}
/** Validate a password-digest request. */
function parseDigestRequest(input) {
	return parseBoundary(digestRequestSchema, input, "digest must be a 64-character lowercase SHA3-256 hexadecimal string");
}
/** Validate a change-password request. */
function parseChangePasswordRequest(input) {
	return parseBoundary(changePasswordRequestSchema, input, "oldDigest and digest must be 64-character lowercase SHA3-256 hexadecimal strings");
}
/** Validate the remembered-login configuration request. */
function parseConfigRequest(input) {
	return parseBoundary(configRequestSchema, input, "config action must be get, or set with rememberDays from -1 through 30");
}
function parseBoundary(schema, input, message) {
	const parsed = safeParse(schema, input);
	if (!parsed.success) throw new VaultError("BAD_REQUEST", message);
	return parsed.output;
}
//#endregion
//#region src/web.ts
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
*   The ticket is only echoed in a response body on the localStorage-backed
*   header channel: either the deployment opts into it
*   (rememberChannel: "header"), or the page asks for it because its carrier
*   cannot keep cookies (the dsh desktop shell serves `dsh-app:` documents,
*   replaces request Cookies, and withholds Set-Cookie). Non-loopback
*   requests never use either channel.
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
loadAndVerifyIntegrity(import.meta.url);
const name = "dsh-encrypt-web";
const inject = ["webServer", "credentials"];
/** Cookie carrying the browser-held remembered-login ticket. */
const REMEMBER_COOKIE = "dsh-encrypt-remember";
/** Request header carrying the ticket on the localStorage-backed channel. */
const REMEMBER_TICKET_HEADER = "x-dsh-encrypt-remember";
/** Request header that opts one request into the localStorage-backed channel. */
const REMEMBER_CHANNEL_HEADER = "x-dsh-encrypt-remember-channel";
/** Value of {@link REMEMBER_CHANNEL_HEADER} selecting the header channel. */
const REMEMBER_CHANNEL_HEADER_VALUE = "header";
/** Cookie max-age for a forever remembered login (100 years in seconds). */
const FOREVER_MAX_AGE = 31536e5;
/**
* Whether a request is genuinely local: its Host names the loopback interface
* AND its socket arrived from loopback. The Host half is the DNS-rebinding
* fence (a rebound page's socket IS loopback, so socket alone is not enough);
* the socket half closes the inverse spoof (a non-browser LAN client forging
* a loopback Host). Password mutations and remembered-login issuance require
* both halves.
*/
function isLocalRequest(req) {
	return isLoopbackRequest(req) && isLoopbackSocket(req);
}
/** Read the remembered-login ticket from the request cookies, if present. */
function readRememberCookie(req) {
	const header = req?.headers?.cookie;
	if (typeof header !== "string" || header.length === 0) return void 0;
	for (const part of header.split(";")) {
		const eq = part.indexOf("=");
		if (eq === -1) continue;
		if (part.slice(0, eq).trim() === "dsh-encrypt-remember") return part.slice(eq + 1).trim();
	}
}
/**
* Read the remembered-login ticket from the explicit request header the
* WebUI attaches. Only honored on the localStorage-backed header channel —
* the HttpOnly cookie is the default carrier.
*/
function readRememberHeader(req) {
	const header = req?.headers?.[REMEMBER_TICKET_HEADER];
	if (typeof header !== "string" || header.length === 0) return void 0;
	return header.trim();
}
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
function requestUsesHeaderChannel(req, configured) {
	if (configured === "header") return true;
	const hint = req?.headers?.[REMEMBER_CHANNEL_HEADER];
	return typeof hint === "string" && hint.trim().toLowerCase() === "header";
}
/** Build the Set-Cookie header issuing a remembered login. */
function rememberCookieHeader(secret, days) {
	const maxAge = days === -1 ? FOREVER_MAX_AGE : Math.max(0, Math.floor(days * 86400));
	return `${REMEMBER_COOKIE}=${secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}
/** Build the Set-Cookie header clearing a remembered login. */
function clearRememberCookieHeader() {
	return `${REMEMBER_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}
/** Build the common successful result for password operations and issue its browser ticket. */
function rememberedPasswordResult(value, issued, cookies, channel) {
	if (issued !== null) cookies.set(rememberCookieHeader(issued.secret, issued.days));
	const result = {
		...value,
		local: true,
		rememberChannel: channel,
		remembered: issued !== null,
		expiresAt: issued?.expiresAt ?? null
	};
	if (channel === "header") result.ticket = issued?.secret;
	return result;
}
/** Reject a non-localhost caller before a password modification runs. */
function assertLocal(req) {
	if (!isLocalRequest(req)) throw new VaultError("LOCAL_ONLY", "password operations and remembered-login settings are only allowed from localhost");
}
/**
* Wrap one HTTP route handler so everything it writes is redacted through
* the guard. No-op (bare passthrough) when the guard is disabled or holds no
* secrets, so locked vaults pay nothing.
* @param {(req: unknown, res: unknown) => unknown} handler - the route handler.
* @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
* @returns the wrapped handler.
*/
function redactingHttpHandler(handler, guard) {
	return redactingHttpHandler$1(handler, guard);
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
function armSocketRedaction(socket, guard) {
	armSocketRedaction$1(socket, guard);
}
/**
* Wrap one upgrade route handler so its socket frames are redacted after the
* handshake completes.
* @param {object} route - the registered upgrade route.
* @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
* @returns the wrapped route.
*/
function redactingUpgradeRoute(route, guard) {
	return redactingUpgradeRoute$1(route, guard);
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
function installLeakRedaction(ctx) {
	return installLeakRedaction$1(ctx);
}
/** Wrap one password operation into a JSON HTTP handler with the write fence. */
function jsonHandler(operation, logger, accessCheck) {
	return async (req, res) => {
		/** Cookie to attach to the response; the last assignment wins. */
		const cookies = {
			value: void 0,
			set(header) {
				cookies.value = header;
			},
			clear() {
				cookies.value = clearRememberCookieHeader();
			}
		};
		const write = (status, body, extraHeaders = {}) => {
			const headers = {
				"content-type": "application/json",
				...extraHeaders
			};
			if (cookies.value !== void 0) {
				headers["set-cookie"] = cookies.value;
				if (typeof res.setHeader === "function") res.setHeader("Set-Cookie", cookies.value);
			}
			res.writeHead(status, headers);
			return res.end(JSON.stringify(body));
		};
		const fail = (error) => {
			const cause = error;
			const code = typeof cause?.code === "string" ? cause.code : "internal";
			const message = error instanceof VaultError ? error.message : "internal server error";
			if (!(error instanceof VaultError)) logger?.warn?.("dsh-encrypt: credentials route failed: %s", error instanceof Error ? error.stack ?? error.message : String(error));
			if (code === "TOO_MANY_ATTEMPTS") {
				const retryAfterSeconds = Math.max(1, Math.ceil((typeof cause?.retryAfterMs === "number" ? cause.retryAfterMs : 0) / 1e3));
				return write(429, {
					ok: false,
					code,
					message,
					retryAfterMs: retryAfterSeconds * 1e3
				}, { "retry-after": String(retryAfterSeconds) });
			}
			if (code === "FORBIDDEN_HOST" || code === "LOCAL_ONLY") return write(403, {
				ok: false,
				code,
				message
			});
			if (code === "PAYLOAD_TOO_LARGE") return write(413, {
				ok: false,
				code,
				message
			});
			if (code === "REQUEST_TIMEOUT") return write(408, {
				ok: false,
				code,
				message
			});
			if (code === "internal") return write(500, {
				ok: false,
				code,
				message
			});
			return write(400, {
				ok: false,
				code,
				message
			});
		};
		if (req.method !== "POST") return write(405, {
			ok: false,
			code: "method-not-allowed",
			message: "POST required"
		});
		try {
			accessCheck?.(req);
		} catch (error) {
			return fail(error);
		}
		if ((String(req.headers["content-type"] ?? "").split(";", 1)[0] ?? "").trim().toLowerCase() !== "application/json") return write(415, {
			ok: false,
			code: "unsupported-media",
			message: "content type must be application/json"
		});
		let payload;
		try {
			payload = await readCredentialJsonBody(req);
		} catch (error) {
			return fail(error);
		}
		try {
			const value = await operation(payload, req, cookies);
			return write(200, {
				ok: true,
				value: value === void 0 ? {} : value
			});
		} catch (error) {
			return fail(error);
		}
	};
}
/**
* Web-row configuration: `trustedHosts` lists non-loopback authorities
* (host or host:port) accepted by the trust fence.
*/
const Config = z.object({ trustedHosts: z.array(String).default([]) });
function apply(ctx, config = {}) {
	const trustedHosts = config?.trustedHosts ?? [];
	for (const entry of trustedHosts) assertTrustedAuthority(entry);
	if (ctx.webServer?.host === "0.0.0.0") ctx.logger.warn?.("dsh-encrypt: the web server is bound to all interfaces; password operations remain local-only, and remote status access still requires an explicit trustedHosts entry");
	if (ctx.webServer?.host === "0.0.0.0" && ctx.credentials?.format === "plain") ctx.logger.warn?.("dsh-encrypt: the web server is bound to all interfaces while credentials are still PLAINTEXT; set a password before exposing the server to the network");
	ctx.effect(() => installLeakRedaction(ctx), "dsh-encrypt: leak-guard output redaction");
	const configuredChannel = ctx.credentials?.config?.rememberChannel ?? "cookie";
	const channelFor = (req) => requestUsesHeaderChannel(req, configuredChannel) ? "header" : "cookie";
	const trustedAccess = (req) => {
		if (!isTrustedRequest(req, trustedHosts)) throw new VaultError("FORBIDDEN_HOST", "this request's Host is not a trusted authority");
	};
	const routes = [
		{
			path: "/api/credentials.status",
			accessCheck: trustedAccess,
			operation: async (payload, req, cookies) => {
				parseEmptyRequest(payload);
				const local = isLocalRequest(req);
				const channel = channelFor(req);
				let ticketRejected = false;
				if (local) {
					const ticket = channel === "header" ? readRememberHeader(req) ?? readRememberCookie(req) : readRememberCookie(req);
					if (ticket !== void 0) try {
						await ctx.credentials.unlockWithRemember(ticket);
					} catch (error) {
						const code = error?.code;
						if (code === "REMEMBER_EXPIRED" || code === "REMEMBER_INVALID") {
							ctx.logger.warn?.("dsh-encrypt: remembered-login ticket rejected (%s); clearing it", code);
							cookies.clear();
							ticketRejected = true;
						} else if (code !== "VAULT_NOT_ENCRYPTED") throw error;
					}
				}
				return {
					...await ctx.credentials.status(),
					rememberChannel: channel,
					local,
					ticketRejected
				};
			}
		},
		{
			path: "/api/credentials.unlock",
			accessCheck: assertLocal,
			operation: async (payload, req, cookies) => {
				const request = parseDigestRequest(payload);
				return rememberedPasswordResult(await ctx.credentials.unlock(request.digest), await ctx.credentials.issueRemember(), cookies, channelFor(req));
			}
		},
		{
			path: "/api/credentials.set-password",
			accessCheck: assertLocal,
			operation: async (payload, req, cookies) => {
				const request = parseDigestRequest(payload);
				return rememberedPasswordResult(await ctx.credentials.setPassword(request.digest), await ctx.credentials.issueRemember(), cookies, channelFor(req));
			}
		},
		{
			path: "/api/credentials.change-password",
			accessCheck: assertLocal,
			operation: async (payload, req, cookies) => {
				const request = parseChangePasswordRequest(payload);
				cookies.clear();
				return rememberedPasswordResult(await ctx.credentials.changePassword(request.oldDigest, request.digest), await ctx.credentials.issueRemember(), cookies, channelFor(req));
			}
		},
		{
			path: "/api/credentials.config",
			accessCheck: trustedAccess,
			operation: async (payload, req, cookies) => {
				const request = parseConfigRequest(payload);
				const channel = channelFor(req);
				let ticket;
				if (request.action === "set") {
					assertLocal(req);
					const issued = await ctx.credentials.setRememberDays(request.rememberDays);
					if (issued !== null) {
						cookies.set(rememberCookieHeader(issued.secret, issued.days));
						ticket = issued.secret;
					} else cookies.clear();
				}
				const result = {
					...await ctx.credentials.status(),
					rememberChannel: channel,
					local: isLocalRequest(req)
				};
				if (request.action === "set") result.remembered = ticket !== void 0;
				if (channel === "header") result.ticket = ticket;
				return result;
			}
		}
	];
	for (const { path, operation, accessCheck } of routes) ctx.effect(() => ctx.webServer.register({
		kind: "exact",
		path,
		handler: jsonHandler(operation, ctx.logger, accessCheck)
	}), `dsh-encrypt: ${path}`);
}
//#endregion
export { Config, REMEMBER_CHANNEL_HEADER, REMEMBER_CHANNEL_HEADER_VALUE, REMEMBER_COOKIE, REMEMBER_TICKET_HEADER, apply, armSocketRedaction, clearRememberCookieHeader, inject, installLeakRedaction, isLocalRequest, name, readRememberCookie, readRememberHeader, redactingHttpHandler, redactingUpgradeRoute, rememberCookieHeader, requestUsesHeaderChannel };

//# sourceMappingURL=web.js.map