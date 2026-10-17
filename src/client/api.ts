export interface ApiValue {
  [key: string]: unknown
  format?: 'plain' | 'encrypted'
  unlocked?: boolean
  local?: boolean
  plaintextForbidden?: boolean
  rememberChannel?: string
  remembered?: boolean
  ticketRejected?: boolean
  ticket?: string
  remember?: { active?: boolean; days?: number; expiresAt?: number | null }
  lockout?: { retryAfterMs?: number }
}

export interface ApiBody {
  ok: boolean
  code?: string
  message?: string
  value?: ApiValue
}

const TICKET_KEY = 'dsh-encrypt-remember'
/** Request header carrying the ticket on the localStorage-backed channel. */
const TICKET_HEADER = 'x-dsh-encrypt-remember'
/** Request header opting one request into the localStorage-backed channel. */
const CHANNEL_HEADER = 'x-dsh-encrypt-remember-channel'

/**
 * Whether this page runs on a carrier that cannot keep the HttpOnly ticket
 * cookie. The dsh desktop shell serves the WebUI from the `dsh-app:` scheme:
 * it swaps every request Cookie for its own Host authentication cookie and
 * withholds Set-Cookie from responses, so the remembered-login ticket has to
 * travel in localStorage plus an explicit request header instead.
 */
export function browserUsesHeaderChannel(): boolean {
  if (typeof location === 'undefined') return false
  const protocol: unknown = location.protocol
  return typeof protocol === 'string' && protocol !== 'http:' && protocol !== 'https:'
}

/** Send one same-origin JSON request with the optional header ticket. */
export async function apiPost(path: string, payload: Record<string, unknown> = {}): Promise<ApiBody> {
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  const ticket = storedTicket()
  if (ticket !== null) headers[TICKET_HEADER] = ticket
  // Ask the host for the header channel when cookies cannot survive here; the
  // host then returns the ticket in the response body instead of relying on
  // Set-Cookie, and accepts the header ticket on the next boot.
  if (browserUsesHeaderChannel()) headers[CHANNEL_HEADER] = 'header'
  const response = await fetch(path, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  })
  return (await response.json()) as ApiBody
}

/** Synchronize the explicit header ticket after an API response. */
export function syncTicket(body: ApiBody): void {
  if (body.ok !== true) return
  const value = body.value ?? {}
  if (value.rememberChannel !== 'header') {
    storeTicket(null)
    return
  }
  if (typeof value.ticket === 'string' && value.ticket.length > 0) storeTicket(value.ticket)
  else if (value.remembered === false) storeTicket(null)
}

/** Remove an explicit remembered-login ticket. */
export function clearStoredTicket(): void {
  storeTicket(null)
}

function storedTicket(): string | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage.getItem(TICKET_KEY)
  } catch {
    return null
  }
}

function storeTicket(ticket: string | null): void {
  try {
    if (typeof localStorage === 'undefined') return
    if (typeof ticket === 'string' && ticket.length > 0) localStorage.setItem(TICKET_KEY, ticket)
    else localStorage.removeItem(TICKET_KEY)
  } catch {}
}
