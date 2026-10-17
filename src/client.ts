import type { ApiValue } from './client/api.js'
import { apiPost, clearStoredTicket, syncTicket } from './client/api.js'
import { daysFromSlider, expiryText, rememberLabel, SLIDER_MAX, sliderFromDays } from './client/settings-model.js'
import { sha3_256Hex } from './client/sha3.js'

type ReactModule = typeof import('react')

interface ClientPlugin {
  apply: (ctx: ClientContext) => void
  inject: string[]
  digestPassword: (text: string) => string
}

interface ClientConnectionState {
  getSnapshot?: () => unknown
  subscribe?: (listener: () => void) => unknown
}

interface ClientConnection {
  state?: ClientConnectionState
}

interface ClientContext {
  slots: {
    inject: (slot: string, callback: () => unknown) => unknown
    register: (
      options: Record<string, unknown>,
      component: (props: Record<string, unknown>) => React.ReactNode,
    ) => unknown
  }
  /** Cordis service injection, when the host client kernel provides it. */
  inject?: (deps: string[], callback: (scope: ClientContext & { connection?: ClientConnection }) => void) => unknown
  /** Cordis effect scope (returns a disposer), when the client kernel provides it. */
  effect?: (run: () => () => void, label: string) => unknown
}

interface ModuleLoaderWindow {
  __ModuleLoader__: {
    load: (spec: { id: string; factory: (require: (name: string) => unknown) => ClientPlugin }) => void
  }
}

interface EncryptionStatus extends ApiValue {
  format: 'plain' | 'encrypted'
  unlocked: boolean
  local: boolean
}

interface FieldProps {
  placeholder: string
  value: string
  disabled: boolean
  onChange: (value: string) => void
}

interface ButtonProps {
  disabled: boolean
  onClick: () => void
  children?: React.ReactNode
}

;(window as unknown as ModuleLoaderWindow).__ModuleLoader__.load({
  id: 'dsh-encrypt',
  factory: (require: (name: string) => unknown) => {
    const module: { exports: Partial<ClientPlugin> } = { exports: {} }
    const exports = module.exports
    const React = require('react') as ReactModule
    //#region lib/client.js
    /**
     * Settings → 加密安全: the browser surface for dsh-encrypt's password
     * lifecycle. Talks to the host over the exact routes the `dsh-encrypt/web`
     * row registers. The raw password never crosses the wire: this bundle
     * derives its SHA3-256 digest (pure JS, Keccak-f[1600]) and POSTs only
     * `{ digest }`.
     *
     * Remembered logins: a slider sets how long a localhost unlock stays
     * valid without the password — 0 = every time, 1..30 days, forever.
     * The server issues the ticket in an HttpOnly cookie on ordinary
     * http(s) pages; on carriers that cannot keep cookies (the dsh desktop
     * shell serves this UI from the `dsh-app:` scheme and replaces every
     * request Cookie) the ticket travels in localStorage plus an explicit
     * request header instead, and this bundle retries the status probe on
     * load, focus, reconnect, and with backoff while the Host is booting.
     * Non-localhost visits always require the password and cannot modify it.
     *
     * States:
     *   plain              — no password set; credentials sit as plaintext
     *                        YAML. Form: set the first password (typed twice).
     *   encrypted+locked   — a password protects the file but this dsh
     *                        process has not unlocked it (restart). Form:
     *                        enter the password to unlock.
     *   encrypted+unlocked — the store is unlocked. Forms: change the
     *                        password, or remove it (back to plaintext).
     * @module dsh-encrypt/client
     */
    const LABEL = { color: 'var(--dsw-alias-label-primary)', fontSize: 14, lineHeight: '22px', margin: 0 }
    const HINT = { color: 'var(--dsw-alias-label-tertiary)', fontSize: 12, lineHeight: '18px', margin: '8px 0 0' }
    const WARN = { color: 'var(--dsw-alias-state-warn-label)', fontSize: 12, lineHeight: '18px', margin: '8px 0 0' }
    const OK = { color: 'var(--dsw-alias-state-success-primary)', fontSize: 12, lineHeight: '18px', margin: '8px 0 0' }
    const FIELD = {
      boxSizing: 'border-box',
      width: '100%',
      height: 36,
      margin: '4px 0 0',
      padding: '0 12px',
      border: '1px solid var(--dsw-alias-border-l2)',
      borderRadius: 18,
      background: 'var(--dsw-alias-fill-primary)',
      color: 'var(--dsw-alias-label-primary)',
      font: 'inherit',
      fontSize: 14,
      outline: 'none',
    }
    const BUTTON = {
      boxSizing: 'border-box',
      height: 36,
      padding: '0 14px',
      margin: '12px 0 0',
      border: 'none',
      borderRadius: 18,
      cursor: 'pointer',
      font: 'inherit',
      fontSize: 14,
      background: 'var(--dsw-alias-button-primary-fill)',
      color: 'var(--dsw-alias-label-primary-foreground)',
    }
    const CARD = {
      border: '1px solid var(--dsw-alias-border-l2)',
      borderRadius: 12,
      padding: '14px 16px',
      margin: '12px 0 0',
    }
    const ROW = { display: 'flex', flexDirection: 'column', gap: 12, margin: 0 }
    const SLIDER = {
      width: '100%',
      margin: '10px 0 0',
      cursor: 'pointer',
      accentColor: 'var(--dsw-alias-button-primary-fill)',
    }
    const SLIDER_MARKS = {
      display: 'flex',
      justifyContent: 'space-between',
      fontSize: 11,
      color: 'var(--dsw-alias-label-tertiary)',
      margin: '4px 0 0',
    }

    function Field(props: FieldProps): React.ReactNode {
      return React.createElement('input', {
        type: 'password',
        placeholder: props.placeholder,
        value: props.value,
        disabled: props.disabled,
        onChange: (event: React.ChangeEvent<HTMLInputElement>) => props.onChange(event.target.value),
        style: FIELD,
      })
    }
    function Button(props: ButtonProps): React.ReactNode {
      return React.createElement(
        'button',
        {
          type: 'button',
          disabled: props.disabled,
          onClick: props.onClick,
          style: { ...BUTTON, opacity: props.disabled ? 0.5 : 1 },
        },
        props.children,
      )
    }

    // ── auto-unlock when the WebUI opens or reconnects ───────────────────
    // The remembered login only applies to localhost. The status route is what
    // consumes the browser-held ticket, so this bundle pings it as soon as the
    // page loads and retries with backoff while the Host is still booting or a
    // transient transport failure intervenes (the desktop shell can serve the
    // document before the Host answers, or restart the Host under an open page).
    const PING_RETRY_DELAYS_MS = [1_000, 2_000, 4_000, 8_000, 15_000, 30_000] as const
    let pingInFlight = false
    let pingAgain = false
    let pingRetryTimer: ReturnType<typeof setTimeout> | undefined
    let pingRetryIndex = 0

    function cancelPingRetry(): void {
      if (pingRetryTimer !== undefined) {
        clearTimeout(pingRetryTimer)
        pingRetryTimer = undefined
      }
    }

    function schedulePingRetry(): void {
      if (pingRetryTimer !== undefined) return
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
      const delay = PING_RETRY_DELAYS_MS[Math.min(pingRetryIndex, PING_RETRY_DELAYS_MS.length - 1)]
      pingRetryIndex += 1
      pingRetryTimer = setTimeout(() => {
        pingRetryTimer = undefined
        void pingStatus()
      }, delay)
    }

    /** One status ping: consumes the remembered-login ticket and records its verdict. */
    async function pingStatus(): Promise<void> {
      if (pingInFlight) return
      pingInFlight = true
      try {
        const body = await apiPost('/api/credentials.status')
        if (body.ok !== true || body.value === undefined) {
          // The Host answered, so retrying a rejection cannot help; only a
          // transport failure (no JSON body at all) is worth another attempt.
          cancelPingRetry()
          return
        }
        // Cookie mode drops stale localStorage copies. The header channel
        // keeps its ticket: it is the only carrier this page has.
        if (body.value.ticketRejected === true || body.value.rememberChannel !== 'header') clearStoredTicket()
        pingRetryIndex = 0
        cancelPingRetry()
      } catch {
        schedulePingRetry()
      } finally {
        pingInFlight = false
        if (pingAgain) {
          pingAgain = false
          void pingStatus()
        }
      }
    }

    function retryNow(): void {
      pingRetryIndex = 0
      cancelPingRetry()
      if (pingInFlight) {
        pingAgain = true
        return
      }
      void pingStatus()
    }

    // Cordis reconnect hook: the dsh desktop shell keeps the page alive across
    // Host process restarts, so a fresh "connected" generation is the moment
    // to consume the remembered login again. The service may be absent in
    // older or non-web client kernels, so everything is optional.
    function watchClientConnection(ctx: ClientContext): void {
      try {
        ctx.inject?.(['connection'], scope => {
          const state = scope.connection?.state
          if (state?.subscribe === undefined || state.getSnapshot === undefined) return
          let previous = state.getSnapshot()
          // Return the unsubscribe so a replaced Connection service (or an
          // unloaded plugin) does not leave the listener behind.
          return state.subscribe(() => {
            const next = state.getSnapshot?.()
            if (next === 'connected' && previous !== 'connected') retryNow()
            previous = next
          })
        })
      } catch {
        // No connection service to watch; load/focus/visibility still trigger.
      }
    }

    // Page triggers: the first paint/unlock attempt, bfcache restore, and the
    // visible/focused transitions that follow a Host restart. Returning a
    // disposer keeps HMR (and re-enable) from stacking duplicate listeners.
    function installAutoUnlock(): () => void {
      if (typeof window === 'undefined' || typeof document === 'undefined' || typeof fetch !== 'function') {
        return () => {}
      }
      const onLoad = (): void => void pingStatus()
      const onPageShow = (): void => retryNow()
      const onFocus = (): void => retryNow()
      const onVisibility = (): void => {
        if (document.visibilityState === 'visible') retryNow()
        else cancelPingRetry()
      }
      const onPageHide = (): void => cancelPingRetry()
      void pingStatus()
      if (document.readyState !== 'complete') window.addEventListener('load', onLoad, { once: true })
      window.addEventListener('pageshow', onPageShow)
      window.addEventListener('focus', onFocus)
      window.addEventListener('pagehide', onPageHide)
      document.addEventListener('visibilitychange', onVisibility)
      return () => {
        window.removeEventListener('load', onLoad)
        window.removeEventListener('pageshow', onPageShow)
        window.removeEventListener('focus', onFocus)
        window.removeEventListener('pagehide', onPageHide)
        document.removeEventListener('visibilitychange', onVisibility)
        cancelPingRetry()
      }
    }

    function EncryptionSection(_props: Record<string, unknown>): React.ReactNode {
      const [status, setStatus] = React.useState<EncryptionStatus | undefined>(void 0)
      const [busy, setBusy] = React.useState(false)
      const [failure, setFailure] = React.useState<string | undefined>(void 0)
      const [notice, setNotice] = React.useState<string | undefined>(void 0)
      const [first, setFirst] = React.useState('')
      const [second, setSecond] = React.useState('')
      const [unlockPw, setUnlockPw] = React.useState('')
      const [oldPw, setOldPw] = React.useState('')
      const [slider, setSlider] = React.useState(0)

      const refresh = React.useCallback(async () => {
        try {
          const body = await apiPost('/api/credentials.status')
          if (!body.ok || body.value === void 0) throw new Error(body.message ?? body.code ?? 'request failed')
          if (body.value.ticketRejected || body.value.rememberChannel !== 'header') clearStoredTicket()
          setStatus(body.value as EncryptionStatus)
          setSlider(sliderFromDays(body.value.remember?.days))
          setFailure(void 0)
        } catch (error) {
          setFailure(error instanceof Error ? error.message : String(error))
        }
      }, [])
      React.useEffect(() => {
        void refresh()
      }, [refresh])

      const run = async (path: string, payload: Record<string, unknown>, done?: string): Promise<void> => {
        setBusy(true)
        setFailure(void 0)
        setNotice(void 0)
        try {
          const body = await apiPost(path, payload)
          if (!body.ok) throw new Error(body.message ?? body.code ?? 'request failed')
          syncTicket(body)
          setFirst('')
          setSecond('')
          setUnlockPw('')
          setOldPw('')
          await refresh()
          if (done !== void 0) setNotice(done)
        } catch (error) {
          setFailure(error instanceof Error ? error.message : String(error))
        } finally {
          setBusy(false)
        }
      }

      const saveSlider = async (raw: string): Promise<void> => {
        setBusy(true)
        setFailure(void 0)
        try {
          const body = await apiPost('/api/credentials.config', {
            action: 'set',
            rememberDays: daysFromSlider(Number(raw)),
          })
          if (!body.ok) throw new Error(body.message ?? body.code ?? 'request failed')
          syncTicket(body)
          await refresh()
        } catch (error) {
          setFailure(error instanceof Error ? error.message : String(error))
        } finally {
          setBusy(false)
        }
      }

      const doublePassword = first.length > 0 && first === second && first.length >= 8
      const passwordHint =
        first.length > 0 && first.length < 8
          ? '密码至少 8 个字符'
          : first.length > 0 && second.length > 0 && first !== second
            ? '两次输入的密码不一致'
            : void 0

      if (status === void 0) {
        return React.createElement('p', { style: HINT }, '读取加密状态…')
      }
      const { format, unlocked, local, remember, lockout } = status
      const retryAfterMs = lockout?.retryAfterMs ?? 0
      const lockSeconds = retryAfterMs > 0 ? Math.max(1, Math.ceil(retryAfterMs / 1000)) : 0

      const localBanner = !local
        ? React.createElement(
            'p',
            { key: 'nl', style: WARN },
            '当前不是本机访问：必须每次输入密码解锁，且不能设置、修改或移除密码。',
          )
        : null

      const sliderCard = React.createElement('div', { key: 'slider', style: CARD }, [
        React.createElement('p', { key: 't', style: LABEL }, '免密登录时长（仅本机生效）'),
        React.createElement('input', {
          key: 's',
          type: 'range',
          min: 0,
          max: SLIDER_MAX,
          step: 1,
          value: slider,
          disabled: busy || !local,
          onChange: (event: React.ChangeEvent<HTMLInputElement>) => setSlider(Number(event.currentTarget.value)),
          onPointerUp: (event: React.PointerEvent<HTMLInputElement>) => void saveSlider(event.currentTarget.value),
          onKeyUp: (event: React.KeyboardEvent<HTMLInputElement>) => {
            if (['ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'].includes(event.key))
              void saveSlider(event.currentTarget.value)
          },
          style: { ...SLIDER, opacity: !local ? 0.5 : 1 },
        }),
        React.createElement('p', { key: 'v', style: LABEL }, rememberLabel(slider)),
        React.createElement('div', { key: 'm', style: SLIDER_MARKS }, [
          React.createElement('span', { key: 'a' }, '每次'),
          React.createElement('span', { key: 'e' }, '永远'),
        ]),
        !local
          ? React.createElement('p', { key: 'n', style: HINT }, '非本机访问始终需要输入密码。')
          : remember?.active
            ? React.createElement(
                'p',
                { key: 'n', style: OK },
                typeof remember.expiresAt === 'number'
                  ? `免密登录生效中，到期时间：${expiryText(remember.expiresAt)}`
                  : '免密登录生效中，永不过期。',
              )
            : React.createElement(
                'p',
                { key: 'n', style: HINT },
                format === 'plain'
                  ? '设置加密密码后生效：按滑块时长在本机签发免密票据。'
                  : '解锁后按滑块时长在本机签发免密票据。',
              ),
      ])

      if (format === 'plain') {
        return React.createElement('div', { style: ROW }, [
          localBanner,
          status.plaintextForbidden
            ? React.createElement(
                'p',
                { key: 'forbidden', style: WARN },
                '警告：凭证文件被人替换成了明文，而密文策略已生效——凭证解析已暂停。请在下方重新设置加密密码，文件将立即恢复为密文。',
              )
            : null,
          React.createElement(
            'p',
            { key: 'intro', style: LABEL },
            '当前凭证以明文存储在 .credentials.yaml 中。设置密码后，同一文件的内容会被替换为 AES-256-GCM 密文（SHA3-256 完整性校验），每次模型调用时临时解密。',
          ),
          local
            ? React.createElement('div', { key: 'card', style: CARD }, [
                React.createElement('p', { key: 't', style: LABEL }, '设置加密密码'),
                React.createElement(Field, {
                  key: 'f1',
                  placeholder: '新密码（至少 8 个字符）',
                  value: first,
                  disabled: busy,
                  onChange: setFirst,
                }),
                React.createElement(Field, {
                  key: 'f2',
                  placeholder: '再次输入新密码',
                  value: second,
                  disabled: busy,
                  onChange: setSecond,
                }),
                passwordHint !== void 0 ? React.createElement('p', { key: 'h', style: WARN }, passwordHint) : null,
                React.createElement(
                  Button,
                  {
                    key: 'b',
                    disabled: busy || !doublePassword,
                    onClick: () =>
                      void run(
                        '/api/credentials.set-password',
                        { digest: sha3_256Hex(first) },
                        '密码已设置，凭证已加密保存',
                      ),
                  },
                  '加密并保存',
                ),
                React.createElement(
                  'p',
                  { key: 'n', style: HINT },
                  '设置后重启 dsh 需要重新输入密码解锁（本设置页即是解锁入口）。忘记密码只能清除凭证重新配置。',
                ),
              ])
            : null,
          sliderCard,
          failure !== void 0 ? React.createElement('p', { key: 'err', style: WARN }, failure) : null,
          notice !== void 0 ? React.createElement('p', { key: 'ok', style: OK }, notice) : null,
        ])
      }
      if (!unlocked) {
        return React.createElement('div', { style: ROW }, [
          localBanner,
          lockSeconds > 0
            ? React.createElement(
                'p',
                { key: 'lockout', style: WARN },
                `解锁尝试次数过多，已临时锁定：请在 ${lockSeconds} 秒后重试（连续失败会自动延长锁定时间）。`,
              )
            : null,
          React.createElement(
            'p',
            { key: 'intro', style: WARN },
            '凭证库已加密但处于锁定状态——模型调用暂时不可用。输入密码解锁后立即恢复。',
          ),
          React.createElement('div', { key: 'card', style: CARD }, [
            React.createElement(Field, {
              key: 'f',
              placeholder: '凭证库密码',
              value: unlockPw,
              disabled: busy || lockSeconds > 0,
              onChange: setUnlockPw,
            }),
            React.createElement(
              Button,
              {
                key: 'b',
                disabled: busy || unlockPw.length === 0 || lockSeconds > 0,
                onClick: () => void run('/api/credentials.unlock', { digest: sha3_256Hex(unlockPw) }, '已解锁'),
              },
              '解锁',
            ),
          ]),
          sliderCard,
          failure !== void 0 ? React.createElement('p', { key: 'err', style: WARN }, failure) : null,
          notice !== void 0 ? React.createElement('p', { key: 'ok', style: OK }, notice) : null,
        ])
      }
      return React.createElement('div', { style: ROW }, [
        localBanner,
        React.createElement('p', { key: 'intro', style: OK }, '凭证已加密且当前进程已解锁。'),
        local
          ? React.createElement('div', { key: 'card', style: CARD }, [
              React.createElement('p', { key: 't', style: LABEL }, '修改密码'),
              React.createElement(Field, {
                key: 'f0',
                placeholder: '当前密码',
                value: oldPw,
                disabled: busy,
                onChange: setOldPw,
              }),
              React.createElement(Field, {
                key: 'f1',
                placeholder: '新密码（至少 8 个字符）',
                value: first,
                disabled: busy,
                onChange: setFirst,
              }),
              React.createElement(Field, {
                key: 'f2',
                placeholder: '再次输入新密码',
                value: second,
                disabled: busy,
                onChange: setSecond,
              }),
              passwordHint !== void 0 ? React.createElement('p', { key: 'h', style: WARN }, passwordHint) : null,
              React.createElement(
                Button,
                {
                  key: 'b',
                  disabled: busy || !doublePassword || oldPw.length === 0,
                  onClick: () =>
                    void run(
                      '/api/credentials.change-password',
                      { digest: sha3_256Hex(first), oldDigest: sha3_256Hex(oldPw) },
                      '密码已修改',
                    ),
                },
                '修改密码',
              ),
            ])
          : null,
        sliderCard,
        failure !== void 0 ? React.createElement('p', { key: 'err', style: WARN }, failure) : null,
        notice !== void 0 ? React.createElement('p', { key: 'ok', style: OK }, notice) : null,
      ])
    }
    //#endregion
    const inject = ['slots']
    function apply(ctx: ClientContext): void {
      if (typeof ctx.effect === 'function') ctx.effect(installAutoUnlock, 'dsh-encrypt: remembered-login auto-unlock')
      else installAutoUnlock()
      watchClientConnection(ctx)
      ctx.slots.inject('settings.section', () =>
        ctx.slots.register(
          {
            name: 'settings.section',
            id: 'encryption',
            order: 1,
            label: () => '加密安全',
          },
          EncryptionSection,
        ),
      )
    }
    exports.apply = apply
    exports.inject = inject
    exports.digestPassword = sha3_256Hex
    return module.exports as ClientPlugin
  },
})
