import { CircleAlert, KeyRound, X } from 'lucide-react'
import { useEffect, useSyncExternalStore } from 'react'
import { subscribeAuthStatus } from '../services/api'
import { dismissToast, getToasts, pushToast, subscribeToasts } from '../services/toast'

export const ADMIN_KEY_INPUT_ID = 'admin-key-input'

function focusAdminKey() {
  const input = document.getElementById(ADMIN_KEY_INPUT_ID)
  input?.focus()
  input?.select()
}

const AUTH_TOASTS = {
  rejected: {
    tone: 'danger',
    title: '401 Unauthorized',
    body: 'The admin key was rejected. It must match ADMIN_API_KEY on the backend.',
    action: { label: 'Edit key', run: focusAdminKey },
  },
  missing: {
    tone: 'warn',
    title: 'Admin key required',
    body: 'Telemetry and the audit ledger need the X-Admin-Key header.',
    action: { label: 'Enter key', run: focusAdminKey },
  },
  unconfigured: {
    tone: 'warn',
    title: '503 Admin API disabled',
    body: 'ADMIN_API_KEY is not set on the backend, so admin routes fail closed. Set it and restart the server.',
  },
  accepted: { tone: 'ok', title: 'Admin key accepted' },
}

const FAILURES = new Set(['missing', 'rejected', 'unconfigured'])

const TONES = {
  danger: 'border-danger/50 text-danger-fg',
  warn: 'border-warn/50 text-warn-fg',
  ok: 'border-ok/50 text-ok-fg',
  info: 'border-line-strong text-fg-2',
}

/** Bottom-right toasts. Auth status changes from the API layer become toasts here. */
export default function Toaster() {
  const toasts = useSyncExternalStore(subscribeToasts, getToasts)

  // Status only fires on change, so a live-refreshing view that keeps getting 401 shows one toast.
  useEffect(() => {
    // Confirm a key only when it fixes an earlier failure; a routine success stays quiet.
    let failedSinceSuccess = false
    return subscribeAuthStatus((status) => {
      if (status === 'accepted') {
        if (!failedSinceSuccess) return
        failedSinceSuccess = false
      } else if (FAILURES.has(status)) {
        failedSinceSuccess = true
      }
      const toast = AUTH_TOASTS[status]
      if (toast) pushToast({ key: 'admin-auth', ...toast })
    })
  }, [])

  return (
    <div aria-live="assertive" className="pointer-events-none fixed inset-x-4 bottom-4 z-50 flex flex-col items-end gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          role={t.tone === 'danger' ? 'alert' : 'status'}
          className={`glass pointer-events-auto flex w-full max-w-sm animate-chip-in items-start gap-3 rounded-lg border px-4 py-3 shadow-lg ${TONES[t.tone] ?? TONES.info}`}
        >
          {t.tone === 'ok' ? (
            <KeyRound className="mt-0.5 size-4 shrink-0" aria-hidden />
          ) : (
            <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
          )}
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold">{t.title}</p>
            {t.body && <p className="mt-0.5 text-xs text-fg-muted">{t.body}</p>}
            {t.action && (
              <button
                type="button"
                onClick={() => {
                  t.action.run()
                  dismissToast(t.id)
                }}
                className="mt-2 rounded-md border border-current/40 px-2 py-0.5 text-xs font-medium hover:bg-muted"
              >
                {t.action.label}
              </button>
            )}
          </div>
          <button
            type="button"
            onClick={() => dismissToast(t.id)}
            aria-label="Dismiss notification"
            className="rounded p-0.5 text-fg-subtle hover:text-fg-2"
          >
            <X className="size-3.5" aria-hidden />
          </button>
        </div>
      ))}
    </div>
  )
}
