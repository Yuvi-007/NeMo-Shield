import { KeyRound, ServerCrash, ShieldAlert } from 'lucide-react'
import { describeError, errorKind } from '../services/api'
import { ADMIN_KEY_INPUT_ID } from './Toaster'

function focusAdminKey() {
  const input = document.getElementById(ADMIN_KEY_INPUT_ID)
  input?.focus()
  input?.select()
}

const VARIANTS = {
  unauthorized: { Icon: KeyRound, title: '401 Unauthorized', tone: 'border-danger/40 bg-danger/10 text-danger-fg', keyAction: true },
  unconfigured: { Icon: ShieldAlert, title: '503 Admin API not configured', tone: 'border-warn/40 bg-warn/10 text-warn-fg' },
  malformed: { Icon: ServerCrash, title: 'Unexpected response', tone: 'border-danger/40 bg-danger/10 text-danger-fg' },
  server: { Icon: ServerCrash, title: 'Gateway unavailable', tone: 'border-danger/40 bg-danger/10 text-danger-fg' },
}

/** Error state for admin views: explains 401/503 and offers the fix instead of a bare message. */
export default function AdminErrorBanner({ error, onRetry }) {
  if (!error) return null
  const kind = errorKind(error)
  const variant = VARIANTS[kind] ?? { Icon: ServerCrash, title: 'Request failed', tone: 'border-danger/40 bg-danger/10 text-danger-fg' }
  const { Icon } = variant

  return (
    <div role="alert" className={`flex flex-wrap items-start gap-3 rounded-md border px-4 py-3 ${variant.tone}`}>
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold">{variant.title}</p>
        <p className="mt-0.5 text-sm text-fg-muted">{describeError(error)}</p>
      </div>
      <div className="flex gap-2">
        {variant.keyAction && (
          <button
            type="button"
            onClick={focusAdminKey}
            className="rounded-md border border-current/40 px-2.5 py-1 text-xs font-medium hover:bg-muted"
          >
            Enter admin key
          </button>
        )}
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="rounded-md border border-line-strong px-2.5 py-1 text-xs text-fg-2 hover:border-accent/60"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  )
}
