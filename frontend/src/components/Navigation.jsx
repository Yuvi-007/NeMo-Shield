import { Monitor, Moon, Sun } from 'lucide-react'
import { useEffect, useState, useSyncExternalStore } from 'react'
import { getAdminKey, getAuthStatus, getHealth, setAdminKey, subscribeAuthStatus } from '../services/api'
import { getThemePreference, setThemePreference, subscribeTheme } from '../theme'
import { TABS } from '../tabs'
import { ADMIN_KEY_INPUT_ID } from './Toaster'

const THEME_OPTIONS = [
  { id: 'light', label: 'Light theme', Icon: Sun },
  { id: 'dark', label: 'Dark theme', Icon: Moon },
  { id: 'system', label: 'Match system theme', Icon: Monitor },
]

function ThemeToggle() {
  const preference = useSyncExternalStore(subscribeTheme, getThemePreference)

  return (
    <div role="radiogroup" aria-label="Color theme" className="inline-flex rounded-full p-0.5 ring-1 ring-inset ring-line-strong">
      {THEME_OPTIONS.map(({ id, label, Icon }) => {
        const active = preference === id
        return (
          <button
            key={id}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={label}
            title={label}
            onClick={() => setThemePreference(id)}
            className={`rounded-full p-1.5 transition-colors ${
              active ? 'bg-muted text-fg shadow-sm' : 'text-fg-subtle hover:text-fg-2'
            }`}
          >
            <Icon className="size-3.5" aria-hidden />
          </button>
        )
      })}
    </div>
  )
}

function ShieldMark() {
  return (
    <svg viewBox="0 0 24 24" className="size-6" aria-hidden>
      <path d="M12 2.5 4 5.5v6c0 4.6 3.3 8.6 8 10 4.7-1.4 8-5.4 8-10v-6l-8-3Z" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path d="M7.5 12h9" stroke="currentColor" strokeWidth="1.5" />
      <path d="M12 7.5v9" stroke="currentColor" strokeWidth="1.5" strokeOpacity=".45" />
    </svg>
  )
}

// Session-only admin key entry for /telemetry and /audit/logs. Never bundled.
// Saved on Enter or blur, not per keystroke: each save triggers a refetch, and
// partial keys would only produce 401s and burn the per-IP rate-limit budget.
const KEY_STATES = {
  accepted: { dot: 'text-ok-fg', ring: 'border-line-strong', text: 'Admin key accepted' },
  rejected: { dot: 'text-danger-fg', ring: 'border-danger/70', text: 'Admin key rejected (401)' },
  missing: { dot: 'text-warn-fg', ring: 'border-warn/70', text: 'Admin key required (401)' },
  unconfigured: { dot: 'text-warn-fg', ring: 'border-line-strong', text: 'Admin API disabled on the backend (503)' },
}

function AdminKeyField() {
  const [value, setValue] = useState(getAdminKey)
  const status = useSyncExternalStore(subscribeAuthStatus, getAuthStatus)
  const state = KEY_STATES[status]

  const save = () => {
    setAdminKey(value)
    setValue(getAdminKey())
  }

  return (
    <label className="inline-flex items-center gap-1.5 text-fg-muted">
      <span className="hidden sm:inline">Admin key</span>
      {state && (
        <span className={state.dot} title={state.text} aria-hidden>
          ●
        </span>
      )}
      {state && <span className="sr-only">{state.text}</span>}
      <input
        id={ADMIN_KEY_INPUT_ID}
        aria-invalid={status === 'rejected' || status === 'missing' ? true : undefined}
        type="password"
        autoComplete="off"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onBlur={save}
        onKeyDown={(e) => {
          if (e.key === 'Enter') save()
        }}
        title="Press Enter to apply"
        placeholder="X-Admin-Key"
        aria-label="Admin key"
        className={`w-32 rounded-md border ${state?.ring ?? 'border-line-strong'} bg-surface px-2 py-1 text-fg-2 placeholder:text-fg-faint focus:border-accent/60 focus:outline-none`}
      />
    </label>
  )
}

export default function Navigation({ activeTab, onTabChange }) {
  const [online, setOnline] = useState(null)

  useEffect(() => {
    let cancelled = false
    const check = () =>
      getHealth()
        .then((h) => !cancelled && setOnline(h?.status === 'healthy'))
        .catch(() => !cancelled && setOnline(false))
    check()
    const id = setInterval(check, 15000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  const status =
    online === null
      ? { text: 'Checking', dot: 'bg-fg-muted', ring: 'ring-fg-subtle/30 text-fg-3' }
      : online
        ? { text: 'Online', dot: 'bg-ok', ring: 'ring-ok/30 text-ok-fg' }
        : { text: 'Offline', dot: 'bg-danger', ring: 'ring-danger/30 text-danger-fg' }

  return (
    <header className="sticky top-0 z-20 border-b border-line bg-canvas/90 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-3 px-4 pt-3 sm:px-6">
        <div className="flex items-center gap-2.5 text-accent">
          <ShieldMark />
          <span className="text-lg font-semibold tracking-tight text-fg">NeMo-Shield</span>
          <span className="hidden text-sm text-fg-subtle sm:inline">Guardrails console</span>
        </div>

        <div className="ml-auto flex items-center gap-2 text-xs">
          <AdminKeyField />
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 ring-1 ring-inset ${status.ring}`} role="status">
            <span className={`size-1.5 rounded-full ${status.dot} ${online ? 'animate-pulse' : ''}`} aria-hidden />
            {status.text}
          </span>
          <span className="rounded-full px-2.5 py-1 text-fg-3 ring-1 ring-inset ring-line-strong">
            NeMo 0.24 <span className="text-fg-subtle">/</span> Colang 2.x
          </span>
          <ThemeToggle />
        </div>

        <nav className="-mb-px flex w-full gap-1 overflow-x-auto" aria-label="Console views">
          {TABS.map((tab) => {
            const active = tab.id === activeTab
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => onTabChange(tab.id)}
                aria-current={active ? 'page' : undefined}
                className={`whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium transition-colors ${
                  active ? 'border-accent text-fg' : 'border-transparent text-fg-muted hover:text-fg-2'
                }`}
              >
                {tab.label}
              </button>
            )
          })}
        </nav>
      </div>
    </header>
  )
}
