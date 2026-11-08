import { useEffect, useState } from 'react'
import { getAdminKey, getHealth, setAdminKey } from '../services/api'

export const TABS = [
  { id: 'playground', label: 'Playground' },
  { id: 'telemetry', label: 'Telemetry' },
  { id: 'policy', label: 'Policy Hub' },
  { id: 'audit', label: 'Audit Ledger' },
]

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
function AdminKeyField() {
  const [value, setValue] = useState(getAdminKey)

  return (
    <label className="inline-flex items-center gap-1.5 text-slate-400">
      <span className="hidden sm:inline">Admin key</span>
      <input
        type="password"
        autoComplete="off"
        value={value}
        onChange={(e) => {
          setValue(e.target.value)
          setAdminKey(e.target.value)
        }}
        placeholder="X-Admin-Key"
        aria-label="Admin key"
        className="w-32 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200 placeholder:text-slate-600 focus:border-sky-300/60 focus:outline-none"
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
      ? { text: 'Checking', dot: 'bg-slate-400', ring: 'ring-slate-500/30 text-slate-300' }
      : online
        ? { text: 'Online', dot: 'bg-emerald-400', ring: 'ring-emerald-400/30 text-emerald-300' }
        : { text: 'Offline', dot: 'bg-red-400', ring: 'ring-red-400/30 text-red-300' }

  return (
    <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-3 px-4 pt-3 sm:px-6">
        <div className="flex items-center gap-2.5 text-sky-300">
          <ShieldMark />
          <span className="text-lg font-semibold tracking-tight text-slate-100">NeMo-Shield</span>
          <span className="hidden text-sm text-slate-500 sm:inline">Guardrails console</span>
        </div>

        <div className="ml-auto flex items-center gap-2 text-xs">
          <AdminKeyField />
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 ring-1 ring-inset ${status.ring}`} role="status">
            <span className={`size-1.5 rounded-full ${status.dot} ${online ? 'animate-pulse' : ''}`} aria-hidden />
            {status.text}
          </span>
          <span className="rounded-full px-2.5 py-1 text-slate-300 ring-1 ring-inset ring-slate-700">
            NeMo v0.10+ <span className="text-slate-500">/</span> Colang 2.0
          </span>
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
                  active ? 'border-sky-300 text-slate-100' : 'border-transparent text-slate-400 hover:text-slate-200'
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
