import { useCallback, useEffect, useState } from 'react'
import { describeError, getTelemetry, onAdminKeyChange } from '../services/api'

// OWASP Top 10 for LLM Applications (2025). `covered` marks categories an active rail reports on.
const OWASP_TOP_10 = [
  { id: 'LLM01', name: 'Prompt Injection', covered: true },
  { id: 'LLM02', name: 'Sensitive Information Disclosure', covered: true },
  { id: 'LLM03', name: 'Supply Chain', covered: false },
  { id: 'LLM04', name: 'Data and Model Poisoning', covered: false },
  { id: 'LLM05', name: 'Improper Output Handling', covered: false },
  { id: 'LLM06', name: 'Excessive Agency', covered: false },
  { id: 'LLM07', name: 'System Prompt Leakage', covered: false },
  { id: 'LLM08', name: 'Vector and Embedding Weaknesses', covered: false },
  { id: 'LLM09', name: 'Misinformation', covered: false },
  { id: 'LLM10', name: 'Unbounded Consumption', covered: false },
]

const LIVE_INTERVAL_MS = 15000

// Backend tags that do not carry an LLMxx code.
const TAG_ALIASES = { PII_LEAKAGE: 'LLM02' }

function owaspIdFor(tag) {
  return tag.match(/LLM\d{2}/)?.[0] ?? TAG_ALIASES[tag] ?? null
}

function bucketThreats(distribution = {}) {
  const counts = Object.fromEntries(OWASP_TOP_10.map((c) => [c.id, 0]))
  let other = 0
  for (const [tag, count] of Object.entries(distribution)) {
    const id = owaspIdFor(tag)
    if (id && id in counts) counts[id] += count
    else other += count
  }
  return { counts, other }
}

function Kpi({ label, value, unit, detail, accent }) {
  return (
    <div className="glass rounded-lg border border-line px-4 py-4">
      <p className="text-sm text-fg-muted">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tracking-tight tabular-nums ${accent ?? 'text-fg'}`}>
        {value}
        {unit && <span className="ml-1 text-base font-normal text-fg-subtle">{unit}</span>}
      </p>
      {detail && <p className="mt-1 text-xs text-fg-subtle">{detail}</p>}
    </div>
  )
}

export default function Telemetry() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [updatedAt, setUpdatedAt] = useState(null)
  const [live, setLive] = useState(false)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setData(await getTelemetry())
      setUpdatedAt(new Date())
    } catch (err) {
      setError(describeError(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  // Refetch as soon as an admin key is saved in the header.
  useEffect(() => onAdminKeyChange(refresh), [refresh])

  // Live mode: 4 requests/min while the tab is visible, well inside the 60/min per-IP budget.
  useEffect(() => {
    if (!live) return undefined
    const id = setInterval(() => {
      if (document.visibilityState === 'visible') refresh()
    }, LIVE_INTERVAL_MS)
    return () => clearInterval(id)
  }, [live, refresh])

  const total = data?.total_requests ?? 0
  const cleanPct = total ? (data.clean_requests / total) * 100 : 0
  const { counts, other } = bucketThreats(data?.threat_distribution)
  const threatTotal = Object.values(counts).reduce((a, b) => a + b, 0) + other
  const peak = Math.max(1, ...Object.values(counts), other)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end gap-4">
        <div className="mr-auto">
          <h1 className="text-2xl font-semibold tracking-tight">Telemetry</h1>
          <p className="mt-1 text-sm text-fg-muted">
            Aggregated from every guarded request in the audit ledger.
            {updatedAt && <span className="text-fg-subtle"> Updated {updatedAt.toLocaleTimeString()}.</span>}
          </p>
        </div>
        <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-fg-muted">
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} className="accent-accent" />
          Live
          {live && <span className="size-1.5 animate-pulse rounded-full bg-ok" aria-hidden />}
          <span className="sr-only">refresh every 15 seconds</span>
        </label>
        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          className="rounded-md border border-line-strong px-3 py-2 text-sm text-fg-2 transition-colors hover:border-accent/60 disabled:opacity-50"
        >
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger-fg">
          {error}
        </p>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Kpi label="Total requests" value={total.toLocaleString()} detail="Through /guard/chat" />
        <Kpi
          label="Block rate"
          value={(data?.block_rate_pct ?? 0).toFixed(1)}
          unit="%"
          accent="text-danger-fg"
          detail={`${data?.blocked_requests ?? 0} halted at the input rail`}
        />
        <Kpi
          label="Clean pass"
          value={cleanPct.toFixed(1)}
          unit="%"
          accent="text-ok-fg"
          detail={`${data?.altered_requests ?? 0} passed with redaction`}
        />
        <Kpi label="Avg latency" value={(data?.avg_latency_ms ?? 0).toFixed(1)} unit="ms" detail="End-to-end, rails included" />
      </div>

      <section className="glass rounded-lg border border-line">
        <header className="flex flex-wrap items-baseline gap-2 border-b border-line px-4 py-3">
          <h2 className="mr-auto text-base font-semibold">Threats by OWASP LLM Top 10 (2025)</h2>
          <span className="text-xs text-fg-subtle tabular-nums">{threatTotal} flagged requests</span>
        </header>

        <ul className="divide-y divide-line/70">
          {OWASP_TOP_10.map((cat) => {
            const count = counts[cat.id]
            const share = threatTotal ? (count / threatTotal) * 100 : 0
            return (
              <li key={cat.id} className="grid grid-cols-[4rem_1fr] items-center gap-x-4 gap-y-1.5 px-4 py-2.5 sm:grid-cols-[4rem_16rem_1fr_5rem]">
                <span className="font-mono text-xs text-fg-subtle">{cat.id}</span>
                <span className={`text-sm ${cat.covered ? 'text-fg-2' : 'text-fg-subtle'}`}>
                  {cat.name}
                  {!cat.covered && <span className="ml-2 text-xs text-fg-subtle">no rail</span>}
                </span>
                <div
                  className="col-span-2 h-2 overflow-hidden rounded-full bg-muted sm:col-span-1"
                  role="meter"
                  aria-label={`${cat.name} share`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={Math.round(share)}
                >
                  <div
                    className={`h-full rounded-full transition-[width] duration-500 ${cat.id === 'LLM02' ? 'bg-warn' : 'bg-danger'}`}
                    style={{ width: `${(count / peak) * 100}%` }}
                  />
                </div>
                <span className="hidden text-right font-mono text-xs text-fg-muted tabular-nums sm:block">
                  {count} <span className="text-fg-subtle">· {share.toFixed(0)}%</span>
                </span>
              </li>
            )
          })}
        </ul>

        {other > 0 && (
          <p className="border-t border-line px-4 py-2.5 text-xs text-fg-subtle">
            {other} flagged requests carry a tag outside the OWASP list.
          </p>
        )}
        {!loading && threatTotal === 0 && !error && (
          <p className="border-t border-line px-4 py-3 text-sm text-fg-subtle">
            No threats recorded yet. Run an attack from the Playground, then refresh.
          </p>
        )}
      </section>
    </div>
  )
}
