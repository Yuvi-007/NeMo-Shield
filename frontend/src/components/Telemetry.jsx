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
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-4">
      <p className="text-sm text-slate-400">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tracking-tight tabular-nums ${accent ?? 'text-slate-100'}`}>
        {value}
        {unit && <span className="ml-1 text-base font-normal text-slate-500">{unit}</span>}
      </p>
      {detail && <p className="mt-1 text-xs text-slate-500">{detail}</p>}
    </div>
  )
}

export default function Telemetry() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [updatedAt, setUpdatedAt] = useState(null)

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
          <p className="mt-1 text-sm text-slate-400">
            Aggregated from every guarded request in the audit ledger.
            {updatedAt && <span className="text-slate-500"> Updated {updatedAt.toLocaleTimeString()}.</span>}
          </p>
        </div>
        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          className="rounded-md border border-slate-700 px-3 py-2 text-sm text-slate-200 transition-colors hover:border-sky-300/60 disabled:opacity-50"
        >
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-red-400/40 bg-red-400/10 px-4 py-3 text-sm text-red-200">
          {error}
        </p>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Kpi label="Total requests" value={total.toLocaleString()} detail="Through /guard/chat" />
        <Kpi
          label="Block rate"
          value={(data?.block_rate_pct ?? 0).toFixed(1)}
          unit="%"
          accent="text-red-300"
          detail={`${data?.blocked_requests ?? 0} halted at the input rail`}
        />
        <Kpi
          label="Clean pass"
          value={cleanPct.toFixed(1)}
          unit="%"
          accent="text-emerald-300"
          detail={`${data?.altered_requests ?? 0} passed with redaction`}
        />
        <Kpi label="Avg latency" value={(data?.avg_latency_ms ?? 0).toFixed(1)} unit="ms" detail="End-to-end, rails included" />
      </div>

      <section className="rounded-lg border border-slate-800 bg-slate-900/40">
        <header className="flex flex-wrap items-baseline gap-2 border-b border-slate-800 px-4 py-3">
          <h2 className="mr-auto text-base font-semibold">Threats by OWASP LLM Top 10 (2025)</h2>
          <span className="text-xs text-slate-500 tabular-nums">{threatTotal} flagged requests</span>
        </header>

        <ul className="divide-y divide-slate-800/70">
          {OWASP_TOP_10.map((cat) => {
            const count = counts[cat.id]
            const share = threatTotal ? (count / threatTotal) * 100 : 0
            return (
              <li key={cat.id} className="grid grid-cols-[4rem_1fr] items-center gap-x-4 gap-y-1.5 px-4 py-2.5 sm:grid-cols-[4rem_16rem_1fr_5rem]">
                <span className="font-mono text-xs text-slate-500">{cat.id}</span>
                <span className={`text-sm ${cat.covered ? 'text-slate-200' : 'text-slate-500'}`}>
                  {cat.name}
                  {!cat.covered && <span className="ml-2 text-xs text-slate-600">no rail</span>}
                </span>
                <div
                  className="col-span-2 h-2 overflow-hidden rounded-full bg-slate-800 sm:col-span-1"
                  role="meter"
                  aria-label={`${cat.name} share`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={Math.round(share)}
                >
                  <div
                    className={`h-full rounded-full transition-[width] duration-500 ${cat.id === 'LLM02' ? 'bg-amber-400' : 'bg-red-400'}`}
                    style={{ width: `${(count / peak) * 100}%` }}
                  />
                </div>
                <span className="hidden text-right font-mono text-xs text-slate-400 tabular-nums sm:block">
                  {count} <span className="text-slate-600">· {share.toFixed(0)}%</span>
                </span>
              </li>
            )
          })}
        </ul>

        {other > 0 && (
          <p className="border-t border-slate-800 px-4 py-2.5 text-xs text-slate-500">
            {other} flagged requests carry a tag outside the OWASP list.
          </p>
        )}
        {!loading && threatTotal === 0 && !error && (
          <p className="border-t border-slate-800 px-4 py-3 text-sm text-slate-500">
            No threats recorded yet. Run an attack from the Playground, then refresh.
          </p>
        )}
      </section>
    </div>
  )
}
