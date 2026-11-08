import { useCallback, useEffect, useState } from 'react'
import { describeError, getAuditLogs } from '../services/api'
import VerdictChip from './VerdictChip'

const FILTERS = [
  { id: 'ALL', label: 'All' },
  { id: 'INPUT_BLOCKED', label: 'Input blocked' },
  { id: 'ALLOWED', label: 'Allowed' },
  { id: 'OUTPUT_ALTERED', label: 'Output altered' },
]

const PAGE_SIZE = 100

function snippet(text, max = 90) {
  if (!text) return ''
  return text.length > max ? `${text.slice(0, max).trimEnd()}…` : text
}

function formatTimestamp(iso) {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

function exportJson(records, filter) {
  const payload = {
    exported_at: new Date().toISOString(),
    filter,
    count: records.length,
    records,
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `nemo-shield-audit-${filter.toLowerCase()}-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export default function AuditLedger() {
  const [filter, setFilter] = useState('ALL')
  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async (verdict) => {
    setLoading(true)
    setError(null)
    try {
      setRecords(await getAuditLogs(PAGE_SIZE, 0, verdict === 'ALL' ? null : verdict))
    } catch (err) {
      setError(describeError(err))
      setRecords([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(filter)
  }, [filter, load])

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end gap-4">
        <div className="mr-auto">
          <h1 className="text-2xl font-semibold tracking-tight">Audit ledger</h1>
          <p className="mt-1 text-sm text-slate-400">The most recent {PAGE_SIZE} guarded requests, newest first.</p>
        </div>
        <button
          type="button"
          onClick={() => load(filter)}
          disabled={loading}
          className="rounded-md border border-slate-700 px-3 py-2 text-sm text-slate-200 transition-colors hover:border-sky-300/60 disabled:opacity-50"
        >
          Reload
        </button>
        <button
          type="button"
          onClick={() => exportJson(records, filter)}
          disabled={!records.length}
          className="rounded-md bg-sky-300 px-3 py-2 text-sm font-semibold text-slate-950 transition-colors hover:bg-sky-200 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
        >
          Export Audit JSON
        </button>
      </div>

      <div role="radiogroup" aria-label="Filter by verdict" className="flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.id}
            type="button"
            role="radio"
            aria-checked={filter === f.id}
            onClick={() => setFilter(f.id)}
            className={`rounded-md px-3 py-1.5 font-mono text-xs transition-colors ${
              filter === f.id
                ? 'bg-slate-100 text-slate-950'
                : 'text-slate-400 ring-1 ring-inset ring-slate-700 hover:text-slate-200'
            }`}
            title={f.label}
          >
            {f.id}
          </button>
        ))}
        <span className="ml-auto self-center text-xs text-slate-500 tabular-nums">
          {loading ? 'Loading…' : `${records.length} records`}
        </span>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-red-400/40 bg-red-400/10 px-4 py-3 text-sm text-red-200">
          {error}
        </p>
      )}

      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full min-w-[56rem] border-collapse text-left text-[13px]">
          <thead className="bg-slate-900 text-xs text-slate-400">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Timestamp</th>
              <th scope="col" className="px-3 py-2 font-medium">Prompt</th>
              <th scope="col" className="px-3 py-2 font-medium">Reply</th>
              <th scope="col" className="px-3 py-2 font-medium">Verdict</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {records.map((r) => (
              <tr key={r.id} className="align-top hover:bg-slate-900/60">
                <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-400 tabular-nums" title={r.timestamp}>
                  {formatTimestamp(r.timestamp)}
                </td>
                <td className="max-w-xs px-3 py-2 font-mono text-xs text-slate-200" title={r.prompt}>
                  {snippet(r.prompt)}
                </td>
                <td className="max-w-xs px-3 py-2 font-mono text-xs text-slate-400" title={r.reply}>
                  {snippet(r.reply)}
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <VerdictChip verdict={r.verdict} title={r.threat_category ?? r.verdict} />
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-right font-mono text-xs text-slate-300 tabular-nums">
                  {r.latency_ms.toFixed(1)} ms
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!loading && !error && records.length === 0 && (
          <p className="px-4 py-10 text-center text-sm text-slate-500">
            {filter === 'ALL'
              ? 'No requests logged yet. Send a prompt from the Playground to create the first entry.'
              : `No ${filter} records. Choose another filter or run a matching prompt.`}
          </p>
        )}
      </div>
    </div>
  )
}
