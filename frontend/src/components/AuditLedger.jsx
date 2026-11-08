import { useCallback, useEffect, useState } from 'react'
import { describeError, getAuditLogs, onAdminKeyChange } from '../services/api'
import CopyButton from './CopyButton'
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

  // Refetch as soon as an admin key is saved in the header.
  useEffect(() => onAdminKeyChange(() => load(filter)), [filter, load])

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end gap-4">
        <div className="mr-auto">
          <h1 className="text-2xl font-semibold tracking-tight">Audit ledger</h1>
          <p className="mt-1 text-sm text-fg-muted">The most recent {PAGE_SIZE} guarded requests, newest first.</p>
        </div>
        <button
          type="button"
          onClick={() => load(filter)}
          disabled={loading}
          className="rounded-md border border-line-strong px-3 py-2 text-sm text-fg-2 transition-colors hover:border-accent/60 disabled:opacity-50"
        >
          Reload
        </button>
        <button
          type="button"
          onClick={() => exportJson(records, filter)}
          disabled={!records.length}
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-canvas transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:bg-line-strong disabled:text-fg-muted"
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
                ? 'bg-fg text-canvas'
                : 'text-fg-muted ring-1 ring-inset ring-line-strong hover:text-fg-2'
            }`}
            title={f.label}
          >
            {f.id}
          </button>
        ))}
        <span className="ml-auto self-center text-xs text-fg-subtle tabular-nums">
          {loading ? 'Loading…' : `${records.length} records`}
        </span>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger-fg">
          {error}
        </p>
      )}

      <div className="glass overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[56rem] border-collapse text-left text-[13px]">
          <thead className="bg-muted/60 text-xs text-fg-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Timestamp</th>
              <th scope="col" className="px-3 py-2 font-medium">Prompt</th>
              <th scope="col" className="px-3 py-2 font-medium">Reply</th>
              <th scope="col" className="px-3 py-2 font-medium">Verdict</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">Latency</th>
              <th scope="col" className="px-3 py-2 font-medium">
                <span className="sr-only">Copy record</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/80">
            {records.map((r) => (
              <tr key={r.id} className="align-top hover:bg-muted/50">
                <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-fg-muted tabular-nums" title={r.timestamp}>
                  {formatTimestamp(r.timestamp)}
                </td>
                <td className="max-w-xs px-3 py-2 font-mono text-xs text-fg-2" title={r.prompt}>
                  {snippet(r.prompt)}
                </td>
                <td className="max-w-xs px-3 py-2 font-mono text-xs text-fg-muted" title={r.reply}>
                  {snippet(r.reply)}
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <VerdictChip verdict={r.verdict} title={r.threat_category ?? r.verdict} animate={false} />
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-right font-mono text-xs text-fg-3 tabular-nums">
                  {r.latency_ms.toFixed(1)} ms
                </td>
                <td className="px-3 py-1.5 text-right">
                  <CopyButton compact text={() => JSON.stringify(r, null, 2)} label="Copy record JSON" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!loading && !error && records.length === 0 && (
          <p className="px-4 py-10 text-center text-sm text-fg-subtle">
            {filter === 'ALL'
              ? 'No requests logged yet. Send a prompt from the Playground to create the first entry.'
              : `No ${filter} records. Choose another filter or run a matching prompt.`}
          </p>
        )}
      </div>
    </div>
  )
}
