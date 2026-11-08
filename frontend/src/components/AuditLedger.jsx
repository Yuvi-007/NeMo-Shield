import { ChevronRight } from 'lucide-react'
import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { countRedactions } from '../lib/redactions'
import { getAuditLogs, onAdminKeyChange } from '../services/api'
import AdminErrorBanner from './AdminErrorBanner'
import CopyButton from './CopyButton'
import PiiInspector, { RedactionPills } from './PiiInspector'
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
  const [expanded, setExpanded] = useState(null)
  const [redactedOnly, setRedactedOnly] = useState(false)

  const latestRequest = useRef(0)

  // State is only set in promise callbacks, so effects can call this directly.
  // Responses to superseded requests (fast filter clicks) are dropped.
  const fetchLogs = useCallback((verdict) => {
    const request = ++latestRequest.current
    const current = () => request === latestRequest.current
    return getAuditLogs(PAGE_SIZE, 0, verdict === 'ALL' ? null : verdict)
      .then(
        (rows) => {
          if (!current()) return
          setRecords(rows)
          setError(null)
        },
        (err) => {
          if (!current()) return
          // Keep the error object: the banner picks its fallback from the status code.
          setError(err)
          setRecords([])
        },
      )
      .finally(() => {
        if (current()) setLoading(false)
      })
  }, [])

  const load = useCallback(
    (verdict) => {
      setLoading(true)
      return fetchLogs(verdict)
    },
    [fetchLogs],
  )

  useEffect(() => {
    fetchLogs(filter)
  }, [filter, fetchLogs])

  // Refetch as soon as an admin key is saved in the header.
  useEffect(() => onAdminKeyChange(() => load(filter)), [filter, load])

  const rows = records.map((r) => ({ record: r, redactions: countRedactions(r.prompt, r.reply) }))
  const visible = redactedOnly ? rows.filter((row) => Object.keys(row.redactions).length) : rows
  const redactedCount = rows.filter((row) => Object.keys(row.redactions).length).length

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
            onClick={() => {
              if (f.id === filter) return
              setLoading(true)
              setFilter(f.id)
            }}
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
        <label className="ml-2 inline-flex cursor-pointer items-center gap-1.5 self-center text-xs text-fg-muted">
          <input
            type="checkbox"
            checked={redactedOnly}
            onChange={(e) => setRedactedOnly(e.target.checked)}
            className="accent-accent"
          />
          PII redacted only
        </label>
        <span className="ml-auto self-center text-xs text-fg-subtle tabular-nums">
          {loading ? 'Loading…' : `${visible.length} records · ${redactedCount} with redactions`}
        </span>
      </div>

      <AdminErrorBanner error={error} onRetry={() => load(filter)} />

      <div className="glass overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[56rem] border-collapse text-left text-[13px]">
          <thead className="bg-muted/60 text-xs text-fg-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Timestamp</th>
              <th scope="col" className="px-3 py-2 font-medium">Prompt</th>
              <th scope="col" className="px-3 py-2 font-medium">Reply</th>
              <th scope="col" className="px-3 py-2 font-medium">Verdict</th>
              <th scope="col" className="px-3 py-2 font-medium">PII scrubbed</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">Latency</th>
              <th scope="col" className="px-3 py-2 font-medium">
                <span className="sr-only">Copy record</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/80">
            {visible.map(({ record: r, redactions }) => (
              <Fragment key={r.id}>
                <tr className="align-top hover:bg-muted/50">
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-fg-muted tabular-nums" title={r.timestamp}>
                    <button
                      type="button"
                      onClick={() => setExpanded((id) => (id === r.id ? null : r.id))}
                      aria-expanded={expanded === r.id}
                      aria-controls={`inspect-${r.id}`}
                      aria-label={`Inspect record from ${formatTimestamp(r.timestamp)}`}
                      className="inline-flex items-center gap-1 rounded hover:text-fg-2"
                    >
                      <ChevronRight
                        className={`size-3.5 transition-transform ${expanded === r.id ? 'rotate-90' : ''}`}
                        aria-hidden
                      />
                      {formatTimestamp(r.timestamp)}
                    </button>
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
                  <td className="px-3 py-2">
                    <RedactionPills counts={redactions} compact />
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-right font-mono text-xs text-fg-3 tabular-nums">
                    {r.latency_ms.toFixed(1)} ms
                  </td>
                  <td className="px-3 py-1.5 text-right">
                    <CopyButton compact text={() => JSON.stringify(r, null, 2)} label="Copy record JSON" />
                  </td>
                </tr>
                {expanded === r.id && (
                  <tr id={`inspect-${r.id}`} className="bg-muted/30">
                    <td colSpan={7} className="px-4 py-4">
                      <PiiInspector record={r} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>

        {!loading && !error && records.length > 0 && visible.length === 0 && (
          <p className="px-4 py-10 text-center text-sm text-fg-subtle">
            None of these records had PII redacted. Try the PII Exfiltration attack in the Playground.
          </p>
        )}

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
