import { BUDGET_MS, FAST_PATH_MS, MAX_LOG, MIN_LOG, formatMs, position, zoneFor } from '../lib/latencyScale'

const TICKS = Array.from({ length: MAX_LOG - MIN_LOG + 1 }, (_, i) => 10 ** (MIN_LOG + i))

function tickLabel(ms) {
  return ms < 1 ? `${ms} ms` : ms >= 1000 ? `${ms / 1000} s` : `${ms} ms`
}

function SplitCard({ label, value, detail, share, bar }) {
  return (
    <div className="rounded-md border border-line bg-canvas/60 px-4 py-3">
      <p className="text-sm text-fg-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-fg">{value.toLocaleString()}</p>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden>
        <div className={`h-full rounded-full transition-[width] duration-500 ${bar}`} style={{ width: `${share}%` }} />
      </div>
      <p className="mt-1.5 text-xs text-fg-subtle">{detail}</p>
    </div>
  )
}

function Marker({ ms, label, align }) {
  const zone = zoneFor(ms)
  return (
    <div
      className="absolute top-0 flex -translate-x-1/2 flex-col items-center"
      style={{ left: `${position(ms) * 100}%` }}
    >
      <span className={`size-3 rotate-45 rounded-[2px] ring-2 ring-surface ${zone.dot}`} aria-hidden />
      <span
        className={`mt-1 whitespace-nowrap font-mono text-[11px] font-semibold tabular-nums ${zone.text} ${
          align === 'below' ? 'translate-y-3.5' : ''
        }`}
      >
        {label} {formatMs(ms)}
      </span>
    </div>
  )
}

/** Percentile track on the shared log scale, with fast-path and Colang zones shaded. */
function PercentileTrack({ p50, p99 }) {
  const fast = position(FAST_PATH_MS) * 100
  const budget = position(BUDGET_MS) * 100
  // Labels collide when the two markers sit close together; push p99 below.
  const close = Math.abs(position(p99) - position(p50)) < 0.12

  return (
    <div
      role="img"
      aria-label={`Median latency ${formatMs(p50)} (${zoneFor(p50).name}); P99 ${formatMs(p99)} (${zoneFor(p99).name})`}
    >
      <div className="relative h-3 overflow-hidden rounded-full">
        <div className="absolute inset-y-0 left-0 bg-ok/30" style={{ width: `${fast}%` }} />
        <div className="absolute inset-y-0 bg-accent/25" style={{ left: `${fast}%`, width: `${budget - fast}%` }} />
        <div className="absolute inset-y-0 right-0 bg-warn/30" style={{ left: `${budget}%` }} />
      </div>
      <div className="relative mt-1 h-4">
        {TICKS.map((ms) => (
          <span
            key={ms}
            className="absolute -translate-x-1/2 font-mono text-[10px] text-fg-subtle"
            style={{ left: `${position(ms) * 100}%` }}
          >
            {tickLabel(ms)}
          </span>
        ))}
      </div>
      <div className={`relative mt-1 ${close ? 'h-12' : 'h-8'}`}>
        <Marker ms={p50} label="P50" />
        <Marker ms={p99} label="P99" align={close ? 'below' : undefined} />
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-fg-subtle">
        <li className="flex items-center gap-1.5">
          <span className="size-2 rounded-full bg-ok" aria-hidden /> Fast-path zone, under 1 ms
        </li>
        <li className="flex items-center gap-1.5">
          <span className="size-2 rounded-full bg-accent" aria-hidden /> Colang zone, 1–100 ms
        </li>
        <li className="flex items-center gap-1.5">
          <span className="size-2 rounded-full bg-warn" aria-hidden /> Over the 100 ms budget
        </li>
      </ul>
    </div>
  )
}

function ZoneBar({ zones, total }) {
  const parts = [
    { key: 'under_1ms', label: 'Fast path (<1 ms)', className: 'bg-ok' },
    { key: '1_to_100ms', label: 'Colang (1–100 ms)', className: 'bg-accent' },
    { key: 'over_100ms', label: 'Over budget (>100 ms)', className: 'bg-warn' },
  ]
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-full bg-muted" aria-hidden>
        {parts.map((p) => (
          <div
            key={p.key}
            className={`h-full transition-[width] duration-500 ${p.className}`}
            style={{ width: `${total ? ((zones[p.key] ?? 0) / total) * 100 : 0}%` }}
          />
        ))}
      </div>
      <dl className="mt-2 grid grid-cols-3 gap-2 text-xs">
        {parts.map((p) => (
          <div key={p.key}>
            <dt className="text-fg-subtle">{p.label}</dt>
            <dd className="font-mono text-fg-2 tabular-nums">
              {(zones[p.key] ?? 0).toLocaleString()}{' '}
              <span className="text-fg-subtle">
                · {total ? (((zones[p.key] ?? 0) / total) * 100).toFixed(0) : 0}%
              </span>
            </dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

/** Which rail decided each request, and where latency lands relative to the fast-path and Colang zones. */
export default function RailBreakdown({ data }) {
  if (!data) return null
  if (data.fast_path_blocks === undefined) {
    return (
      <p className="rounded-md border border-line px-4 py-3 text-sm text-fg-subtle">
        This backend does not report a rail breakdown yet. Deploy the latest gateway to see fast-path vs Colang splits.
      </p>
    )
  }

  const total = data.total_requests ?? 0
  const blocked = data.blocked_requests ?? 0
  const fast = data.fast_path_blocks ?? 0
  const colang = data.colang_blocks ?? 0
  const sanitized = data.sanitized_outputs ?? 0
  const unattributed = Math.max(0, blocked - fast - colang)
  const pct = (n, of) => (of ? (n / of) * 100 : 0)

  return (
    <section className="glass rounded-lg border border-line">
      <header className="flex flex-wrap items-baseline gap-2 border-b border-line px-4 py-3">
        <h2 className="mr-auto text-base font-semibold">Rail breakdown</h2>
        <span className="text-xs text-fg-subtle">Which layer decided each request</span>
      </header>

      <div className="grid gap-3 p-4 sm:grid-cols-3">
        <SplitCard
          label="Fast-path regex halts"
          value={fast}
          share={pct(fast, blocked)}
          bar="bg-ok"
          detail={`${pct(fast, blocked).toFixed(0)}% of blocks · under 1 ms, Colang never ran`}
        />
        <SplitCard
          label="Colang dialog rails halted"
          value={colang}
          share={pct(colang, blocked)}
          bar="bg-danger"
          detail={`${pct(colang, blocked).toFixed(0)}% of blocks · input rail aborted the flow`}
        />
        <SplitCard
          label="Sanitized PII outputs"
          value={sanitized}
          share={pct(sanitized, total)}
          bar="bg-warn"
          detail={`${pct(sanitized, total).toFixed(1)}% of requests · output rail redacted the reply`}
        />
      </div>
      {unattributed > 0 && (
        <p className="-mt-1 px-4 pb-3 text-xs text-fg-subtle">
          {unattributed} older blocked {unattributed === 1 ? 'record predates' : 'records predate'} rail attribution and
          {unattributed === 1 ? ' is' : ' are'} in neither split.
        </p>
      )}

      <div className="grid gap-6 border-t border-line p-4 lg:grid-cols-[3fr_2fr]">
        <div>
          <h3 className="mb-3 text-sm font-semibold text-fg">
            Latency percentiles <span className="font-normal text-fg-subtle">(log scale)</span>
          </h3>
          {total ? (
            <PercentileTrack p50={data.p50_latency_ms ?? 0} p99={data.p99_latency_ms ?? 0} />
          ) : (
            <p className="text-sm text-fg-subtle">No requests yet.</p>
          )}
        </div>
        <div>
          <h3 className="mb-3 text-sm font-semibold text-fg">Requests by latency zone</h3>
          <ZoneBar zones={data.latency_zones ?? {}} total={total} />
        </div>
      </div>
    </section>
  )
}
