// Latency gauge on a log scale (see lib/latencyScale.js for why log).
import { BUDGET_MS, FAST_PATH_MS, formatMs, position, zoneFor } from '../lib/latencyScale'

const CENTER = 64
const RADIUS = 52
const ARC = `M ${CENTER - RADIUS} ${CENTER} A ${RADIUS} ${RADIUS} 0 0 1 ${CENTER + RADIUS} ${CENTER}`

function pointAt(t, radius) {
  const angle = Math.PI * (1 - t)
  return [CENTER + radius * Math.cos(angle), CENTER - radius * Math.sin(angle)]
}

const ZONES = [
  { from: 0, to: position(FAST_PATH_MS), className: 'stroke-ok/25' },
  { from: position(FAST_PATH_MS), to: position(BUDGET_MS), className: 'stroke-accent/20' },
  { from: position(BUDGET_MS), to: 1, className: 'stroke-warn/30' },
]

function Dial({ ms }) {
  const t = position(ms)
  const zone = zoneFor(ms)
  return (
    <div
      role="meter"
      aria-label="Guard latency for the last request"
      aria-valuemin={0}
      aria-valuemax={1000}
      aria-valuenow={Number(ms.toFixed(2))}
      aria-valuetext={`${formatMs(ms)}, ${zone.name}`}
      className="relative w-40 shrink-0"
    >
      <svg viewBox="0 0 128 72" className="w-full" aria-hidden>
        {ZONES.map((z) => (
          <path
            key={z.from}
            d={ARC}
            pathLength={100}
            fill="none"
            strokeWidth={10}
            className={z.className}
            strokeDasharray={`${(z.to - z.from) * 100} 100`}
            strokeDashoffset={-z.from * 100}
          />
        ))}
        <path
          d={ARC}
          pathLength={100}
          fill="none"
          strokeWidth={10}
          strokeLinecap="round"
          className={`${zone.stroke} transition-colors duration-300`}
          strokeDasharray={`${Math.max(t * 100, 0.5)} 100`}
          style={{ transition: 'stroke-dasharray 600ms cubic-bezier(0.2, 0.8, 0.2, 1)' }}
        />
        {[FAST_PATH_MS, BUDGET_MS].map((mark) => {
          const [x1, y1] = pointAt(position(mark), RADIUS - 9)
          const [x2, y2] = pointAt(position(mark), RADIUS + 9)
          return <line key={mark} x1={x1} y1={y1} x2={x2} y2={y2} strokeWidth={1.5} className="stroke-fg-faint" />
        })}
      </svg>
      <div className="absolute inset-x-0 bottom-0 text-center">
        <p className={`font-mono text-lg font-semibold tabular-nums ${zone.text}`}>{formatMs(ms)}</p>
        <p className="text-[11px] text-fg-subtle">{zone.name}</p>
      </div>
    </div>
  )
}

function Sparkline({ history }) {
  const width = 240
  const height = 56
  const pad = 4
  const n = history.length
  const x = (i) => (n === 1 ? width / 2 : pad + (i * (width - 2 * pad)) / (n - 1))
  const y = (ms) => pad + (1 - position(ms)) * (height - 2 * pad)
  const budgetY = y(BUDGET_MS)
  const points = history.map((h, i) => `${x(i)},${y(h.ms)}`).join(' ')

  // The SVG stretches to the container width, so lines scale freely. Dots are
  // HTML overlays positioned in percent, so they stay round at any width.
  return (
    <div className="relative h-14 w-full" aria-hidden>
      <svg viewBox={`0 0 ${width} ${height}`} className="absolute inset-0 size-full" preserveAspectRatio="none">
        <line
          x1={0}
          x2={width}
          y1={budgetY}
          y2={budgetY}
          strokeDasharray="4 4"
          strokeWidth={1}
          className="stroke-warn/60"
          vectorEffect="non-scaling-stroke"
        />
        {n > 1 && (
          <polyline points={points} fill="none" strokeWidth={1.5} className="stroke-accent/60" vectorEffect="non-scaling-stroke" />
        )}
      </svg>
      {history.map((h, i) => (
        <span
          key={i}
          className={`absolute -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-surface ${zoneFor(h.ms).dot} ${
            i === n - 1 ? 'size-2.5' : 'size-1.5'
          }`}
          style={{ left: `${(x(i) / width) * 100}%`, top: `${(y(h.ms) / height) * 100}%` }}
        />
      ))}
    </div>
  )
}

/** Last-request dial plus a session sparkline. `history` is [{ ms, verdict }], oldest first. */
export default function LatencyGauge({ history }) {
  if (!history.length) return null
  const latest = history[history.length - 1]
  const fastPath = history.filter((h) => h.ms < FAST_PATH_MS).length

  return (
    <section className="glass flex flex-col gap-4 rounded-lg border border-line px-4 py-3 sm:flex-row sm:items-center">
      <Dial ms={latest.ms} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h3 className="mr-auto text-sm font-semibold text-fg">Guard latency</h3>
          <span className="text-xs text-fg-subtle tabular-nums">
            {history.length} this session · {fastPath} on the fast path
          </span>
        </div>
        <Sparkline history={history} />
        <ul className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-fg-subtle">
          <li className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-ok" aria-hidden /> Fast path, under 1 ms
          </li>
          <li className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-accent" aria-hidden /> Colang rails
          </li>
          <li className="flex items-center gap-1.5">
            <span className="h-px w-3 border-t border-dashed border-warn" aria-hidden /> 100 ms budget (log scale)
          </li>
        </ul>
      </div>
    </section>
  )
}
