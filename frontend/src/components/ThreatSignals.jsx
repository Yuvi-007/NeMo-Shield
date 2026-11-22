import { Binary, Languages } from 'lucide-react'
import { FLAGS, SIGNALS, parseSignal } from '../lib/flags'

const FLAG_ICONS = { ENCODED_PAYLOAD: Binary, UNCOVERED_LANGUAGE: Languages }

/** Advisory flags (ENCODED_PAYLOAD, UNCOVERED_LANGUAGE). `compact` shows icons only. */
export function FlagBadges({ flags, compact = false }) {
  const known = (flags || []).filter((flag) => FLAGS[flag])
  if (!known.length) return null
  return (
    <span className="inline-flex flex-wrap gap-1">
      {known.map((flag) => {
        const Icon = FLAG_ICONS[flag]
        const info = FLAGS[flag]
        return (
          <span
            key={flag}
            title={info.hint}
            className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${info.pill}`}
          >
            <Icon className="size-3" aria-hidden />
            {compact ? <span className="sr-only">{info.label}</span> : info.label}
          </span>
        )
      })}
    </span>
  )
}

/**
 * Classifier signals behind the score. Decoded ones show the encoding layers
 * they were hidden under: base64 → hex → Instruction override.
 */
export function SignalChips({ signals }) {
  if (!signals?.length) return null
  return (
    <ul className="inline-flex flex-wrap gap-1" aria-label="Matched signals">
      {signals.map((signal) => {
        const { layers, name } = parseSignal(signal)
        return (
          <li
            key={signal}
            title={signal}
            className="inline-flex items-center gap-1 rounded-md bg-muted/70 px-1.5 py-0.5 font-mono text-[11px] text-fg-3"
          >
            {layers.map((layer, i) => (
              <span key={i} className="text-violet-700 dark:text-violet-300">
                {layer} <span aria-hidden>→</span>
              </span>
            ))}
            <span>{SIGNALS[name] ?? name}</span>
          </li>
        )
      })}
    </ul>
  )
}
