import { REDACTION_TYPES, countRedactions, splitRedactions } from '../lib/redactions'
import RailPathBadge from './RailPathBadge'

/** Distinct pill per redacted field type, e.g. "Email ×2". */
export function RedactionPills({ counts, compact = false }) {
  const entries = Object.entries(counts)
  if (!entries.length) return compact ? <span className="text-xs text-fg-faint">none</span> : null
  return (
    <span className="inline-flex flex-wrap gap-1">
      {entries.map(([type, n]) => (
        <span
          key={type}
          title={`${n} ${REDACTION_TYPES[type].label} value${n === 1 ? '' : 's'} redacted`}
          className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${REDACTION_TYPES[type].pill}`}
        >
          {compact ? type : REDACTION_TYPES[type].label}
          <span className="tabular-nums opacity-80">×{n}</span>
        </span>
      ))}
    </span>
  )
}

/**
 * Inline diff: each redaction shows the removed field (struck out, value
 * withheld) followed by the token that replaced it.
 */
function RedactionDiff({ text }) {
  const parts = splitRedactions(text)
  if (!text) return <p className="text-xs text-fg-faint">(empty)</p>
  return (
    <p className="whitespace-pre-wrap break-words font-mono text-[13px] leading-relaxed text-fg-2">
      {parts.map((part, i) =>
        part.token ? (
          <span key={i} className="whitespace-nowrap">
            <del
              className="rounded-l bg-danger/10 px-1 text-danger-fg decoration-danger/60"
              title="Original value withheld: it was never stored"
            >
              {REDACTION_TYPES[part.type].removed}
            </del>
            <ins className={`rounded-r px-1 no-underline ring-1 ring-inset ${REDACTION_TYPES[part.type].pill}`}>
              {part.token}
            </ins>
          </span>
        ) : (
          <span key={i}>{part.text}</span>
        ),
      )}
    </p>
  )
}

function Side({ title, caption, text }) {
  const counts = countRedactions(text)
  const changed = Object.keys(counts).length > 0
  return (
    <div className="min-w-0 rounded-md border border-line bg-canvas/60 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h4 className="text-xs font-semibold text-fg">{title}</h4>
        <span
          className={`rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${
            changed ? 'bg-warn/10 text-warn-fg ring-warn/30' : 'bg-ok/10 text-ok-fg ring-ok/30'
          }`}
        >
          {changed ? 'Sanitized' : 'Unchanged'}
        </span>
        <RedactionPills counts={counts} />
      </div>
      <p className="mb-2 text-[11px] text-fg-subtle">{caption}</p>
      <RedactionDiff text={text} />
    </div>
  )
}

/** Expanded audit row: what was scrubbed from the prompt and the reply. */
export default function PiiInspector({ record }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg-muted">
        <RailPathBadge path={record.rail_path} />
        {record.threat_category && <span>Threat: {record.threat_category}</span>}
        <span className="tabular-nums">Confidence {(record.confidence * 100).toFixed(0)}%</span>
        {record.session_id && <span className="font-mono">session {record.session_id}</span>}
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <Side
          title="Prompt"
          caption="Masked by the gateway before the audit write, whatever the verdict."
          text={record.prompt}
        />
        <Side title="Reply" caption="Masked by the Colang output rail and the gateway re-mask." text={record.reply} />
      </div>
      <p className="text-[11px] text-fg-subtle">
        Originals are never persisted, so the struck-out part names the kind of value removed, not the value itself.
      </p>
    </div>
  )
}
