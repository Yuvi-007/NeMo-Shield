const STYLES = {
  ALLOWED: { label: 'Allowed', className: 'bg-ok/10 text-ok-fg ring-ok/30', dot: 'bg-ok' },
  BLOCKED: { label: 'Blocked', className: 'bg-danger/10 text-danger-fg ring-danger/30', dot: 'bg-danger' },
  ALTERED: { label: 'Altered', className: 'bg-warn/10 text-warn-fg ring-warn/30', dot: 'bg-warn' },
  UNGUARDED: { label: 'No rails', className: 'bg-fg-muted/10 text-fg-3 ring-fg-muted/25', dot: 'bg-fg-muted' },
}

const FROM_API = {
  ALLOWED: 'ALLOWED',
  INPUT_BLOCKED: 'BLOCKED',
  OUTPUT_ALTERED: 'ALTERED',
}

function toDisplayVerdict(apiVerdict) {
  return FROM_API[apiVerdict] ?? apiVerdict
}

export default function VerdictChip({ verdict, title, animate = true }) {
  const style = STYLES[toDisplayVerdict(verdict)] ?? STYLES.UNGUARDED
  return (
    <span
      key={verdict}
      title={title ?? verdict}
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset transition-colors ${animate ? 'animate-chip-in' : ''} ${style.className}`}
    >
      <span aria-hidden className={`size-1.5 rounded-full ${style.dot}`} />
      {style.label}
    </span>
  )
}
