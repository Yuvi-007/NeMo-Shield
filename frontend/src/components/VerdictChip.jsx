const STYLES = {
  ALLOWED: { label: 'Allowed', className: 'bg-emerald-400/10 text-emerald-300 ring-emerald-400/30', dot: 'bg-emerald-400' },
  BLOCKED: { label: 'Blocked', className: 'bg-red-400/10 text-red-300 ring-red-400/30', dot: 'bg-red-400' },
  ALTERED: { label: 'Altered', className: 'bg-amber-400/10 text-amber-300 ring-amber-400/30', dot: 'bg-amber-400' },
  UNGUARDED: { label: 'No rails', className: 'bg-slate-400/10 text-slate-300 ring-slate-400/25', dot: 'bg-slate-400' },
}

const FROM_API = {
  ALLOWED: 'ALLOWED',
  INPUT_BLOCKED: 'BLOCKED',
  OUTPUT_ALTERED: 'ALTERED',
}

export function toDisplayVerdict(apiVerdict) {
  return FROM_API[apiVerdict] ?? apiVerdict
}

export default function VerdictChip({ verdict, title }) {
  const style = STYLES[toDisplayVerdict(verdict)] ?? STYLES.UNGUARDED
  return (
    <span
      title={title ?? verdict}
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${style.className}`}
    >
      <span aria-hidden className={`size-1.5 rounded-full ${style.dot}`} />
      {style.label}
    </span>
  )
}
