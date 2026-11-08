// Which layer decided a request (backend `rail_path`).
const PATHS = {
  FAST_PATH: { label: 'Fast-path halt', hint: 'Gateway regex classifier blocked it before Colang ran (<1 ms)', className: 'text-danger-fg ring-danger/30' },
  COLANG_INPUT: { label: 'Colang flow aborted', hint: 'The Colang input rail aborted the dialog flow', className: 'text-danger-fg ring-danger/30' },
  COLANG_OUTPUT: { label: 'Output rail redacted', hint: 'The model answered and the output rail masked PII', className: 'text-warn-fg ring-warn/30' },
  PASSTHROUGH: { label: 'Full Colang pass', hint: 'Input, dialog and output rails ran; nothing changed', className: 'text-fg-3 ring-line-strong' },
}

export default function RailPathBadge({ path }) {
  const info = PATHS[path]
  if (!info) return null
  return (
    <span
      title={info.hint}
      className={`inline-flex items-center rounded-md px-2 py-0.5 font-mono text-[11px] ring-1 ring-inset ${info.className}`}
    >
      {info.label}
    </span>
  )
}
