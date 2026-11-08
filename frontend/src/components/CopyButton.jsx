import { Check, Copy } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

const RESET_MS = 1500

async function writeClipboard(text) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }
  // Fallback for non-secure origins (e.g. a LAN IP over plain HTTP).
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  document.body.appendChild(area)
  area.select()
  const ok = document.execCommand('copy')
  area.remove()
  if (!ok) throw new Error('Copy command was rejected')
}

/** Copies `text` (a string, or a function returning one) and confirms for 1.5 s. */
export default function CopyButton({ text, label = 'Copy JSON', compact = false }) {
  const [state, setState] = useState('idle') // idle | copied | failed
  const timer = useRef(null)

  useEffect(() => () => clearTimeout(timer.current), [])

  async function copy() {
    try {
      await writeClipboard(typeof text === 'function' ? text() : text)
      setState('copied')
    } catch {
      setState('failed')
    }
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setState('idle'), RESET_MS)
  }

  const Icon = state === 'copied' ? Check : Copy
  const visibleLabel = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label
  const tone =
    state === 'copied'
      ? 'text-ok-fg ring-ok/40'
      : state === 'failed'
        ? 'text-danger-fg ring-danger/40'
        : 'text-fg-muted ring-line-strong hover:text-fg-2 hover:ring-accent/50'

  return (
    <>
      <button
        type="button"
        onClick={copy}
        aria-label={compact ? visibleLabel : undefined}
        title={compact ? visibleLabel : undefined}
        className={`inline-flex items-center gap-1.5 rounded-md text-xs ring-1 ring-inset transition-colors ${
          compact ? 'p-1.5' : 'px-2 py-1'
        } ${tone}`}
      >
        <Icon key={state} className="size-3.5 animate-chip-in" aria-hidden />
        {!compact && <span>{visibleLabel}</span>}
      </button>
      <span className="sr-only" aria-live="polite">
        {state === 'copied' ? 'Copied to clipboard' : state === 'failed' ? 'Copy failed' : ''}
      </span>
    </>
  )
}
