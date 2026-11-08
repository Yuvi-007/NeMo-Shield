import { useState } from 'react'
import { MAX_PROMPT_CHARS } from './presets'

// Rough English estimate; only used to explain truncation, never to enforce it.
const CHARS_PER_TOKEN = 4

/**
 * Textarea capped at the gateway's per-turn limit. Oversized pastes are trimmed
 * with a visible notice instead of silently, and whitespace-only input is
 * flagged because the gateway rejects it.
 */
export default function PromptBox({ id, value, onChange, onSubmit, rows = 4, placeholder, label, footer }) {
  const [trimmedFrom, setTrimmedFrom] = useState(null)
  const blank = value.length > 0 && !value.trim()

  return (
    <div>
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <textarea
        id={id}
        value={value}
        onChange={(e) => {
          const next = e.target.value
          setTrimmedFrom(next.length > MAX_PROMPT_CHARS ? next.length : null)
          onChange(next.slice(0, MAX_PROMPT_CHARS))
        }}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) onSubmit(e)
        }}
        rows={rows}
        placeholder={placeholder}
        aria-describedby={`${id}-count`}
        className="w-full resize-y rounded-md border border-line bg-canvas px-3 py-2.5 font-mono text-sm text-fg placeholder:text-fg-faint focus:border-accent/60 focus:outline-none"
      />
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <span id={`${id}-count`} className="font-mono text-xs text-fg-subtle tabular-nums">
          {value.length.toLocaleString()}/{MAX_PROMPT_CHARS.toLocaleString()}
        </span>
        {footer}
      </div>
      {trimmedFrom && (
        <p role="status" className="mt-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn-fg">
          Pasted text was {trimmedFrom.toLocaleString()} characters (about{' '}
          {Math.round(trimmedFrom / CHARS_PER_TOKEN).toLocaleString()} tokens). It was trimmed to{' '}
          {MAX_PROMPT_CHARS.toLocaleString()}, the gateway&apos;s per-turn limit.
        </p>
      )}
      {blank && (
        <p role="status" className="mt-2 text-xs text-fg-subtle">
          Only whitespace so far. The gateway rejects blank prompts, so sending is disabled.
        </p>
      )}
    </div>
  )
}
