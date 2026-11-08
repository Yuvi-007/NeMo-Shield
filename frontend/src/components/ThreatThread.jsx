import { useRef, useState } from 'react'
import { describeError, sendChat } from '../services/api'
import CopyButton from './CopyButton'
import PresetChips from './PresetChips'
import PromptBox from './PromptBox'
import RailPathBadge from './RailPathBadge'
import VerdictChip from './VerdictChip'
import { MAX_PROMPT_CHARS, MAX_THREAD_TURNS, SPLIT_TURN_ATTACK } from './presets'

const SCRIPT_STEP_DELAY_MS = 400

function newSessionId() {
  const random = globalThis.crypto?.randomUUID?.() ?? `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`
  return `thread-${random}`
}

const isHalted = (exchange) => exchange.status === 'done' && exchange.response.verdict === 'INPUT_BLOCKED'

/** Completed exchanges that will be sent as history. */
function forwarded(exchanges, keepHalted) {
  return exchanges.filter((e) => e.status === 'done' && (keepHalted || !isHalted(e)))
}

function buildMessages(exchanges, prompt, keepHalted) {
  const messages = forwarded(exchanges, keepHalted).flatMap((e) => [
    { role: 'user', content: e.prompt },
    // Model replies have no length cap but history turns do; trimming our own
    // past reply keeps the request valid without touching anything the user sent.
    { role: 'assistant', content: e.response.reply.slice(0, MAX_PROMPT_CHARS) },
  ])
  return [...messages, { role: 'user', content: prompt }]
}

const EDGE = {
  ALLOWED: 'border-ok/40',
  INPUT_BLOCKED: 'border-danger/50 bg-danger/5',
  OUTPUT_ALTERED: 'border-warn/50',
}

const TRACE_DOT = {
  ALLOWED: 'bg-ok',
  INPUT_BLOCKED: 'bg-danger',
  OUTPUT_ALTERED: 'bg-warn',
}

function TurnTrace({ exchanges }) {
  if (!exchanges.length) return null
  return (
    <ol className="flex flex-wrap items-center gap-1.5" aria-label="Turn trace">
      {exchanges.map((e, i) => {
        const verdict = e.status === 'done' ? e.response.verdict : e.status
        const dot = TRACE_DOT[verdict] ?? (e.status === 'pending' ? 'bg-accent animate-pulse' : 'bg-fg-faint')
        return (
          <li key={e.id} className="flex items-center gap-1.5">
            {i > 0 && <span className="h-px w-3 bg-line-strong" aria-hidden />}
            <span
              className={`grid size-5 place-items-center rounded-full font-mono text-[10px] font-semibold text-canvas ${dot}`}
              title={`Turn ${i + 1}: ${verdict}`}
            >
              {i + 1}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

function Exchange({ exchange, index }) {
  const { prompt, status, response, error } = exchange
  return (
    <li className="space-y-2">
      <div className="ml-auto max-w-[85%] rounded-lg rounded-br-sm bg-muted px-3 py-2">
        <p className="mb-1 text-[11px] text-fg-subtle">Turn {index + 1} · user</p>
        <p className="whitespace-pre-wrap break-words font-mono text-[13px] text-fg-2">{prompt}</p>
      </div>

      {status === 'pending' && (
        <div className="max-w-[85%] rounded-lg border border-dashed border-accent/40 px-3 py-2 text-xs text-fg-muted">
          <span className="mr-2 inline-block size-1.5 animate-pulse rounded-full bg-accent align-middle" aria-hidden />
          Running input → dialog → output rails…
        </div>
      )}

      {status === 'error' && (
        <div role="alert" className="max-w-[85%] rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger-fg">
          {error} This turn was not added to the thread history.
        </div>
      )}

      {status === 'done' && (
        <div className={`max-w-[85%] rounded-lg rounded-bl-sm border px-3 py-2 ${EDGE[response.verdict] ?? 'border-line'}`}>
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <VerdictChip verdict={response.verdict} title={response.threat_category ?? response.verdict} />
            <RailPathBadge path={response.rail_path} />
            <span className="font-mono text-[11px] text-fg-subtle tabular-nums">
              {response.latency_ms.toFixed(response.latency_ms < 1 ? 2 : 1)} ms · {(response.confidence * 100).toFixed(0)}%
            </span>
          </div>
          {response.verdict === 'INPUT_BLOCKED' && (
            <p className="mb-1 text-xs font-medium text-danger-fg">
              {response.rail_path === 'COLANG_INPUT' ? 'Colang flow aborted' : 'Halted before the Colang runtime'} at turn{' '}
              {index + 1}. The model was never called.
            </p>
          )}
          <p className="whitespace-pre-wrap break-words font-mono text-[13px] leading-relaxed text-fg-2">{response.reply}</p>
        </div>
      )}
    </li>
  )
}

/**
 * Multi-turn red-team thread. Every send posts the whole conversation to
 * /guard/chat as `messages`, so the gateway rescans history on each turn and
 * attacks split across turns get caught.
 */
export default function ThreatThread({ onResult }) {
  const [exchanges, setExchanges] = useState([])
  const exchangesRef = useRef(exchanges)
  const [draft, setDraft] = useState('')
  const [keepHalted, setKeepHalted] = useState(true)
  const [busy, setBusy] = useState(false)
  const [sessionId, setSessionId] = useState(newSessionId)
  const nextId = useRef(1)

  // The script loop awaits several sends, so it reads the latest thread from the ref.
  function update(fn) {
    exchangesRef.current = fn(exchangesRef.current)
    setExchanges(exchangesRef.current)
  }

  const historyTurns = forwarded(exchanges, keepHalted).length * 2
  const atLimit = historyTurns + 1 > MAX_THREAD_TURNS
  const haltedIndex = exchanges.findIndex(isHalted)

  async function send(text) {
    const prompt = text.trim()
    if (!prompt) return false
    const messages = buildMessages(exchangesRef.current, prompt, keepHalted)
    if (messages.length > MAX_THREAD_TURNS) return false
    const id = nextId.current++
    update((prev) => [...prev, { id, prompt, status: 'pending' }])
    try {
      const response = await sendChat(null, { messages, sessionId })
      update((prev) => prev.map((e) => (e.id === id ? { ...e, status: 'done', response } : e)))
      onResult?.(response)
      return true
    } catch (err) {
      update((prev) => prev.map((e) => (e.id === id ? { ...e, status: 'error', error: describeError(err) } : e)))
      return false
    }
  }

  async function handleSubmit(event) {
    event.preventDefault()
    if (busy || atLimit || !draft.trim()) return
    setBusy(true)
    const sent = await send(draft)
    if (sent) setDraft('')
    setBusy(false)
  }

  async function runSplitScript() {
    if (busy) return
    setBusy(true)
    for (const [i, turn] of SPLIT_TURN_ATTACK.entries()) {
      if (i > 0) await new Promise((resolve) => setTimeout(resolve, SCRIPT_STEP_DELAY_MS))
      if (!(await send(turn))) break
    }
    setBusy(false)
  }

  function reset() {
    update(() => [])
    setSessionId(newSessionId())
    setDraft('')
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <TurnTrace exchanges={exchanges} />
        <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-[11px] text-fg-subtle">
          session {sessionId.slice(0, 15)}…
          <CopyButton compact text={sessionId} label="Copy session id" />
        </span>
      </div>

      {exchanges.length === 0 ? (
        <p className="rounded-lg border border-dashed border-line px-4 py-6 text-center text-sm text-fg-subtle">
          Send turns one at a time, or run the split-turn script: each half passes alone, but the gateway rescans the
          whole thread and halts the second turn.
        </p>
      ) : (
        <ol aria-live="polite" aria-label="Conversation" className="max-h-[32rem] space-y-4 overflow-y-auto pr-1">
          {exchanges.map((exchange, i) => (
            <Exchange key={exchange.id} exchange={exchange} index={i} />
          ))}
        </ol>
      )}

      {haltedIndex >= 0 && keepHalted && (
        <p className="rounded-md border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-fg-muted">
          Turn {haltedIndex + 1} was halted and is still in the history this thread sends. If the fast path caught it,
          every later turn is blocked too, because the gateway rescans the whole conversation. Untick{' '}
          <em>Keep halted turns</em> to see what an attacker who drops them gets, or reset the thread.
        </p>
      )}

      <form onSubmit={handleSubmit} className="space-y-3 rounded-lg border border-line p-3">
        <PresetChips onPick={setDraft} disabled={busy} />
        <PromptBox
          id="thread-prompt"
          label="Next user turn"
          rows={3}
          value={draft}
          onChange={setDraft}
          onSubmit={handleSubmit}
          placeholder={atLimit ? 'Thread is full (20 turns). Reset to start again.' : 'Next user turn…'}
          footer={
            <>
              <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs text-fg-muted">
                <input
                  type="checkbox"
                  checked={keepHalted}
                  onChange={(e) => setKeepHalted(e.target.checked)}
                  className="accent-accent"
                />
                Keep halted turns in history
              </label>
              <span className="font-mono text-xs text-fg-subtle tabular-nums">
                {Math.min(historyTurns + 1, MAX_THREAD_TURNS)}/{MAX_THREAD_TURNS} turns
              </span>
              <div className="ml-auto flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={runSplitScript}
                  disabled={busy || historyTurns + SPLIT_TURN_ATTACK.length * 2 - 1 > MAX_THREAD_TURNS}
                  className="rounded-md border border-danger/40 px-3 py-1.5 text-xs font-medium text-danger-fg transition-colors hover:bg-danger/10 disabled:opacity-50"
                >
                  Run split-turn attack
                </button>
                <button
                  type="button"
                  onClick={reset}
                  disabled={busy || !exchanges.length}
                  className="rounded-md border border-line-strong px-3 py-1.5 text-xs text-fg-2 transition-colors hover:border-accent/60 disabled:opacity-50"
                >
                  Reset thread
                </button>
                <button
                  type="submit"
                  disabled={busy || atLimit || !draft.trim()}
                  className="rounded-md bg-accent px-4 py-1.5 text-xs font-semibold text-canvas transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:bg-line-strong disabled:text-fg-muted"
                >
                  {busy ? 'Running…' : 'Send turn'}
                </button>
              </div>
            </>
          }
        />
      </form>
    </div>
  )
}
