import { useState } from 'react'
import inputRailsSource from '../../../config/rails/input_rails.co?raw'
import outputRailsSource from '../../../config/rails/output_rails.co?raw'

const FILES = [
  {
    id: 'input',
    name: 'input_rails.co',
    summary: 'Runs before the model. Pattern detectors and a weighted classifier can abort the request.',
    source: inputRailsSource,
  },
  {
    id: 'output',
    name: 'output_rails.co',
    summary: 'Runs after the model. Emails, card numbers, and API keys are masked before the reply is sent.',
    source: outputRailsSource,
  },
]

const KEYWORDS = new Set(['flow', 'if', 'elif', 'else', 'await', 'global', 'import', 'abort', 'or', 'and', 'not', 'match', 'send', 'return'])

// Tokens: comment | string | $variable | identifier | anything else.
const TOKEN = /(#.*$)|("(?:[^"\\]|\\.)*")|(\$[A-Za-z_]\w*)|([A-Za-z_]\w*)|([^#"$A-Za-z_]+)/g

function highlightLine(line) {
  const parts = []
  let match
  let afterFlow = false
  TOKEN.lastIndex = 0
  while ((match = TOKEN.exec(line)) !== null) {
    const [text, comment, string, variable, word] = match
    let cls = 'text-slate-300'
    if (comment) cls = 'text-slate-500 italic'
    else if (string) cls = 'text-emerald-300'
    else if (variable) cls = 'text-amber-200'
    else if (word && KEYWORDS.has(word)) cls = 'text-sky-300 font-medium'
    else if (word && afterFlow) cls = 'text-violet-300'
    else if (word && /Action$/.test(word)) cls = 'text-rose-300'
    if (word === 'flow') afterFlow = true
    else if (variable) afterFlow = false
    parts.push(
      <span key={match.index} className={cls}>
        {text}
      </span>,
    )
  }
  return parts
}

function CodeView({ source }) {
  const lines = source.replace(/\s+$/, '').split('\n')
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse font-mono text-[12.5px] leading-6">
        <tbody>
          {lines.map((line, i) => (
            <tr key={i} className="hover:bg-slate-800/40">
              <td className="w-10 select-none pr-4 text-right align-top text-slate-600 tabular-nums">{i + 1}</td>
              <td className="whitespace-pre pr-6">{highlightLine(line)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const PIPELINE = [
  {
    title: 'Input rail evaluates the prompt',
    body: 'Colang flows run three regex detectors (instruction override, jailbreak personas, system prompt extraction), then ClassifyThreatAction scores multi-signal attacks.',
    tone: 'border-sky-300/40',
  },
  {
    title: 'A match aborts the flow',
    body: 'The block flow sends a fixed refusal and calls abort. The LLM is never invoked, so a blocked prompt costs no tokens and cannot leak anything.',
    tone: 'border-red-400/50',
  },
  {
    title: 'Clean prompts reach the model',
    body: 'Only prompts that pass every input check are forwarded to the LLM. The same input always produces the same verdict.',
    tone: 'border-emerald-400/40',
  },
  {
    title: 'Output rail redacts before delivery',
    body: 'mask_pii_output checks the reply for card numbers, emails, and sk- keys, and rewrites $bot_message through MaskSensitiveEntitiesAction.',
    tone: 'border-amber-400/50',
  },
]

export default function PolicyHub() {
  const [active, setActive] = useState('input')
  const file = FILES.find((f) => f.id === active)

  return (
    <div className="space-y-8">
      <div className="max-w-2xl">
        <h1 className="text-2xl font-semibold tracking-tight">Policy hub</h1>
        <p className="mt-1 text-sm text-slate-400">
          The Colang 2.0 flows enforced on every request, loaded from <span className="font-mono text-slate-300">config/rails</span>.
        </p>
      </div>

      <section className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/40">
        <div role="tablist" aria-label="Colang files" className="flex border-b border-slate-800">
          {FILES.map((f) => (
            <button
              key={f.id}
              type="button"
              role="tab"
              aria-selected={f.id === active}
              onClick={() => setActive(f.id)}
              className={`border-r border-slate-800 px-4 py-2.5 font-mono text-xs transition-colors ${
                f.id === active ? 'bg-slate-950 text-slate-100' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {f.name}
            </button>
          ))}
        </div>
        <p className="border-b border-slate-800 px-4 py-2.5 text-sm text-slate-400">{file.summary}</p>
        <div role="tabpanel" className="bg-slate-950 py-3">
          <CodeView source={file.source} />
        </div>
      </section>

      <section>
        <h2 className="text-base font-semibold">How a request moves through the rails</h2>
        <p className="mt-1 max-w-2xl text-sm text-slate-400">
          Every decision is made by deterministic code paths, not by asking the model to police itself.
        </p>
        <ol className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {PIPELINE.map((step, i) => (
            <li key={step.title} className={`rounded-lg border-l-2 bg-slate-900/50 px-4 py-4 ${step.tone}`}>
              <span className="font-mono text-xs text-slate-500">Step {i + 1}</span>
              <h3 className="mt-1 text-sm font-semibold text-slate-100">{step.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{step.body}</p>
            </li>
          ))}
        </ol>
      </section>
    </div>
  )
}
