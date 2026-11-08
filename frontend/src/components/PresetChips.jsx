import { ATTACKS, MULTILINGUAL_ATTACKS } from './presets'

const CHIP =
  'rounded-full border border-line-strong px-3 py-1 text-xs text-fg-3 transition-colors hover:border-danger/50 hover:text-danger-fg disabled:opacity-50'

/** Quick-select attack chips: English presets plus multilingual obfuscated injections. */
export default function PresetChips({ onPick, disabled = false, showEnglish = true }) {
  return (
    <div className="space-y-2">
      {showEnglish && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="mr-1 text-sm text-fg-muted">Load an attack:</span>
          {ATTACKS.map((attack) => (
            <button key={attack.label} type="button" disabled={disabled} onClick={() => onPick(attack.prompt)} className={CHIP}>
              {attack.label}
            </button>
          ))}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <span className="mr-1 text-sm text-fg-muted">Multilingual obfuscation:</span>
        {MULTILINGUAL_ATTACKS.map((attack) => (
          <button
            key={attack.lang}
            type="button"
            disabled={disabled}
            onClick={() => onPick(attack.prompt)}
            title={`${attack.label} text wrapping an English override hidden with ${attack.technique}`}
            className={CHIP}
          >
            <span lang={attack.lang}>{attack.label}</span>
            <span className="ml-1.5 font-mono text-[10px] uppercase text-fg-subtle">{attack.lang}</span>
            <span className="ml-1.5 text-fg-subtle">· {attack.technique}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
