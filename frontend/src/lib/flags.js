// Advisory request flags and classifier signal names from the gateway
// (backend/models.py RequestFlag, config/actions.py _THREAT_SIGNALS).
// Flags never change a verdict on their own; they explain what the gateway saw.

export const FLAGS = {
  ENCODED_PAYLOAD: {
    label: 'Encoded payload',
    hint: 'A base64 or hex run decoded to readable text, and that text was rescanned with the same injection signals.',
    pill: 'bg-violet-500/10 text-violet-700 ring-violet-500/30 dark:text-violet-300',
  },
  UNCOVERED_LANGUAGE: {
    label: 'Language not covered',
    hint: 'Much of this conversation is in a non-Latin script. The injection signatures are English-only, so it was flagged rather than fully screened. The verdict is unchanged.',
    pill: 'bg-accent/10 text-accent ring-accent/30',
  },
}

export const SIGNALS = {
  instruction_override: 'Instruction override',
  jailbreak_persona: 'Jailbreak persona',
  system_prompt_extraction: 'System prompt extraction',
  delimiter_injection: 'Delimiter injection',
  secret_exfiltration: 'Secret exfiltration',
  role_override: 'Role override',
  obfuscation: 'Obfuscation keyword',
}

/** "base64:hex:instruction_override" -> { layers: ['base64', 'hex'], name: 'instruction_override' } */
export function parseSignal(signal) {
  const parts = String(signal).split(':')
  return { layers: parts.slice(0, -1), name: parts[parts.length - 1] }
}
