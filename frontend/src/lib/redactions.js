// Redaction tokens written by the gateway's masker (config/actions.py
// _MASKING_RULES and backend/routes.py REDACTION_TOKENS). Keep in sync.

export const REDACTION_TYPES = {
  EMAIL: {
    label: 'Email',
    removed: 'email address',
    pill: 'bg-accent/10 text-accent ring-accent/30',
  },
  KEY: {
    label: 'API key / credential',
    removed: 'secret key',
    pill: 'bg-danger/10 text-danger-fg ring-danger/30',
  },
  CC: {
    label: 'Card number',
    removed: 'card number',
    pill: 'bg-warn/10 text-warn-fg ring-warn/30',
  },
}

const TOKEN = /\[REDACTED_(EMAIL|KEY|CC)\]/g

/** Splits text into plain runs and redaction tokens: [{ text } | { token, type }]. */
export function splitRedactions(text = '') {
  const parts = []
  let last = 0
  for (const match of text.matchAll(TOKEN)) {
    if (match.index > last) parts.push({ text: text.slice(last, match.index) })
    parts.push({ token: match[0], type: match[1] })
    last = match.index + match[0].length
  }
  if (last < text.length) parts.push({ text: text.slice(last) })
  return parts
}

/** { EMAIL: n, KEY: n, CC: n } with only the types that occur. */
export function countRedactions(...texts) {
  const counts = {}
  for (const text of texts) {
    for (const match of (text || '').matchAll(TOKEN)) counts[match[1]] = (counts[match[1]] ?? 0) + 1
  }
  return counts
}
