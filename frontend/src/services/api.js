import axios from 'axios'

// Base URL comes from VITE_API_BASE_URL at build time. Without it the console
// calls the same origin at /api/v1: the Vite dev server proxies that path to
// the backend (see vite.config.js), and a production build without the variable
// fails loudly (the host answers with HTML, which the shape checks below catch)
// instead of silently calling a developer's machine.
export function resolveBaseUrl(raw) {
  const value = (raw || '').trim().replace(/\/+$/, '')
  return value || '/api/v1'
}

export const API_BASE_URL = resolveBaseUrl(import.meta.env.VITE_API_BASE_URL)
const BASE_URL_FROM_ENV = Boolean((import.meta.env.VITE_API_BASE_URL || '').trim())

if (import.meta.env.PROD && !BASE_URL_FROM_ENV) {
  console.warn('[NeMo-Shield] VITE_API_BASE_URL is not set; API calls go to this origin at /api/v1.')
}

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

/** Thrown when the gateway answers 2xx with a body that is not the documented JSON shape. */
export class MalformedResponseError extends Error {
  constructor(what, data) {
    const html = typeof data === 'string' && /^\s*</.test(data)
    super(
      html
        ? `Expected JSON from ${what} but got an HTML page. Check that VITE_API_BASE_URL points at the FastAPI gateway.`
        : `The gateway returned a malformed ${what} response.`,
    )
    this.name = 'MalformedResponseError'
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requireShape(data, what, fields) {
  if (!isRecord(data)) throw new MalformedResponseError(what, data)
  for (const [field, type] of Object.entries(fields)) {
    if (typeof data[field] !== type) throw new MalformedResponseError(what, data)
  }
  return data
}

const num = (value) => (Number.isFinite(Number(value)) ? Number(value) : 0)

// ---------------------------------------------------------------------------
// Admin key (session only) and its verification status
// ---------------------------------------------------------------------------

// The admin key is never bundled. An operator types it into the console and it
// lives in sessionStorage for this tab only.
const ADMIN_KEY_STORAGE = 'nemo-shield-admin-key'
const ADMIN_KEY_EVENT = 'nemo-shield:admin-key'

export function getAdminKey() {
  try {
    return sessionStorage.getItem(ADMIN_KEY_STORAGE) || ''
  } catch {
    return ''
  }
}

// Keys are often copied from .env, where they may be quoted (ADMIN_API_KEY="...").
// The quotes are .env syntax, not part of the key, so drop one surrounding pair.
export function normalizeAdminKey(key) {
  const trimmed = (key || '').trim()
  const quoted = /^(["'])(.*)\1$/.exec(trimmed)
  return (quoted ? quoted[2] : trimmed).trim()
}

export function setAdminKey(key) {
  const normalized = normalizeAdminKey(key)
  if (normalized === getAdminKey()) return
  try {
    if (normalized) sessionStorage.setItem(ADMIN_KEY_STORAGE, normalized)
    else sessionStorage.removeItem(ADMIN_KEY_STORAGE)
  } catch {
    // Storage disabled: the key simply won't persist across reloads.
  }
  // A new (or cleared) key has not been checked yet.
  setAuthStatus('unknown')
  window.dispatchEvent(new Event(ADMIN_KEY_EVENT))
}

// Lets admin views refetch as soon as a key is saved. Returns an unsubscribe function.
export function onAdminKeyChange(callback) {
  window.addEventListener(ADMIN_KEY_EVENT, callback)
  return () => window.removeEventListener(ADMIN_KEY_EVENT, callback)
}

function adminHeaders() {
  const key = getAdminKey()
  return key ? { 'X-Admin-Key': key } : {}
}

/**
 * What the last admin call said about the key:
 *   unknown (not checked since load or since the key changed) | accepted |
 *   missing (401, no key) | rejected (401, wrong key) | unconfigured (503, no ADMIN_API_KEY)
 * Starting from `unknown` means the very first failure is reported too.
 */
let authStatus = 'unknown'
const authListeners = new Set()

function setAuthStatus(next) {
  if (next === authStatus) return
  const previous = authStatus
  authStatus = next
  authListeners.forEach((listener) => listener(next, previous))
}

export function getAuthStatus() {
  return authStatus
}

export function subscribeAuthStatus(listener) {
  authListeners.add(listener)
  return () => authListeners.delete(listener)
}

function isAdminDisabled(error) {
  const detail = error?.response?.data?.detail
  return error?.response?.status === 503 && typeof detail === 'string' && detail.startsWith('Admin API disabled')
}

async function adminGet(path, params) {
  try {
    const { data } = await client.get(path, { params, headers: adminHeaders() })
    setAuthStatus('accepted')
    return data
  } catch (error) {
    if (error?.response?.status === 401) setAuthStatus(getAdminKey() ? 'rejected' : 'missing')
    else if (isAdminDisabled(error)) setAuthStatus('unconfigured')
    throw error
  }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

function normalizeChat(data) {
  requireShape(data, '/guard/chat', { reply: 'string', verdict: 'string' })
  return {
    ...data,
    confidence: num(data.confidence),
    latency_ms: num(data.latency_ms),
    rail_path: typeof data.rail_path === 'string' ? data.rail_path : null,
  }
}

/** One prompt, or a conversation: pass `messages` ([{ role, content }], ending on a user turn). */
export async function sendChat(prompt, { messages, sessionId } = {}) {
  const body = messages ? { messages } : { prompt }
  if (sessionId) body.session_id = sessionId
  const { data } = await client.post('/guard/chat', body)
  return normalizeChat(data)
}

export async function runABTest(prompt) {
  const { data } = await client.post('/guard/ab-test', { prompt })
  requireShape(data, '/guard/ab-test', { unguarded_reply: 'string', guarded_reply: 'string' })
  return { ...data, latency_delta_ms: num(data.latency_delta_ms), intervened: Boolean(data.intervened) }
}

export async function getTelemetry() {
  const data = await adminGet('/telemetry')
  requireShape(data, '/telemetry', { total_requests: 'number' })
  return data
}

export async function getAuditLogs(limit = 50, skip = 0, verdict = null) {
  const params = { limit, skip }
  if (verdict) params.verdict = verdict
  const data = await adminGet('/audit/logs', params)
  if (!Array.isArray(data)) throw new MalformedResponseError('/audit/logs', data)
  return data.filter(isRecord).map((r, i) => ({
    ...r,
    id: r.id ?? `row-${i}`,
    prompt: typeof r.prompt === 'string' ? r.prompt : '',
    reply: typeof r.reply === 'string' ? r.reply : '',
    latency_ms: num(r.latency_ms),
    confidence: num(r.confidence),
  }))
}

export async function getHealth() {
  const { data } = await client.get('/health')
  return requireShape(data, '/health', { status: 'string' })
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

function describeValidation(detail) {
  // FastAPI 422: [{ loc: ['body', 'messages', 0, 'content'], msg: '...' }, ...]
  const first = Array.isArray(detail) ? detail[0] : null
  if (!first) return 'The gateway rejected the request.'
  const msg = String(first.msg || '').replace(/^Value error, /, '')
  if (/at most \d+ characters/.test(msg)) return 'Prompt is too long: the gateway accepts up to 2,000 characters per turn.'
  if (/at most \d+ items/.test(msg)) return 'Conversation is too long: the gateway accepts up to 20 turns.'
  if (/empty or whitespace-only|at least 1 character/.test(msg)) return 'Prompt is empty. Type something other than spaces.'
  const field = (first.loc || []).filter((part) => part !== 'body').join('.')
  return `The gateway rejected the request${field ? ` (${field})` : ''}: ${msg}`
}

/** Machine-readable kind for an error, so views can choose a fallback state. */
export function errorKind(error) {
  const status = error?.response?.status
  if (error instanceof MalformedResponseError) return 'malformed'
  if (status === 401) return 'unauthorized'
  if (isAdminDisabled(error)) return 'unconfigured'
  if (status === 422) return 'validation'
  if (status === 429) return 'rate-limited'
  if (status >= 500) return 'server'
  if (error?.code === 'ECONNABORTED') return 'timeout'
  if (error?.request && !error?.response) return 'offline'
  return 'unknown'
}

export function describeError(error) {
  const status = error?.response?.status
  switch (errorKind(error)) {
    case 'malformed':
      return error.message
    case 'unauthorized':
      return getAdminKey()
        ? 'Admin key rejected (401). Check it matches ADMIN_API_KEY on the backend.'
        : 'Admin key required (401). Enter it in the "Admin key" field in the header.'
    case 'unconfigured':
      return 'Admin API is disabled (503): set ADMIN_API_KEY on the backend and restart it.'
    case 'validation':
      return describeValidation(error.response.data?.detail)
    case 'rate-limited':
      return 'Rate limit exceeded (60 requests/min). Wait a minute and try again.'
    case 'server':
      return status === 503
        ? 'Gateway temporarily unavailable (503). A sleeping free-tier host can take ~30 s to wake; retry shortly.'
        : `Gateway error (${status}). Check the backend logs.`
    case 'timeout':
      return 'The gateway did not answer within 30 s. It may be waking up; try again.'
    case 'offline':
      return `Gateway unreachable at ${API_BASE_URL}. Start the FastAPI server and try again.`
    default: {
      const detail = error?.response?.data?.detail
      if (typeof detail === 'string') return detail
      return error?.message || 'Unexpected error.'
    }
  }
}
