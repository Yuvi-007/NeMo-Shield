import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// The admin key is never bundled. An operator types it into the console and it
// lives in sessionStorage for this tab only.
const ADMIN_KEY_STORAGE = 'nemo-shield-admin-key'

export function getAdminKey() {
  return sessionStorage.getItem(ADMIN_KEY_STORAGE) || ''
}

const ADMIN_KEY_EVENT = 'nemo-shield:admin-key'

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
  if (normalized) sessionStorage.setItem(ADMIN_KEY_STORAGE, normalized)
  else sessionStorage.removeItem(ADMIN_KEY_STORAGE)
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

export async function sendChat(prompt) {
  const { data } = await client.post('/guard/chat', { prompt })
  return data
}

export async function runABTest(prompt) {
  const { data } = await client.post('/guard/ab-test', { prompt })
  return data
}

export async function getTelemetry() {
  const { data } = await client.get('/telemetry', { headers: adminHeaders() })
  return data
}

export async function getAuditLogs(limit = 50, skip = 0, verdict = null) {
  const params = { limit, skip }
  if (verdict) params.verdict = verdict
  const { data } = await client.get('/audit/logs', { params, headers: adminHeaders() })
  return data
}

export async function getHealth() {
  const { data } = await client.get('/health')
  return data
}

export function describeError(error) {
  const status = error?.response?.status
  if (status === 401) {
    return 'Admin key missing or invalid. Enter it in the "Admin key" field in the header.'
  }
  if (status === 503 && error?.response?.data?.detail?.startsWith?.('Admin API disabled')) {
    return 'Admin API is disabled: set ADMIN_API_KEY on the backend.'
  }
  if (status === 429) {
    return 'Rate limit exceeded. Wait a minute and try again.'
  }
  if (error?.response?.data?.detail) {
    const detail = error.response.data.detail
    return typeof detail === 'string' ? detail : 'The gateway rejected the request. Check the prompt length (1–2000 characters).'
  }
  if (error?.request) {
    return `Gateway unreachable at ${API_BASE_URL}. Start the FastAPI server and try again.`
  }
  return error?.message || 'Unexpected error.'
}
