import axios from 'axios'

const client = axios.create({
  baseURL: 'http://localhost:8000/api/v1',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

export async function sendChat(prompt) {
  const { data } = await client.post('/guard/chat', { prompt })
  return data
}

export async function runABTest(prompt) {
  const { data } = await client.post('/guard/ab-test', { prompt })
  return data
}

export async function getTelemetry() {
  const { data } = await client.get('/telemetry')
  return data
}

export async function getAuditLogs(limit = 50, skip = 0, verdict = null) {
  const params = { limit, skip }
  if (verdict) params.verdict = verdict
  const { data } = await client.get('/audit/logs', { params })
  return data
}

export async function getHealth() {
  const { data } = await client.get('/health')
  return data
}

export function describeError(error) {
  if (error?.response?.data?.detail) {
    const detail = error.response.data.detail
    return typeof detail === 'string' ? detail : 'The gateway rejected the request. Check the prompt length (1–2000 characters).'
  }
  if (error?.request) {
    return 'Gateway unreachable at localhost:8000. Start the FastAPI server and try again.'
  }
  return error?.message || 'Unexpected error.'
}
