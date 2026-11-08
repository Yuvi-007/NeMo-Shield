// Coerces a /telemetry payload into the numeric shape the Telemetry view
// renders, so one malformed field ("oops", null, NaN) can't crash it.

const COUNT_FIELDS = ['total_requests', 'blocked_requests', 'altered_requests', 'clean_requests']
const METRIC_FIELDS = ['block_rate_pct', 'avg_latency_ms']
const BREAKDOWN_COUNTS = ['fast_path_blocks', 'colang_blocks', 'sanitized_outputs']
const BREAKDOWN_METRICS = ['p50_latency_ms', 'p99_latency_ms']
const LATENCY_ZONES = ['under_1ms', '1_to_100ms', 'over_100ms']

const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

/** Finite number, else 0. */
export function toNumber(value) {
  const n = Number(value)
  return Number.isFinite(n) ? n : 0
}

/** Non-negative finite number, else 0. */
export function toCount(value) {
  return Math.max(0, toNumber(value))
}

/**
 * Every field the view reads comes back as a finite number. Rail-breakdown
 * fields that are absent stay absent: that is how RailBreakdown tells an
 * older backend (no breakdown) apart from a real zero.
 */
export function normalizeTelemetry(raw) {
  const data = isRecord(raw) ? raw : {}
  const out = {}
  for (const field of COUNT_FIELDS) out[field] = toCount(data[field])
  for (const field of METRIC_FIELDS) out[field] = Math.max(0, toNumber(data[field]))
  out.block_rate_pct = Math.min(100, out.block_rate_pct)

  out.threat_distribution = Object.fromEntries(
    Object.entries(isRecord(data.threat_distribution) ? data.threat_distribution : {}).map(([tag, n]) => [
      tag,
      toCount(n),
    ]),
  )

  for (const field of BREAKDOWN_COUNTS) if (field in data) out[field] = toCount(data[field])
  for (const field of BREAKDOWN_METRICS) if (field in data) out[field] = Math.max(0, toNumber(data[field]))
  if ('latency_zones' in data) {
    const zones = isRecord(data.latency_zones) ? data.latency_zones : {}
    out.latency_zones = Object.fromEntries(LATENCY_ZONES.map((zone) => [zone, toCount(zones[zone])]))
  }
  return out
}
