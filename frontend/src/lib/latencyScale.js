// Shared log-scale latency helpers. Fast-path halts take ~0.04 ms and a full
// Colang pass ~100 ms: three-plus orders of magnitude apart, so a linear scale
// would pin every fast-path block at zero.

export const MIN_LOG = -2 // 0.01 ms
export const MAX_LOG = 3 // 1000 ms
export const FAST_PATH_MS = 1
export const BUDGET_MS = 100

/** 0..1 position of `ms` on the log scale. */
export function position(ms) {
  if (!(ms > 0)) return 0
  return Math.min(1, Math.max(0, (Math.log10(ms) - MIN_LOG) / (MAX_LOG - MIN_LOG)))
}

// Class names are spelled out in full so Tailwind's source scan can find them.
export function zoneFor(ms) {
  if (ms < FAST_PATH_MS) return { name: 'Fast path', stroke: 'stroke-ok', dot: 'bg-ok', text: 'text-ok-fg' }
  if (ms <= BUDGET_MS) return { name: 'Colang rails', stroke: 'stroke-accent', dot: 'bg-accent', text: 'text-accent' }
  return { name: 'Over budget', stroke: 'stroke-warn', dot: 'bg-warn', text: 'text-warn-fg' }
}

export function formatMs(ms) {
  return ms < 1 ? `${ms.toFixed(2)} ms` : `${ms.toFixed(1)} ms`
}
