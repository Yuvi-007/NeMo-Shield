// Tiny toast store, read with useSyncExternalStore. Each toast:
// { id, tone: 'danger' | 'warn' | 'ok' | 'info', title, body, action? }

const AUTO_DISMISS_MS = 8000
let toasts = []
const listeners = new Set()
let nextId = 1

function emit() {
  listeners.forEach((listener) => listener())
}

export function getToasts() {
  return toasts
}

export function subscribeToasts(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function dismissToast(id) {
  toasts = toasts.filter((t) => t.id !== id)
  emit()
}

/** Shows a toast; one with the same `key` replaces the older one instead of stacking. */
export function pushToast({ key, ...toast }) {
  const id = nextId++
  toasts = [...toasts.filter((t) => !key || t.key !== key), { id, key, ...toast }].slice(-4)
  emit()
  setTimeout(() => dismissToast(id), AUTO_DISMISS_MS)
  return id
}
