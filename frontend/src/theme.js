// Theme preference: 'light' | 'dark' | 'system', persisted in localStorage.
// The inline script in index.html applies the same logic before first paint,
// so the page never flashes the wrong theme. Keep the two in sync.

const STORAGE_KEY = 'nemo-shield-theme'
const PREFERENCES = ['light', 'dark', 'system']
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)')
const listeners = new Set()

export function getThemePreference() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    return PREFERENCES.includes(stored) ? stored : 'system'
  } catch {
    return 'system'
  }
}

function applyTheme(preference) {
  const dark = preference === 'dark' || (preference === 'system' && darkQuery.matches)
  document.documentElement.classList.toggle('dark', dark)
}

export function setThemePreference(preference) {
  if (!PREFERENCES.includes(preference)) return
  try {
    localStorage.setItem(STORAGE_KEY, preference)
  } catch {
    // Private mode or blocked storage: the choice still applies for this page.
  }
  applyTheme(preference)
  listeners.forEach((notify) => notify())
}

// useSyncExternalStore-compatible subscription.
export function subscribeTheme(notify) {
  listeners.add(notify)
  return () => listeners.delete(notify)
}

// Follow the OS setting live while the preference is 'system'.
darkQuery.addEventListener('change', () => {
  if (getThemePreference() === 'system') applyTheme('system')
})
