import { Component } from 'react'

/**
 * Catches render errors below it and shows a fallback instead of letting React
 * unmount the whole tree. App wraps each view in one keyed by tab, so the header
 * stays usable and switching tabs clears the error.
 */
export default class ErrorBoundary extends Component {
  state = { error: null }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('[NeMo-Shield] view crashed:', error, info?.componentStack)
  }

  reset = () => this.setState({ error: null })

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <section role="alert" className="glass rounded-lg border border-danger/40 px-5 py-6">
        <h2 className="text-base font-semibold text-danger-fg">{this.props.title ?? 'This view hit an error'}</h2>
        <p className="mt-1 text-sm text-fg-muted">
          The rest of the console still works. This usually means the gateway sent data the console did not expect.
        </p>
        <pre className="mt-3 overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-xs text-fg-3">
          {String(error?.message || error)}
        </pre>
        <button
          type="button"
          onClick={this.reset}
          className="mt-4 rounded-md border border-line-strong px-3 py-1.5 text-sm text-fg-2 transition-colors hover:border-accent/60"
        >
          Try again
        </button>
      </section>
    )
  }
}
