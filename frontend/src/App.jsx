import { useState } from 'react'
import AuditLedger from './components/AuditLedger'
import ErrorBoundary from './components/ErrorBoundary'
import Navigation from './components/Navigation'
import Playground from './components/Playground'
import PolicyHub from './components/PolicyHub'
import Telemetry from './components/Telemetry'
import Toaster from './components/Toaster'
import { TABS } from './tabs'

const VIEWS = {
  playground: Playground,
  telemetry: Telemetry,
  policy: PolicyHub,
  audit: AuditLedger,
}

export default function App() {
  const [activeTab, setActiveTab] = useState('playground')
  const View = VIEWS[activeTab]
  const label = TABS.find((tab) => tab.id === activeTab)?.label ?? 'This view'

  return (
    <div className="min-h-screen text-fg">
      <Navigation activeTab={activeTab} onTabChange={setActiveTab} />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
        {/* Keyed by tab: a crash stays inside one view, and switching tabs clears it. */}
        <ErrorBoundary key={activeTab} title={`${label} hit an error`}>
          <View />
        </ErrorBoundary>
      </main>
      <Toaster />
    </div>
  )
}
