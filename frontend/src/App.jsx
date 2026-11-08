import { useState } from 'react'
import AuditLedger from './components/AuditLedger'
import Navigation from './components/Navigation'
import Playground from './components/Playground'
import PolicyHub from './components/PolicyHub'
import Telemetry from './components/Telemetry'

const VIEWS = {
  playground: Playground,
  telemetry: Telemetry,
  policy: PolicyHub,
  audit: AuditLedger,
}

export default function App() {
  const [activeTab, setActiveTab] = useState('playground')
  const View = VIEWS[activeTab]

  return (
    <div className="min-h-screen text-fg">
      <Navigation activeTab={activeTab} onTabChange={setActiveTab} />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
        <View />
      </main>
    </div>
  )
}
