import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import ErrorBoundary from './components/ErrorBoundary'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {/* Last line of defence; each view also has its own boundary inside App. */}
    <ErrorBoundary title="The console hit an error">
      <App />
    </ErrorBoundary>
  </StrictMode>,
)
