import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'

function mountReact() {
  const rootEl = document.getElementById('react-root') || document.getElementById('login-react')
  if (rootEl) {
    const root = createRoot(rootEl)
    root.render(
      <React.StrictMode>
        <App />
      </React.StrictMode>
    )
  }
}

// Try to mount immediately; in Flask pages the element exists on load.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mountReact)
} else {
  mountReact()
}
