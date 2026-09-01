import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from './App'
import { installAuth } from './lib/auth'
import './styles.css'

// Adopt a `?token=` from the URL and attach the bearer token to every fetch,
// for a daemon with auth.enabled (issue #58). A no-op when no token is set.
installAuth()

const el = document.getElementById('root')
if (!el) throw new Error('#root element missing from index.html')

createRoot(el).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
