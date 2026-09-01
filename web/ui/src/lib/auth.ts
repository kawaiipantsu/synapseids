// API token handling for a daemon with `auth.enabled` (issue #58).
//
// When synapsed is reached directly (not through a reverse proxy that carries
// the credential), every /api/v1 call needs `Authorization: Bearer <token>` and
// the WebSocket needs `?token=<token>`. This module keeps one token in
// localStorage and installs a `window.fetch` wrapper that attaches it, so no
// per-call change is needed.
//
// Getting a token in:
//   - open the SPA once as `…/?token=SECRET#/dashboard` — it is stored and
//     stripped from the URL;
//   - or from devtools: `window.__synapse.setToken('SECRET')`.
//
// A same-host / loopback daemon with the default `allow_loopback: true` needs
// none of this.

const KEY = 'synapseids.api-token'

export function apiToken(): string {
  try {
    return localStorage.getItem(KEY) ?? ''
  } catch {
    return ''
  }
}

export function setApiToken(tok: string): void {
  try {
    if (tok) localStorage.setItem(KEY, tok)
    else localStorage.removeItem(KEY)
  } catch {
    /* private mode / storage disabled — the in-URL form still works per load */
  }
}

/** Append the token to a WebSocket URL when one is set. */
export function withToken(url: string): string {
  const t = apiToken()
  if (!t) return url
  return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(t)
}

/**
 * Called once at boot. Adopts a `?token=` from the current URL (then removes it
 * so it does not linger in history), installs the fetch wrapper, and exposes a
 * small `window.__synapse` helper.
 */
export function installAuth(): void {
  try {
    const u = new URL(window.location.href)
    const t = u.searchParams.get('token')
    if (t) {
      setApiToken(t)
      u.searchParams.delete('token')
      window.history.replaceState(null, '', u.toString())
    }
  } catch {
    /* non-standard URL — ignore */
  }

  const orig = window.fetch.bind(window)
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const t = apiToken()
    if (!t) return orig(input, init)
    const headers = new Headers(init?.headers)
    if (!headers.has('Authorization')) headers.set('Authorization', 'Bearer ' + t)
    return orig(input, { ...init, headers })
  }

  ;(window as unknown as { __synapse?: unknown }).__synapse = {
    setToken: setApiToken,
    clearToken: () => setApiToken(''),
    token: apiToken,
  }
}
