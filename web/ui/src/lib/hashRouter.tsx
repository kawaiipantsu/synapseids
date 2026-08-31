import { useEffect, useMemo, useState } from 'react'

// Hash routing only (PROJECT.md §19 SPA task): every document request stays on
// "/", so synapsed needs no SPA-fallback handler and internal/api is untouched.
// A clean-URL history router is deliberately a later issue.

export const DEFAULT_ROUTE = '/flow-log'

export function currentPath(): string {
  const raw = window.location.hash.replace(/^#/, '')
  const path = raw.split('?')[0]!.trim()
  return path && path.startsWith('/') ? path : DEFAULT_ROUTE
}

/** The raw hash target, path and query together, e.g. "/investigate?host=10.0.0.1". */
function currentTarget(): string {
  const raw = window.location.hash.replace(/^#/, '').trim()
  return raw.startsWith('/') ? raw : DEFAULT_ROUTE
}

/** The query string after the path, e.g. "host=10.0.0.1". */
export function currentQuery(): string {
  const raw = window.location.hash.replace(/^#/, '')
  const i = raw.indexOf('?')
  return i === -1 ? '' : raw.slice(i + 1)
}

/** Navigate to a route. `path` may carry a query string. */
export function navigate(path: string): void {
  if (currentTarget() === path) return
  window.location.hash = path
}

/**
 * Navigate to `path` with `params` as the hash query. Empty values are dropped,
 * and every value is encoded — host addresses reaching here are packet-derived
 * strings and must never be pasted into a URL raw (PROJECT.md §21, §28.11).
 */
export function navigateWith(path: string, params: Record<string, string | undefined>): void {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v) q.set(k, v)
  }
  const s = q.toString()
  navigate(s ? `${path}?${s}` : path)
}

/** Subscribe a component to the active hash route. */
export function useHashRoute(): string {
  const [path, setPath] = useState<string>(() => currentPath())
  useEffect(() => {
    const onChange = () => setPath(currentPath())
    window.addEventListener('hashchange', onChange)
    // Normalize a bare "/" or empty hash to the default on first mount.
    if (window.location.hash.replace(/^#/, '').trim() === '') {
      window.location.replace(`#${DEFAULT_ROUTE}`)
    }
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return path
}

/**
 * Subscribe a component to the hash query string. It keeps its own state
 * because useHashRoute's state is the path alone: navigating from
 * "#/investigate?host=a" to "#/investigate?host=b" fires hashchange but leaves
 * the path identical, so React would bail out of the re-render.
 */
export function useHashQuery(): URLSearchParams {
  const [q, setQ] = useState<string>(() => currentQuery())
  useEffect(() => {
    const onChange = () => setQ(currentQuery())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return useMemo(() => new URLSearchParams(q), [q])
}

type LinkProps = React.AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }

export function Link({ to, children, ...rest }: LinkProps) {
  return (
    <a href={`#${to}`} {...rest}>
      {children}
    </a>
  )
}
