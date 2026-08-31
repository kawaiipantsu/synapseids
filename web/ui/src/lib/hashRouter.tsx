import { useEffect, useState } from 'react'

// Hash routing only (PROJECT.md §19 SPA task): every document request stays on
// "/", so synapsed needs no SPA-fallback handler and internal/api is untouched.
// A clean-URL history router is deliberately a later issue.

export const DEFAULT_ROUTE = '/flow-log'

export function currentPath(): string {
  const raw = window.location.hash.replace(/^#/, '')
  const path = raw.split('?')[0]!.trim()
  return path && path.startsWith('/') ? path : DEFAULT_ROUTE
}

export function navigate(path: string): void {
  if (currentPath() === path) return
  window.location.hash = path
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

type LinkProps = React.AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }

export function Link({ to, children, ...rest }: LinkProps) {
  return (
    <a href={`#${to}`} {...rest}>
      {children}
    </a>
  )
}
