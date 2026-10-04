import { useCallback, useSyncExternalStore } from 'react'

export interface IPContext {
  ip: string
  scope: string
  status: string
  stale: boolean
  updated_at: string
  expires_at: string
  dns: { status: string; names: string[] }
  geo: { status: string; source?: string; country?: string; city?: string; continent?: string; subdivision?: string; latitude?: number; longitude?: number; accuracy_km?: number; timezone?: string; asn?: number; organization?: string }
  whois: { status: string; source?: string; handle?: string; name?: string; start?: string; end?: string; type?: string; country?: string; updated?: string }
}
type Cached = { value?: IPContext; next: number; listeners: Set<() => void> }
const cache = new Map<string, Cached>()
let timer: ReturnType<typeof setTimeout> | undefined
let running = false

function schedule() {
  if (!timer && !running) timer = setTimeout(() => void flush(), 300)
}
async function flush() {
  timer = undefined
  running = true
  const now = Date.now()
  const due = [...cache.entries()].filter(([, row]) => row.listeners.size && row.next <= now).slice(0, 64)
  if (due.length) {
    const params = new URLSearchParams()
    due.forEach(([ip]) => params.append('ip', ip))
    try {
      const response = await fetch(`/api/v1/enrichment?${params}`)
      if (!response.ok) throw new Error('IP context unavailable')
      const { hosts } = await response.json() as { hosts: IPContext[] }
      const byIP = new Map(hosts.map((h) => [h.ip, h]))
      for (const [ip, row] of due) {
        const value = byIP.get(ip)
        row.next = now + 30000
        if (!value) continue
        row.value = value
        row.next = ['pending', 'refreshing', 'busy', 'unobserved'].includes(value.status)
          ? now + 2000 : Math.max(now + 30000, Date.parse(value.expires_at) || 0)
        row.listeners.forEach((notify) => notify())
      }
    } catch {
      for (const [, row] of due) row.next = now + 30000
    }
  }
  // Evict inactive entries first, without dropping a mounted row's subscription.
  if (cache.size > 2048) {
    for (const [ip, row] of cache) {
      if (!row.listeners.size) cache.delete(ip)
      if (cache.size <= 2048) break
    }
  }
  running = false
  if ([...cache.values()].some((row) => row.listeners.size)) timer = setTimeout(() => void flush(), 1000)
}

/** One shared batch poll for visible IPs across lists, graph and host details. */
export function useIPContext(ip: string) {
  const subscribe = useCallback((notify: () => void) => {
    let row = cache.get(ip)
    if (!row) { row = { next: 0, listeners: new Set() }; cache.set(ip, row) }
    row.listeners.add(notify)
    schedule()
    return () => { row.listeners.delete(notify) }
  }, [ip])
  const snapshot = useCallback(() => cache.get(ip)?.value, [ip])
  return useSyncExternalStore(subscribe, snapshot)
}

export function countryName(code?: string) {
  if (!code || !/^[A-Z]{2}$/.test(code)) return ''
  try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(code) ?? code } catch { return code }
}
export function countryFlag(code?: string) {
  return code && /^[A-Z]{2}$/.test(code)
    ? String.fromCodePoint(...[...code].map((c) => 127397 + c.charCodeAt(0))) : ''
}
