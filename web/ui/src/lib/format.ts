// Small, dependency-free formatting helpers.

/** "HH:MM:SS.mmm" in local time, matching the old vanilla shell. */
export function fmtClock(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`
}

export function fmtDateTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toISOString().replace('T', ' ').replace('Z', ' UTC')
}

const intFmt = new Intl.NumberFormat('en-US')
export function fmtInt(n: number | undefined | null): string {
  if (n == null || Number.isNaN(n)) return '—'
  return intFmt.format(Math.round(n))
}

export function fmtNum(n: number, digits = 2): string {
  if (n == null || Number.isNaN(n)) return '—'
  if (n !== 0 && Math.abs(n) < 0.001) return n.toExponential(2)
  return n.toLocaleString('en-US', { maximumFractionDigits: digits })
}

export function fmtPct(x: number, digits = 1): string {
  if (x == null || Number.isNaN(x)) return '—'
  return `${(x * 100).toFixed(digits)}%`
}

export function fmtBytes(n: number): string {
  if (n == null || Number.isNaN(n)) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`
}

export function fmtDuration(sec: number): string {
  if (sec == null || Number.isNaN(sec)) return '—'
  if (sec < 1) return `${(sec * 1000).toFixed(1)} ms`
  if (sec < 60) return `${sec.toFixed(2)} s`
  const m = Math.floor(sec / 60)
  const s = Math.round(sec % 60)
  return `${m}m ${s}s`
}

/** "12s ago" / "3m ago" / "just now" for a past ISO timestamp. A zero/invalid
 *  time returns "—" (never observed). */
export function fmtAgo(iso: string, now: number = Date.now()): string {
  const t = new Date(iso).getTime()
  if (Number.isNaN(t) || t <= 0) return '—'
  const s = Math.max(0, Math.round((now - t) / 1000))
  if (s < 2) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}m ago`
  return `${Math.floor(h / 24)}d ${h % 24}h ago`
}

export function endpoint(ip: string, port: number): string {
  if (!ip) return '—'
  return port ? `${ip}:${port}` : ip
}
