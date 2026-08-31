import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'

import { getClassifications } from '../api/client'
import { useStream } from '../api/stream'
import type { Classification, WsEvent } from '../api/types'
import { FlowInspector } from '../components/FlowInspector'
import { CLASS_NAMES, LOW_CONFIDENCE, classColor, roleInitial } from '../lib/classes'
import { endpoint, fmtClock, fmtInt, fmtPct } from '../lib/format'
import { usePersistedState } from '../lib/persist'

const PROTOS = ['TCP', 'UDP', 'ICMP']
const SEED_LIMIT = 300
const SEEN_CAP = 10_000

function clampRows(n: number): number {
  if (Number.isNaN(n)) return 2000
  return Math.min(20_000, Math.max(100, Math.round(n)))
}

function key(c: Classification): string {
  return `${c.flow_id}:${c.ts}`
}

export function FlowLog() {
  const { subscribe } = useStream()

  const [rows, setRows] = useState<Classification[]>([])
  const [paused, setPaused] = useState(false)
  const [bufferedCount, setBufferedCount] = useState(0)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [inspect, setInspect] = useState<Classification | null>(null)
  const [showJump, setShowJump] = useState(false)
  const [kiosk, setKiosk] = useState(false)

  const [density, setDensity] = usePersistedState<'comfortable' | 'compact'>('flowlog.density', 'comfortable')
  const [maxRows, setMaxRows] = usePersistedState<number>('flowlog.maxRows', 2000)
  const [fClass, setFClass] = usePersistedState('flowlog.class', '')
  const [fMinConf, setFMinConf] = usePersistedState('flowlog.minConf', 0)
  const [fProto, setFProto] = usePersistedState('flowlog.proto', '')
  const [fText, setFText] = usePersistedState('flowlog.text', '')

  const pausedRef = useRef(paused)
  pausedRef.current = paused
  const maxRowsRef = useRef(maxRows)
  maxRowsRef.current = maxRows
  const bufferRef = useRef<Classification[]>([])
  const seenRef = useRef<Set<string>>(new Set())
  const stickRef = useRef(true)
  const scrollerRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  const pass = useCallback(
    (c: Classification): boolean => {
      if (fMinConf > 0 && c.result.score * 100 < fMinConf) return false
      if (fClass && c.result.class !== fClass) return false
      if (fProto && c.proto.toUpperCase() !== fProto) return false
      if (fText) {
        const q = fText.toLowerCase()
        const hay = `${c.initiator_ip}:${c.initiator_port} ${c.responder_ip}:${c.responder_port}`.toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    },
    [fMinConf, fClass, fProto, fText],
  )

  const visible = useMemo(() => rows.filter(pass), [rows, pass])
  const visibleRef = useRef(visible)
  visibleRef.current = visible

  // ---- ingest -----------------------------------------------------------
  useEffect(() => {
    let alive = true
    getClassifications(Math.min(SEED_LIMIT, clampRows(maxRowsRef.current)))
      .then((seed) => {
        if (!alive) return
        const ordered = seed.slice().reverse() // API is newest-first; log is oldest→newest
        for (const c of ordered) seenRef.current.add(key(c))
        setRows(ordered.slice(-clampRows(maxRowsRef.current)))
      })
      .catch(() => {
        /* seeding is best-effort; the live stream fills the log regardless */
      })
    return () => {
      alive = false
    }
  }, [])

  useEffect(() => {
    return subscribe((batch: WsEvent[]) => {
      const fresh: Classification[] = []
      for (const ev of batch) {
        if (ev.type !== 'ClassificationCreated') continue
        const c = ev.data as Classification
        const k = key(c)
        if (seenRef.current.has(k)) continue
        seenRef.current.add(k)
        fresh.push(c)
      }
      if (seenRef.current.size > SEEN_CAP) seenRef.current.clear()
      if (fresh.length === 0) return

      if (pausedRef.current) {
        bufferRef.current.push(...fresh)
        const cap = clampRows(maxRowsRef.current) * 4
        if (bufferRef.current.length > cap) bufferRef.current.splice(0, bufferRef.current.length - cap)
        setBufferedCount(bufferRef.current.length)
        return
      }
      setRows((prev) => {
        const next = prev.concat(fresh)
        const cap = clampRows(maxRowsRef.current)
        if (next.length > cap) next.splice(0, next.length - cap)
        return next
      })
    })
  }, [subscribe])

  // ---- auto-scroll ----------------------------------------------------
  useLayoutEffect(() => {
    if (paused) return
    const el = scrollerRef.current
    if (el && stickRef.current) el.scrollTop = el.scrollHeight
  }, [visible, paused])

  const onScroll = useCallback(() => {
    const el = scrollerRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    stickRef.current = atBottom
    setShowJump(!atBottom)
  }, [])

  const jumpToLatest = useCallback(() => {
    const el = scrollerRef.current
    if (!el) return
    stickRef.current = true
    setShowJump(false)
    el.scrollTop = el.scrollHeight
  }, [])

  // ---- pause / resume / clear --------------------------------------
  const togglePause = useCallback(() => {
    setPaused((p) => {
      const next = !p
      if (!next && bufferRef.current.length) {
        setRows((prev) => {
          const merged = prev.concat(bufferRef.current)
          const cap = clampRows(maxRowsRef.current)
          if (merged.length > cap) merged.splice(0, merged.length - cap)
          return merged
        })
        bufferRef.current = []
        setBufferedCount(0)
        stickRef.current = true
      }
      return next
    })
  }, [])

  const clear = useCallback(() => {
    bufferRef.current = []
    seenRef.current.clear()
    setBufferedCount(0)
    setRows([])
    setSelectedId(null)
  }, [])

  // ---- fullscreen / kiosk -----------------------------------------
  const toggleKiosk = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    if (document.fullscreenElement === el) {
      document.exitFullscreen().catch(() => {})
    } else {
      el.requestFullscreen().catch(() => {})
    }
  }, [])

  useEffect(() => {
    const onFs = () => setKiosk(document.fullscreenElement === containerRef.current)
    document.addEventListener('fullscreenchange', onFs)
    return () => document.removeEventListener('fullscreenchange', onFs)
  }, [])

  // ---- keyboard nav ----------------------------------------------
  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      const list = visibleRef.current
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault()
        if (list.length === 0) return
        setSelectedId((cur) => {
          const idx = cur == null ? -1 : list.findIndex((c) => c.flow_id === cur)
          let nextIdx: number
          if (e.key === 'ArrowDown') nextIdx = idx < 0 ? 0 : Math.min(list.length - 1, idx + 1)
          else nextIdx = idx < 0 ? list.length - 1 : Math.max(0, idx - 1)
          const id = list[nextIdx]?.flow_id ?? null
          if (id != null) {
            stickRef.current = false
            queueMicrotask(() => {
              document
                .getElementById(`flowrow-${id}`)
                ?.scrollIntoView({ block: 'nearest' })
            })
          }
          return id
        })
      } else if (e.key === 'Enter') {
        e.preventDefault()
        const row = list.find((c) => c.flow_id === selectedId)
        if (row) setInspect(row)
      } else if (e.key === ' ') {
        e.preventDefault()
        togglePause()
      }
    },
    [selectedId, togglePause],
  )

  const filtered = visible.length
  const held = rows.length

  return (
    <div className={`flowlog${kiosk ? ' kiosk' : ''}`} ref={containerRef}>
      <div className="flowbar">
        <button className={paused ? 'on' : ''} onClick={togglePause}>
          {paused ? 'Resume' : 'Pause'}
        </button>
        {paused && bufferedCount > 0 ? (
          <span className="buffered">{fmtInt(bufferedCount)} buffered</span>
        ) : null}
        <button onClick={clear}>Clear</button>
        <button className={kiosk ? 'on' : ''} onClick={toggleKiosk}>
          {kiosk ? 'Exit kiosk' : 'Kiosk'}
        </button>

        <label>
          density
          <select value={density} onChange={(e) => setDensity(e.target.value as 'comfortable' | 'compact')}>
            <option value="comfortable">comfortable</option>
            <option value="compact">compact</option>
          </select>
        </label>
        <label>
          max rows
          <input
            type="number"
            min={100}
            max={20000}
            step={100}
            value={maxRows}
            onChange={(e) => setMaxRows(clampRows(Number(e.target.value)))}
          />
        </label>

        <label>
          class
          <select value={fClass} onChange={(e) => setFClass(e.target.value)}>
            <option value="">all</option>
            {CLASS_NAMES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <label>
          min&nbsp;conf
          <input
            type="number"
            min={0}
            max={100}
            step={5}
            value={fMinConf}
            onChange={(e) => setFMinConf(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
          />
        </label>
        <label>
          proto
          <select value={fProto} onChange={(e) => setFProto(e.target.value)}>
            <option value="">all</option>
            {PROTOS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <input
          type="search"
          placeholder="search ip:port…"
          value={fText}
          onChange={(e) => setFText(e.target.value)}
        />

        <span className="spacer" />
        <span className="dim">
          showing {fmtInt(filtered)} / {fmtInt(held)}
          {held >= clampRows(maxRows) ? ' (at cap)' : ''}
        </span>
      </div>

      <div
        className="flowscroll"
        ref={scrollerRef}
        onScroll={onScroll}
        onKeyDown={onKeyDown}
        tabIndex={0}
        role="grid"
        aria-label="rolling flow classification log"
      >
        <table className={`flow ${density}`}>
          <thead>
            <tr>
              <th>time</th>
              <th>sensor</th>
              <th>source</th>
              <th aria-hidden="true" />
              <th>destination</th>
              <th>proto</th>
              <th>class</th>
              <th>confidence</th>
              <th>models</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((c) => {
              const r = c.result
              const cn = [
                c.flow_id === selectedId ? 'sel' : '',
                r.score < LOW_CONFIDENCE ? 'lowconf' : '',
                r.disagreement ? 'disagree' : '',
                r.class === 'suspicious' ? 'suspicious' : '',
              ]
                .filter(Boolean)
                .join(' ')
              return (
                <tr
                  key={`${c.flow_id}-${c.ts}`}
                  id={`flowrow-${c.flow_id}`}
                  className={cn}
                  onClick={() => {
                    setSelectedId(c.flow_id)
                    setInspect(c)
                  }}
                >
                  <td className="dim">{fmtClock(c.ts)}</td>
                  <td>{c.sensor || '-'}</td>
                  <td className="mono">{endpoint(c.initiator_ip, c.initiator_port)}</td>
                  <td className="dim">→</td>
                  <td className="mono">{endpoint(c.responder_ip, c.responder_port)}</td>
                  <td className="dim">{c.proto}</td>
                  <td>
                    <span className={`cls ${r.class}`} style={{ background: classColor(r.class) }}>
                      {r.class.toUpperCase()}
                    </span>
                  </td>
                  <td className="mono">
                    <span
                      className="bar"
                      style={{ width: `${Math.max(2, Math.round(r.score * 80))}px` }}
                    />
                    {fmtPct(r.score)}
                  </td>
                  <td className="dim">
                    {(r.models ?? [])
                      .map((m) => `${roleInitial(m.role)}:${m.class} ${(m.score * 100).toFixed(0)}%`)
                      .join('  ')}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>

        {showJump ? (
          <button className="jump on" onClick={jumpToLatest}>
            ↓ jump to latest
          </button>
        ) : null}
      </div>

      {inspect ? <FlowInspector cls={inspect} onClose={() => setInspect(null)} /> : null}
    </div>
  )
}
