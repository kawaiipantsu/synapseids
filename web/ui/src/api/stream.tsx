import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

import { getStatus } from './client'
import type {
  Classification,
  DaemonStatus,
  ModelInfo,
  ReplayStatus,
  WsEvent,
} from './types'

// ---------------------------------------------------------------------------
// Public shapes
// ---------------------------------------------------------------------------

export interface MappedStatus {
  flows: number
  classifications: number
  clients: number
  driver: string
  models: ModelInfo[]
  replay: ReplayStatus
  raw: DaemonStatus | null
  error: string | null
  lastUpdated: number
}

export interface Rollup {
  /** Per-second classification counts, oldest→newest, up to WINDOW entries. */
  clsPerSec: number[]
  /** Per-second closed/updated flow counts. */
  flowPerSec: number[]
  clsRate: number
  flowRate: number
  /** Cumulative since page load, sorted by count desc. */
  classCounts: Array<[string, number]>
  protoCounts: Array<[string, number]>
  /** Rolling 5-minute window. */
  topTalkers: Array<{ ip: string; count: number }>
  topPorts: Array<{ port: number; count: number }>
  hostsSeen: number
  windowSec: number
  sampleCount: number
}

export interface ReplayLogEntry {
  seq: number
  ts: string
  type: string
  text: string
}

type EventHandler = (evs: WsEvent[]) => void

interface StreamContextValue {
  connected: boolean
  status: MappedStatus
  rollup: Rollup
  replayEvents: ReplayLogEntry[]
  subscribe: (fn: EventHandler) => () => void
  refreshStatus: () => void
}

// ---------------------------------------------------------------------------
// Defaults / constants
// ---------------------------------------------------------------------------

const WINDOW = 90 // seconds of sparkline history
const ROLL_WINDOW_MS = 5 * 60 * 1000 // top-talkers / ports / hosts window
const RECENT_CAP = 20_000 // hard cap on the rolling-window event log
const REPLAY_LOG_CAP = 60
const POLL_MS = 1000
const RECONNECT_MIN_MS = 1500
const RECONNECT_MAX_MS = 10_000

const EMPTY_REPLAY: ReplayStatus = { running: false, packets: 0, flows: 0 }

const EMPTY_STATUS: MappedStatus = {
  flows: 0,
  classifications: 0,
  clients: 0,
  driver: '',
  models: [],
  replay: EMPTY_REPLAY,
  raw: null,
  error: null,
  lastUpdated: 0,
}

const EMPTY_ROLLUP: Rollup = {
  clsPerSec: [],
  flowPerSec: [],
  clsRate: 0,
  flowRate: 0,
  classCounts: [],
  protoCounts: [],
  topTalkers: [],
  topPorts: [],
  hostsSeen: 0,
  windowSec: ROLL_WINDOW_MS / 1000,
  sampleCount: 0,
}

const StreamContext = createContext<StreamContextValue | null>(null)

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

function mapStatus(s: DaemonStatus): MappedStatus {
  return {
    flows: Number(s.storage?.flows ?? 0),
    classifications: Number(s.storage?.classifications ?? 0),
    clients: Number(s.live?.clients ?? 0),
    driver: String(s.storage?.driver ?? ''),
    models: Array.isArray(s.models) ? s.models : [],
    replay: s.replay ?? EMPTY_REPLAY,
    raw: s,
    error: null,
    lastUpdated: Date.now(),
  }
}

function replayText(type: string, data: unknown): string {
  const d = (data ?? {}) as Record<string, unknown>
  const s = (k: string) => (d[k] == null ? '?' : String(d[k]))
  switch (type) {
    case 'ReplayStarted':
      return `started ${s('source')} @${s('speed')}`
    case 'ReplayProgress':
      return `progress — ${s('packets')} pkts (${s('decoded')} decoded)`
    case 'ReplayFinished':
      return `finished — ${s('packets')} pkts, ${s('flows')} flows, ${s('classifications')} classified, ${s('elapsed_ms')} ms`
    default:
      return type
  }
}

export function StreamProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false)
  const [status, setStatus] = useState<MappedStatus>(EMPTY_STATUS)
  const [rollup, setRollup] = useState<Rollup>(EMPTY_ROLLUP)
  const [replayEvents, setReplayEvents] = useState<ReplayLogEntry[]>([])

  const subscribers = useRef(new Set<EventHandler>())

  // Rolling-aggregate scratch space — mutated on every batch, snapshotted once
  // a second so consumers re-render at a sane cadence (PROJECT.md §22).
  const agg = useRef({
    clsPending: 0,
    flowPending: 0,
    clsPerSec: [] as number[],
    flowPerSec: [] as number[],
    classCounts: new Map<string, number>(),
    protoCounts: new Map<string, number>(),
    recent: [] as Array<{ t: number; ip: string; port: number }>,
    sampleCount: 0,
    replayLog: [] as ReplayLogEntry[],
    replayDirty: false,
  })

  const subscribe = useCallback((fn: EventHandler) => {
    subscribers.current.add(fn)
    return () => {
      subscribers.current.delete(fn)
    }
  }, [])

  const pollRef = useRef<() => void>(() => {})
  const refreshStatus = useCallback(() => pollRef.current(), [])

  // --- status polling ------------------------------------------------------
  useEffect(() => {
    let alive = true
    const poll = () => {
      getStatus()
        .then((s) => {
          if (alive) setStatus(mapStatus(s))
        })
        .catch((err: unknown) => {
          if (alive) {
            setStatus((prev) => ({
              ...prev,
              error: err instanceof Error ? err.message : String(err),
            }))
          }
        })
    }
    pollRef.current = poll
    poll()
    const id = window.setInterval(poll, POLL_MS)
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [])

  // --- rollup snapshot ---------------------------------------------------
  useEffect(() => {
    const id = window.setInterval(() => {
      const a = agg.current
      const now = Date.now()

      a.clsPerSec.push(a.clsPending)
      a.flowPerSec.push(a.flowPending)
      a.clsPending = 0
      a.flowPending = 0
      if (a.clsPerSec.length > WINDOW) a.clsPerSec.splice(0, a.clsPerSec.length - WINDOW)
      if (a.flowPerSec.length > WINDOW) a.flowPerSec.splice(0, a.flowPerSec.length - WINDOW)

      const cutoff = now - ROLL_WINDOW_MS
      if (a.recent.length && a.recent[0]!.t < cutoff) {
        let i = 0
        while (i < a.recent.length && a.recent[i]!.t < cutoff) i++
        a.recent.splice(0, i)
      }

      const byIp = new Map<string, number>()
      const byPort = new Map<number, number>()
      for (const r of a.recent) {
        byIp.set(r.ip, (byIp.get(r.ip) ?? 0) + 1)
        if (r.port) byPort.set(r.port, (byPort.get(r.port) ?? 0) + 1)
      }
      const topTalkers = [...byIp.entries()]
        .sort((x, y) => y[1] - x[1])
        .slice(0, 8)
        .map(([ip, count]) => ({ ip, count }))
      const topPorts = [...byPort.entries()]
        .sort((x, y) => y[1] - x[1])
        .slice(0, 8)
        .map(([port, count]) => ({ port, count }))

      setRollup({
        clsPerSec: a.clsPerSec.slice(),
        flowPerSec: a.flowPerSec.slice(),
        clsRate: a.clsPerSec[a.clsPerSec.length - 1] ?? 0,
        flowRate: a.flowPerSec[a.flowPerSec.length - 1] ?? 0,
        classCounts: [...a.classCounts.entries()].sort((x, y) => y[1] - x[1]),
        protoCounts: [...a.protoCounts.entries()].sort((x, y) => y[1] - x[1]),
        topTalkers,
        topPorts,
        hostsSeen: byIp.size,
        windowSec: ROLL_WINDOW_MS / 1000,
        sampleCount: a.sampleCount,
      })

      if (a.replayDirty) {
        a.replayDirty = false
        setReplayEvents(a.replayLog.slice().reverse())
      }
    }, 1000)
    return () => window.clearInterval(id)
  }, [])

  // --- websocket ---------------------------------------------------------
  useEffect(() => {
    let ws: WebSocket | null = null
    let reconnectTimer = 0
    let backoff = RECONNECT_MIN_MS
    let disposed = false

    const dispatch = (batch: WsEvent[]) => {
      const a = agg.current
      for (const ev of batch) {
        switch (ev.type) {
          case 'ClassificationCreated': {
            const c = ev.data as Classification
            a.clsPending++
            a.sampleCount++
            a.classCounts.set(c.result.class, (a.classCounts.get(c.result.class) ?? 0) + 1)
            const proto = c.proto || '?'
            a.protoCounts.set(proto, (a.protoCounts.get(proto) ?? 0) + 1)
            a.recent.push({ t: Date.now(), ip: c.initiator_ip, port: c.responder_port })
            if (a.recent.length > RECENT_CAP) a.recent.splice(0, a.recent.length - RECENT_CAP)
            break
          }
          case 'FlowClosed':
          case 'FlowUpdated':
            a.flowPending++
            break
          case 'ReplayStarted':
          case 'ReplayProgress':
          case 'ReplayFinished':
            a.replayLog.push({
              seq: ev.seq,
              ts: ev.ts,
              type: ev.type,
              text: replayText(ev.type, ev.data),
            })
            if (a.replayLog.length > REPLAY_LOG_CAP) {
              a.replayLog.splice(0, a.replayLog.length - REPLAY_LOG_CAP)
            }
            a.replayDirty = true
            break
          default:
            break
        }
      }
      for (const fn of subscribers.current) {
        try {
          fn(batch)
        } catch {
          // a broken subscriber must not stall the stream
        }
      }
    }

    const connect = () => {
      if (disposed) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      ws = new WebSocket(`${proto}://${window.location.host}/api/v1/stream`)
      ws.onopen = () => {
        backoff = RECONNECT_MIN_MS
        setConnected(true)
      }
      ws.onclose = () => {
        setConnected(false)
        if (disposed) return
        reconnectTimer = window.setTimeout(connect, backoff)
        backoff = Math.min(backoff * 2, RECONNECT_MAX_MS)
      }
      ws.onerror = () => ws?.close()
      ws.onmessage = (e) => {
        let batch: WsEvent[]
        try {
          batch = JSON.parse(e.data as string)
        } catch {
          return
        }
        if (Array.isArray(batch) && batch.length) dispatch(batch)
      }
    }

    connect()
    return () => {
      disposed = true
      window.clearTimeout(reconnectTimer)
      if (ws) {
        ws.onclose = null
        ws.onerror = null
        ws.close()
      }
    }
  }, [])

  const value = useMemo<StreamContextValue>(
    () => ({ connected, status, rollup, replayEvents, subscribe, refreshStatus }),
    [connected, status, rollup, replayEvents, subscribe, refreshStatus],
  )

  return <StreamContext.Provider value={value}>{children}</StreamContext.Provider>
}

export function useStream(): StreamContextValue {
  const ctx = useContext(StreamContext)
  if (!ctx) throw new Error('useStream must be used within <StreamProvider>')
  return ctx
}
