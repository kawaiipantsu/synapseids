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

import {
  ZERO_COUNTERS,
  addCounters,
  latest,
  newRateSampler,
  pushSample,
  type Counters,
} from '../lib/rates'
import { getCaptures, getSensorTopology, getStatus } from './client'
import type {
  CaptureSourceStatus,
  Classification,
  DaemonStatus,
  ModelInfo,
  ReplayStatus,
  SensorTopology,
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
  /** Live flow-table size from status.flow.active, and its cumulative siblings. */
  activeFlows: number
  flowsStarted: number
  flowsClosed: number
  flowsEvicted: number
  flowMax: number
  /** False until /api/v1/status has actually answered once. */
  hasFlowTable: boolean
  raw: DaemonStatus | null
  error: string | null
  lastUpdated: number
}

/**
 * Daemon-wide packet ingest, sampled into rates (§19.1 packets/sec + throughput).
 *
 * Every counter here is cumulative on the wire, so the rates come from
 * differentiating successive readings — see lib/rates.ts. Three ingest paths
 * are folded together because the card is about the daemon, not about one
 * source: local capture sources (/api/v1/captures), remote sensors
 * (/api/v1/sensors/topology) and a running replay, which PROJECT.md §6 lists as
 * a capture source and which really does drive the same pipeline.
 *
 * `bytes` deliberately excludes the replay: `status.replay` reports packets and
 * flows only, with no byte counter, so folding it into throughput would mean
 * inventing one. `replayPackets > 0 && !replayBytes` is what the Throughput card
 * says out loud instead (§16).
 */
export interface Ingest {
  /** 'loading' until the first poll answers; 'error' if an endpoint is broken. */
  state: 'loading' | 'ok' | 'error'
  /** the endpoint error, verbatim, when state === 'error' */
  error: string | null
  /** cumulative packets across every ingest path the daemon reports */
  packets: number
  /** cumulative bytes — capture sources + sensors only */
  bytes: number
  drops: number
  /** per-second history, oldest→newest, at most SPARK_WINDOW entries */
  pktPerSec: number[]
  bytesPerSec: number[]
  pktRate: number
  byteRate: number
  /** readings folded in; a rate needs 2, so 1 means "measuring…" */
  samples: number
  /** the capture sources that contributed, verbatim */
  sources: CaptureSourceStatus[]
  sourcesRunning: number
  /** the sensor topology document, or null if that endpoint failed */
  topology: SensorTopology | null
  /** packets contributed by a running replay */
  replayPackets: number
  replayRunning: boolean
  /** no capture source, no sensor, no running replay: the honest idle state */
  idle: boolean
}

export interface Rollup {
  /** Per-second classification counts, oldest→newest, up to SPARK_WINDOW entries. */
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
  ingest: Ingest
  replayEvents: ReplayLogEntry[]
  subscribe: (fn: EventHandler) => () => void
  refreshStatus: () => void
}

// ---------------------------------------------------------------------------
// Defaults / constants
// ---------------------------------------------------------------------------

/** Seconds of sparkline history every Dashboard series keeps. */
const SPARK_WINDOW = 90
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
  activeFlows: 0,
  flowsStarted: 0,
  flowsClosed: 0,
  flowsEvicted: 0,
  flowMax: 0,
  hasFlowTable: false,
  raw: null,
  error: null,
  lastUpdated: 0,
}

const EMPTY_INGEST: Ingest = {
  state: 'loading',
  error: null,
  packets: 0,
  bytes: 0,
  drops: 0,
  pktPerSec: [],
  bytesPerSec: [],
  pktRate: 0,
  byteRate: 0,
  samples: 0,
  sources: [],
  sourcesRunning: 0,
  topology: null,
  replayPackets: 0,
  replayRunning: false,
  idle: true,
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
  const f = s.flow
  return {
    flows: Number(s.storage?.flows ?? 0),
    classifications: Number(s.storage?.classifications ?? 0),
    clients: Number(s.live?.clients ?? 0),
    driver: String(s.storage?.driver ?? ''),
    models: Array.isArray(s.models) ? s.models : [],
    replay: s.replay ?? EMPTY_REPLAY,
    activeFlows: Number(f?.active ?? 0),
    flowsStarted: Number(f?.started ?? 0),
    flowsClosed: Number(f?.closed ?? 0),
    flowsEvicted: Number(f?.evicted ?? 0),
    flowMax: Number(f?.max ?? 0),
    hasFlowTable: f != null,
    raw: s,
    error: null,
    lastUpdated: Date.now(),
  }
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** Cumulative counters for one poll's worth of capture sources. */
function sourceCounters(rows: CaptureSourceStatus[]): Counters {
  return rows.reduce<Counters>(
    (acc, s) => addCounters(acc, {
      packets: Number(s.packets ?? 0),
      bytes: Number(s.bytes ?? 0),
      drops: Number(s.drops ?? 0),
    }),
    ZERO_COUNTERS,
  )
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
  const [ingest, setIngest] = useState<Ingest>(EMPTY_INGEST)
  const [replayEvents, setReplayEvents] = useState<ReplayLogEntry[]>([])
  const rates = useRef(newRateSampler())

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

  // --- status + ingest polling ---------------------------------------------
  // One loop, one cadence, three cheap reads. The ingest counters have to be
  // sampled in lock-step with each other for the derived rate to mean anything,
  // so they share this poll rather than getting a second timer of their own.
  useEffect(() => {
    let alive = true
    const poll = () => {
      void Promise.allSettled([getStatus(), getCaptures(), getSensorTopology()]).then(
        ([sr, cr, tr]) => {
          if (!alive) return

          if (sr.status === 'fulfilled') setStatus(mapStatus(sr.value))
          else setStatus((prev) => ({ ...prev, error: errText(sr.reason) }))
          const st = sr.status === 'fulfilled' ? sr.value : null

          const sources = cr.status === 'fulfilled' ? cr.value : []
          const topology = tr.status === 'fulfilled' ? tr.value : null
          const failure =
            cr.status === 'rejected'
              ? errText(cr.reason)
              : tr.status === 'rejected'
                ? errText(tr.reason)
                : null

          const replay = st?.replay ?? EMPTY_REPLAY
          const replayRunning = Boolean(replay.running)
          const replayPackets = Number(replay.packets ?? 0)

          // bytes: sources + sensors only. status.replay carries no byte
          // counter, so there is nothing honest to add for a replay.
          const byteBearing = addCounters(sourceCounters(sources), {
            packets: Number(topology?.packets ?? 0),
            bytes: Number(topology?.bytes ?? 0),
            drops: Number(topology?.drops ?? 0),
          })
          const total: Counters = {
            packets: byteBearing.packets + replayPackets,
            bytes: byteBearing.bytes,
            drops: byteBearing.drops,
          }

          const s = rates.current
          pushSample(s, total, Date.now(), SPARK_WINDOW)

          setIngest({
            state: failure ? 'error' : 'ok',
            error: failure,
            packets: total.packets,
            bytes: total.bytes,
            drops: total.drops,
            pktPerSec: s.pktPerSec.slice(),
            bytesPerSec: s.bytesPerSec.slice(),
            pktRate: latest(s.pktPerSec),
            byteRate: latest(s.bytesPerSec),
            samples: s.samples,
            sources,
            sourcesRunning: sources.filter((x) => x.state === 'running').length,
            topology,
            replayPackets,
            replayRunning,
            idle:
              sources.length === 0 &&
              Number(topology?.sensors ?? 0) === 0 &&
              !replayRunning &&
              replayPackets === 0,
          })
        },
      )
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
      if (a.clsPerSec.length > SPARK_WINDOW) a.clsPerSec.splice(0, a.clsPerSec.length - SPARK_WINDOW)
      if (a.flowPerSec.length > SPARK_WINDOW) a.flowPerSec.splice(0, a.flowPerSec.length - SPARK_WINDOW)

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
    () => ({ connected, status, rollup, ingest, replayEvents, subscribe, refreshStatus }),
    [connected, status, rollup, ingest, replayEvents, subscribe, refreshStatus],
  )

  return <StreamContext.Provider value={value}>{children}</StreamContext.Provider>
}

export function useStream(): StreamContextValue {
  const ctx = useContext(StreamContext)
  if (!ctx) throw new Error('useStream must be used within <StreamProvider>')
  return ctx
}
