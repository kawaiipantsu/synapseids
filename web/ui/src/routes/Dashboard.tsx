import { useEffect, useState } from 'react'

import { getDetections, getModels, getTimeline } from '../api/client'
import { useStream, type Ingest } from '../api/stream'
import type { Detection, ModelList, SensorTopology, TimelineSeries } from '../api/types'
import { IssueLink, IssueLinks } from '../components/IssueLink'
import { Sparkline } from '../components/Sparkline'
import { classColor, severityColor } from '../lib/classes'
import { endpoint, fmtAgo, fmtBytes, fmtInt, fmtNum, fmtPct } from '../lib/format'
import { Link } from '../lib/hashRouter'

/** Registry / detections poll. Slower than the 1 s counter loop on purpose. */
const SLOW_POLL_MS = 5000
const RECENT_DETECTIONS = 5

function BarRow({ label, value, max, color }: { label: string; value: number; max: number; color?: string }) {
  const pct = max > 0 ? Math.max(2, (value / max) * 100) : 0
  return (
    <div className="barrow">
      <span title={label} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {label}
      </span>
      <span className="track">
        <span className="fill" style={{ width: `${pct}%`, background: color ?? 'var(--accent)' }} />
      </span>
      <span className="n">{fmtInt(value)}</span>
    </div>
  )
}

/**
 * A card with nothing to show because the feature does not exist yet.
 *
 * It must cite **open** issues. "Phase 3" on a card whose endpoint shipped in
 * Phase 3, or "Phase 2" after Phase 2 closed, tells an operator the UI is stale
 * rather than that the data is missing — that was issue #118. Keeping the gap
 * itself is correct (PROJECT.md §16): a labelled gap beats an invented number.
 */
function Gap({ title, issues, note }: { title: string; issues: number[]; note: string }) {
  return (
    <div className="card needs-api">
      <h3>{title}</h3>
      <div className="big">—</div>
      <div className="note">
        not built yet · <IssueLinks issues={issues} /> · {note}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Ingest cards (§19.1) — issue #118
//
// /api/v1/captures, /api/v1/sensors/topology and status.replay all report
// cumulative totals, so the rates behind these two cards are differentiated from
// successive samples in the provider's one polling loop (api/stream.tsx +
// lib/rates.ts), exactly like the classifications/sec and flow-events/sec cards
// above them.
//
// Three states have to look different, and conflating them is what #118 was
// about:
//
//   error        the endpoint is broken — say which and why
//   idle         the endpoint answered and there is nothing ingesting. A real
//                0/s, NOT a greyed "needs API": the API is right here.
//   measuring    exactly one sample so far. A rate needs two, so this shows a
//                dash rather than a zero that would read as "no traffic".
// ---------------------------------------------------------------------------

/** What the daemon is currently ingesting from, in words. */
function contributors(ing: Ingest): string {
  const bits: string[] = []
  if (ing.sources.length) {
    bits.push(
      `${fmtInt(ing.sourcesRunning)}/${fmtInt(ing.sources.length)} capture source${ing.sources.length === 1 ? '' : 's'} running`,
    )
  }
  const sensors = Number(ing.topology?.sensors ?? 0)
  if (sensors) bits.push(`${fmtInt(sensors)} sensor${sensors === 1 ? '' : 's'}`)
  if (ing.replayRunning) bits.push('replay running')
  else if (ing.replayPackets > 0) bits.push('last replay')
  if (!bits.length) return 'no capture source, sensor or replay'
  return bits.join(' · ')
}

function PacketsCard({ ing }: { ing: Ingest }) {
  if (ing.state === 'error') {
    return (
      <div className="card">
        <h3>Packets / sec</h3>
        <div className="big">—</div>
        <div className="foot err">ingest counters unavailable — {ing.error}</div>
      </div>
    )
  }
  const measuring = ing.samples < 2
  return (
    <div className="card">
      <h3>Packets / sec</h3>
      <div className="big">{measuring ? '—' : fmtNum(ing.pktRate, 1)}</div>
      <Sparkline
        values={ing.pktPerSec}
        stroke="#c586ff"
        fill="rgba(197,134,255,0.16)"
        ariaLabel="ingested packets per second"
      />
      <div className="foot">
        {measuring
          ? 'measuring — a rate needs two samples'
          : `${fmtInt(ing.packets)} packets total · ${contributors(ing)}`}
      </div>
    </div>
  )
}

function ThroughputCard({ ing }: { ing: Ingest }) {
  if (ing.state === 'error') {
    return (
      <div className="card">
        <h3>Throughput</h3>
        <div className="big">—</div>
        <div className="foot err">ingest counters unavailable — {ing.error}</div>
      </div>
    )
  }
  const measuring = ing.samples < 2
  // A replay is the one ingest path with no byte counter on the wire, so when it
  // is the only thing running the honest render is 0 B/s plus that sentence —
  // not the packet rate multiplied by a guessed average frame size.
  const replayOnly =
    ing.replayPackets > 0 && ing.sources.length === 0 && Number(ing.topology?.sensors ?? 0) === 0
  return (
    <div className="card">
      <h3>Throughput</h3>
      <div className="big">{measuring ? '—' : `${fmtBytes(ing.byteRate)}/s`}</div>
      <Sparkline
        values={ing.bytesPerSec}
        stroke="#ffd166"
        fill="rgba(255,209,102,0.16)"
        ariaLabel="ingested bytes per second"
      />
      <div className="foot">
        {measuring ? (
          'measuring — a rate needs two samples'
        ) : replayOnly ? (
          <>
            replay only · <code>status.replay</code> reports packets and flows, no byte counter
          </>
        ) : (
          `${fmtBytes(ing.bytes)} total · ${fmtInt(ing.drops)} drops · ${contributors(ing)}`
        )}
      </div>
    </div>
  )
}

/**
 * Sensor health (§19.15) from /api/v1/sensors/topology.
 *
 * The endpoint never 503s, and its `collector: false` is deliberately different
 * from "a collector is up and nobody is connected". Both are honest renders and
 * neither is a missing API, so neither is greyed out.
 */
function SensorHealthCard({ topology, error }: { topology: SensorTopology | null; error: string | null }) {
  if (error || !topology) {
    return (
      <div className="card span2">
        <h3>Sensor health</h3>
        <div className="big">—</div>
        <div className="foot err">
          {error ?? 'waiting for /api/v1/sensors/topology…'}
        </div>
      </div>
    )
  }
  if (!topology.collector) {
    return (
      <div className="card span2">
        <h3>Sensor health</h3>
        <div className="big">off</div>
        <div className="foot">
          no SYNPOIP collector configured — set <code>capture.collector</code> to accept{' '}
          <code>synapse-sensor</code> connections (§19.15). This daemon reports only its own capture
          sources.
        </div>
      </div>
    )
  }
  if (topology.sensors === 0) {
    return (
      <div className="card span2">
        <h3>Sensor health</h3>
        <div className="big">0</div>
        <div className="foot">
          collector is listening · no sensor connected yet · <Link to="/sensors">CAPTURE ▸ Sensors</Link>
        </div>
      </div>
    )
  }
  const worst = topology.locations.some((l) => l.health === 'down')
    ? 'down'
    : topology.locations.some((l) => l.health === 'degraded')
      ? 'degraded'
      : 'ok'
  return (
    <div className="card span2">
      <h3>Sensor health</h3>
      <div className="big">
        {fmtInt(topology.sensors)} <span className={`sn-health ${worst}`}>{worst}</span>
      </div>
      <ul className="list-plain">
        {topology.locations.map((l) => (
          <li key={l.unassigned ? '(unassigned)' : l.location}>
            <span className="mono">{l.unassigned ? '(unassigned)' : l.location}</span>
            <span className="dim">
              {fmtInt(l.running)}/{fmtInt(l.sensor_count)} up · {fmtNum(l.pps, 1)} pps ·{' '}
              {fmtBytes(l.bps)}/s
            </span>
            <span className={`sn-health ${l.health}`}>{l.health}</span>
          </li>
        ))}
      </ul>
      <div className="foot">
        {fmtInt(topology.location_count)} location(s) · {fmtInt(topology.attributable_sensors)} of{' '}
        {fmtInt(topology.sensors)} scopable · {fmtInt(topology.drops)} drops ·{' '}
        <Link to="/sensors">topology</Link>
      </div>
    </div>
  )
}

/** GET /api/v1/models, polled slowly — the registry barely changes. */
function useModelRegistry(): { list: ModelList | null; error: string | null } {
  const [list, setList] = useState<ModelList | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    const load = () =>
      getModels()
        .then((r) => {
          if (!alive) return
          setList(r)
          setError(null)
        })
        .catch((e: unknown) => {
          if (alive) setError(e instanceof Error ? e.message : String(e))
        })
    void load()
    const id = window.setInterval(load, SLOW_POLL_MS)
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [])
  return { list, error }
}

/**
 * Recent detections (§19.1) over GET /api/v1/detections (issue #117).
 *
 * A daemon older than #117 has no such route, so a 404 is handled as a state —
 * "not available in this build", once, with no retry loop and no console error.
 * `ok` with zero rows is a different, equally honest render: a current daemon
 * with no alert store answers 200 with an empty page.
 */
function useRecentDetections(): {
  rows: Detection[] | null
  unavailable: string | null
  error: string | null
} {
  const [rows, setRows] = useState<Detection[] | null>(null)
  const [unavailable, setUnavailable] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const gone = unavailable != null

  useEffect(() => {
    if (gone) return
    let alive = true
    const load = () =>
      getDetections({ limit: RECENT_DETECTIONS }).then((r) => {
        if (!alive) return
        if (r.state === 'ok') {
          setRows(r.list.detections)
          setError(null)
        } else if (r.state === 'unavailable') {
          setRows(null)
          setUnavailable(r.message)
        } else {
          setError(r.message)
        }
      })
    void load()
    const id = window.setInterval(() => void load(), SLOW_POLL_MS)
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [gone])

  return { rows, unavailable, error }
}

function RecentDetectionsCard() {
  const { rows, unavailable, error } = useRecentDetections()
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [])

  if (unavailable) {
    return (
      <div className="card span2 needs-api">
        <h3>Recent detections</h3>
        <div className="big">—</div>
        <div className="note">
          <code>/api/v1/detections</code> answered 404 — this daemon predates{' '}
          <IssueLink n={117} />
        </div>
      </div>
    )
  }
  return (
    <div className="card span2">
      <h3>Recent detections</h3>
      {error ? <div className="foot err">{error}</div> : null}
      {rows == null && !error ? <div className="foot">loading…</div> : null}
      {rows != null && rows.length === 0 ? (
        <div className="foot">none — the endpoint answered with an empty feed</div>
      ) : null}
      {rows != null && rows.length > 0 ? (
        <ul className="list-plain dt-recent">
          {rows.map((d) => (
            <li key={d.id}>
              <span className={`dt-sev ${d.severity}`} style={{ background: severityColor(d.severity) }}>
                {d.severity}
              </span>
              <span className="cls" style={{ background: classColor(d.class) }}>
                {d.class.toUpperCase()}
              </span>
              <span className="mono pair" title={`${d.src_ip} → ${endpoint(d.dst_ip, d.dst_port)}`}>
                {d.src_ip} → {endpoint(d.dst_ip, d.dst_port)}
              </span>
              <span className="dim meta">
                {d.count > 1 ? `×${fmtInt(d.count)} · ` : ''}
                {fmtPct(d.confidence, 0)} · {fmtAgo(d.last_ts, now)}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
      <div className="foot">
        deduplicated · <Link to="/detections">LIVE ▸ Detections</Link>
      </div>
    </div>
  )
}

/**
 * Anomaly rate over the retained 1-minute timeline (ADR 0037). A real number
 * when a flow-anomaly-v1 model scored the window; a labelled gap otherwise —
 * never a fabricated zero (PROJECT.md §16).
 */
function AnomalyRateCard() {
  const [series, setSeries] = useState<TimelineSeries | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    const load = () =>
      getTimeline({ bucket: '1m' })
        .then((s) => live && (setSeries(s), setError(null)))
        .catch((e) => live && setError(String(e)))
    load()
    const id = window.setInterval(load, SLOW_POLL_MS)
    return () => {
      live = false
      window.clearInterval(id)
    }
  }, [])

  if (error) return <Gap title="Anomaly rate" issues={[167]} note={`timeline query failed: ${error}`} />
  if (series == null)
    return (
      <div className="card">
        <h3>Anomaly rate</h3>
        <div className="foot">loading…</div>
      </div>
    )
  if (!series.anomaly_available)
    return (
      <Gap
        title="Anomaly rate"
        issues={[167]}
        note="no flow-anomaly-v1 model is active — activate one to score flows for novelty (§13)"
      />
    )

  let scored = 0
  let exceeded = 0
  let peak = 0
  for (const b of series.buckets) {
    scored += b.anomaly_n
    exceeded += b.anomaly_exceeds
    if (b.anomaly_max > peak) peak = b.anomaly_max
  }
  const pct = scored > 0 ? (exceeded / scored) * 100 : 0
  return (
    <div className="card">
      <h3>Anomaly rate · retained window</h3>
      <div className="big">{fmtPct(pct / 100, 1)}</div>
      <div className="note">
        {fmtInt(exceeded)} / {fmtInt(scored)} scored flows over threshold · peak score{' '}
        {peak.toFixed(2)}
      </div>
    </div>
  )
}

export function Dashboard() {
  const { status, rollup, ingest, connected } = useStream()
  const registry = useModelRegistry()

  const classMax = rollup.classCounts.reduce((m, [, n]) => Math.max(m, n), 0)
  const protoMax = rollup.protoCounts.reduce((m, [, n]) => Math.max(m, n), 0)
  const talkerMax = rollup.topTalkers.reduce((m, t) => Math.max(m, t.count), 0)
  const portMax = rollup.topPorts.reduce((m, t) => Math.max(m, t.count), 0)
  const windowMin = Math.round(rollup.windowSec / 60)

  const registered = registry.list?.models ?? []
  const active = registered.filter((m) => m.status === 'active')

  return (
    <div>
      <div className="page-h">
        <h1>Dashboard</h1>
        <span className="sub">
          live counters from <code>/api/v1/status</code>, <code>/api/v1/captures</code>,{' '}
          <code>/api/v1/sensors/topology</code> and <code>/api/v1/models</code>, plus client-side
          aggregation of the classification stream
        </span>
      </div>

      <div className="cards">
        <div className="card">
          <h3>Classifications</h3>
          <div className="big">{fmtInt(status.classifications)}</div>
          <Sparkline values={rollup.clsPerSec} ariaLabel="classifications per second" />
          <div className="foot">{fmtInt(rollup.clsRate)} / s · stored total</div>
        </div>

        <div className="card">
          <h3>Flows</h3>
          <div className="big">{fmtInt(status.flows)}</div>
          <Sparkline
            values={rollup.flowPerSec}
            stroke="#ffb454"
            fill="rgba(255,180,84,0.16)"
            ariaLabel="flow events per second"
          />
          <div className="foot">{fmtInt(rollup.flowRate)} / s closed · updated</div>
        </div>

        {/* status.flow.active — the live flow-table size (#118). */}
        <div className="card">
          <h3>Active flows</h3>
          <div className="big">{status.hasFlowTable ? fmtInt(status.activeFlows) : '—'}</div>
          <div className="foot">
            {status.hasFlowTable ? (
              <>
                {fmtInt(status.flowsStarted)} started · {fmtInt(status.flowsClosed)} closed ·{' '}
                {fmtInt(status.flowsEvicted)} evicted · cap {fmtInt(status.flowMax)}
              </>
            ) : (
              <>
                this daemon&apos;s <code>/api/v1/status</code> reports no <code>flow</code> block
              </>
            )}
          </div>
        </div>

        <PacketsCard ing={ingest} />
        <ThroughputCard ing={ingest} />

        <div className="card">
          <h3>WebSocket clients</h3>
          <div className="big">{fmtInt(status.clients)}</div>
          <div className="foot">{connected ? 'this client: live' : 'this client: reconnecting…'}</div>
        </div>

        <div className="card">
          <h3>Hosts seen</h3>
          <div className="big">{fmtInt(rollup.hostsSeen)}</div>
          <div className="foot">distinct initiators · rolling {windowMin} min</div>
        </div>

        <div className="card span2">
          <h3>Loaded models</h3>
          {status.models.length === 0 ? (
            <div className="foot">none reported</div>
          ) : (
            <ul className="list-plain">
              {status.models.map((m) => (
                <li key={m.id}>
                  <span className="mono">{m.id}</span>
                  <span className="dim">
                    {m.family} · {m.role}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {/* Registry, activation state and lineage all exist — /api/v1/models
              and /api/v1/models/{id}/lineage (#118). The per-model lineage chain
              is drawn on ML ▸ Models rather than fetched once per model here. */}
          <div className="foot">
            {registry.error ? (
              <span className="err">registry unavailable — {registry.error}</span>
            ) : registry.list == null ? (
              'reading the registry…'
            ) : (
              <>
                {fmtInt(registered.length)} registered ·{' '}
                {active.length ? (
                  <>
                    active <span className="mono">{active.map((m) => m.model_id).join(', ')}</span>
                  </>
                ) : (
                  'none activated — the heuristic is primary'
                )}{' '}
                · metrics and lineage per model on <Link to="/models">ML ▸ Models</Link>
              </>
            )}
          </div>
        </div>

        <div className="card span2">
          <h3>Class breakdown · since load</h3>
          {rollup.classCounts.length === 0 ? (
            <div className="foot">waiting for classifications…</div>
          ) : (
            rollup.classCounts.map(([name, n]) => (
              <BarRow key={name} label={name} value={n} max={classMax} color={classColor(name)} />
            ))
          )}
        </div>

        <div className="card span2">
          <h3>Protocol breakdown · since load</h3>
          {rollup.protoCounts.length === 0 ? (
            <div className="foot">waiting for classifications…</div>
          ) : (
            rollup.protoCounts.map(([name, n]) => (
              <BarRow key={name} label={name} value={n} max={protoMax} />
            ))
          )}
        </div>

        <div className="card span2">
          <h3>Top talkers · rolling {windowMin} min</h3>
          {rollup.topTalkers.length === 0 ? (
            <div className="foot">waiting for classifications…</div>
          ) : (
            rollup.topTalkers.map((t) => (
              <BarRow key={t.ip} label={t.ip} value={t.count} max={talkerMax} />
            ))
          )}
        </div>

        <div className="card span2">
          <h3>Top destination ports · rolling {windowMin} min</h3>
          {rollup.topPorts.length === 0 ? (
            <div className="foot">waiting for classifications…</div>
          ) : (
            rollup.topPorts.map((t) => (
              <BarRow key={t.port} label={String(t.port)} value={t.count} max={portMax} />
            ))
          )}
        </div>

        <RecentDetectionsCard />
        <SensorHealthCard topology={ingest.topology} error={ingest.error} />

        <AnomalyRateCard />

        {/* Still genuinely unbuilt. Cites an open issue, and shows no number —
            PROJECT.md §16 makes the labelled gap the correct render. */}
        <Gap
          title="Inference latency p50/p95/p99"
          issues={[55]}
          note="needs the /metrics + latency-histogram work (§19.16)"
        />
      </div>
    </div>
  )
}
