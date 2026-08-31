import { useCallback, useEffect, useRef, useState } from 'react'

import { getClassifications, getDetections } from '../api/client'
import type { Detection, DetectionList, Severity } from '../api/types'
import type { Classification } from '../api/types'
import { SEVERITIES } from '../api/types'
import { FlowInspector } from '../components/FlowInspector'
import { CLASS_NAMES, classColor, severityColor } from '../lib/classes'
import { endpoint, fmtAgo, fmtDateTime, fmtInt, fmtPct } from '../lib/format'
import { navigateWith } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'

// LIVE ▸ Detections (§19.1 "recent detections", §19.4, §18) — the alert feed
// over GET /api/v1/detections (issue #117).
//
// A detection is deduplicated by the daemon, so `count` is the number the
// operator actually has to read: one row standing for 400 scanned ports and one
// row standing for a single probe look identical without it. It is therefore its
// own column, and a row with count > 1 also carries a first-seen → last-seen
// span rather than one timestamp.
//
// Filtering is server-side because the endpoint's contract already takes class,
// severity and min_confidence — the Flow Log filters in the browser only because
// it is filtering a live stream it has already received. The filter *idiom* here
// (a persisted control bar, "showing N / M", a class select over CLASS_NAMES and
// a 0-100 min-confidence box) is the Flow Log's.
//
// This view must survive the endpoint not existing: /api/v1/detections is on a
// sibling branch, and until it lands every build answers 404. That is rendered
// as "not available in this build", never as a spinner or an error banner.

const POLL_MS = 2000
const LIMITS = [50, 100, 250, 500, 1000]

/** The `since` presets, in minutes. 0 = no bound. */
const WINDOWS: Array<[string, number]> = [
  ['all', 0],
  ['15m', 15],
  ['1h', 60],
  ['6h', 360],
  ['24h', 1440],
]

export function SeverityChip({ s }: { s: Severity }) {
  return (
    <span className={`dt-sev ${s}`} style={{ background: severityColor(s) }}>
      {s}
    </span>
  )
}

/** The occurrence count. Deliberately loud once it is more than one. */
function CountCell({ n }: { n: number }) {
  if (!(n > 1)) {
    return <span className="dim">single</span>
  }
  return (
    <span className="dt-count" title={`${fmtInt(n)} deduplicated occurrences`}>
      ×{fmtInt(n)}
    </span>
  )
}

function Row({
  d,
  now,
  onOpenFlow,
}: {
  d: Detection
  now: number
  onOpenFlow: (d: Detection) => void
}) {
  const span = d.count > 1 && d.last_ts !== d.ts
  return (
    <>
      <tr className={d.disagreement ? 'disagree' : ''}>
        <td>
          <SeverityChip s={d.severity} />
        </td>
        <td>
          <span className={`cls ${d.class}`} style={{ background: classColor(d.class) }}>
            {d.class.toUpperCase()}
          </span>
        </td>
        <td className="num">
          <CountCell n={d.count} />
        </td>
        <td
          className="mono linkish"
          title={`investigate ${d.src_ip}`}
          onClick={() => navigateWith('/investigate', { host: d.src_ip })}
        >
          {endpoint(d.src_ip, d.src_port)}
        </td>
        <td className="dim">→</td>
        <td
          className="mono linkish"
          title={`investigate ${d.dst_ip}`}
          onClick={() => navigateWith('/investigate', { host: d.dst_ip })}
        >
          {endpoint(d.dst_ip, d.dst_port)}
        </td>
        <td className="dim">{(d.protocol || '—').toUpperCase()}</td>
        <td className="mono">
          <span className="bar" style={{ width: `${Math.max(2, Math.round(d.confidence * 60))}px` }} />
          {fmtPct(d.confidence)}
        </td>
        <td title={fmtDateTime(d.ts)}>{fmtAgo(d.ts, now)}</td>
        <td title={fmtDateTime(d.last_ts)}>{span ? fmtAgo(d.last_ts, now) : <span className="dim">—</span>}</td>
        <td>
          <button className="dt-open" onClick={() => onOpenFlow(d)} title="open the flow inspector">
            flow #{d.flow_id}
          </button>
          {d.flow_ids && d.flow_ids.length > 1 ? (
            <span className="dim" title={d.flow_ids.join(', ')}>
              {' '}
              +{fmtInt(d.flow_ids.length - 1)}
            </span>
          ) : null}
        </td>
      </tr>
      {d.reason || d.disagreement || (d.models && d.models.length) ? (
        <tr className="dt-why">
          <td colSpan={11}>
            {d.disagreement ? <span className="badge-dis">model disagreement</span> : null}{' '}
            {d.reason ? <span>{d.reason}</span> : null}
            {d.models && d.models.length ? (
              <span className="dim">
                {' · '}
                {d.models
                  .map((m) => `${m.model_id} (${m.role}) ${m.class} ${fmtPct(m.confidence, 0)}`)
                  .join('  ')}
              </span>
            ) : null}
          </td>
        </tr>
      ) : null}
    </>
  )
}

export function Detections() {
  const [fClass, setFClass] = usePersistedState('detections.class', '')
  const [fSeverity, setFSeverity] = usePersistedState<Severity | ''>('detections.severity', '')
  const [fMinConf, setFMinConf] = usePersistedState('detections.minConf', 0)
  const [fWindowMin, setFWindowMin] = usePersistedState('detections.windowMin', 0)
  const [limit, setLimit] = usePersistedState('detections.limit', 100)

  const [list, setList] = useState<DetectionList | null>(null)
  const [unavailable, setUnavailable] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [now, setNow] = useState(() => Date.now())

  // Opening the inspector needs the flow's real Classification — the detection
  // carries a class and a confidence but not the 7-way probability vector, and
  // synthesising one would be inventing data (§16). The stored classification
  // ring is scanned for the flow instead; a flow already evicted from it says so.
  const [inspect, setInspect] = useState<Classification | null>(null)
  const [inspectErr, setInspectErr] = useState<string | null>(null)

  const load = useCallback(() => {
    const since =
      fWindowMin > 0 ? new Date(Date.now() - fWindowMin * 60_000).toISOString() : undefined
    return getDetections({
      limit,
      class: fClass || undefined,
      severity: fSeverity || undefined,
      min_confidence: fMinConf > 0 ? fMinConf / 100 : undefined,
      since,
    }).then((r) => {
      setLoading(false)
      setNow(Date.now())
      if (r.state === 'ok') {
        setList(r.list)
        setUnavailable(null)
        setError(null)
      } else if (r.state === 'unavailable') {
        setList(null)
        setUnavailable(r.message)
        setError(null)
      } else {
        setError(r.message)
        setUnavailable(null)
      }
    })
  }, [limit, fClass, fSeverity, fMinConf, fWindowMin])

  // Same shape as the other polled views: a ref so the interval always calls the
  // current closure, and no polling once the endpoint has said 404 — retrying a
  // route that does not exist would just log a 404 a second, forever.
  const loadRef = useRef(load)
  loadRef.current = load
  useEffect(() => {
    setLoading(true)
    loadRef.current()
  }, [load])

  useEffect(() => {
    if (unavailable) return
    const id = window.setInterval(() => loadRef.current(), POLL_MS)
    return () => window.clearInterval(id)
  }, [unavailable])

  const openFlow = useCallback((d: Detection) => {
    setInspectErr(null)
    getClassifications(1000)
      .then((rows) => {
        const hit = rows.find((c) => c.flow_id === d.flow_id)
        if (hit) setInspect(hit)
        else
          setInspectErr(
            `flow ${d.flow_id} is no longer in the stored classification window — the detection outlived it.`,
          )
      })
      .catch((e: unknown) => setInspectErr(e instanceof Error ? e.message : String(e)))
  }, [])

  const rows = list?.detections ?? []
  const filtersOn = Boolean(fClass || fSeverity || fMinConf > 0 || fWindowMin > 0)

  return (
    <div>
      <div className="page-h">
        <h1>Detections</h1>
        <span className="sub">
          deduplicated alert feed from <code>GET /api/v1/detections</code> (polled 2s, issue #117) —
          class, severity and minimum confidence are applied by the daemon
        </span>
      </div>

      {unavailable ? (
        <div className="mx-partial">
          <b>Not available in this build.</b> {unavailable} Every other LIVE view keeps working; this
          one lights up with no further change once the endpoint ships. Nothing is shown here in the
          meantime — a fabricated detection list would be worse than an empty one (PROJECT.md §16).
        </div>
      ) : null}

      {error ? <div className="src-msg err">detections unavailable — {error}</div> : null}
      {inspectErr ? <div className="src-msg err">{inspectErr}</div> : null}

      {!unavailable ? (
        <>
          <div className="flowbar">
            <label>
              severity
              <select
                value={fSeverity}
                onChange={(e) => setFSeverity(e.target.value as Severity | '')}
              >
                <option value="">all</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
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
              since
              <select value={fWindowMin} onChange={(e) => setFWindowMin(Number(e.target.value))}>
                {WINDOWS.map(([label, min]) => (
                  <option key={label} value={min}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              limit
              <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
                {LIMITS.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
            {filtersOn ? (
              <button
                onClick={() => {
                  setFClass('')
                  setFSeverity('')
                  setFMinConf(0)
                  setFWindowMin(0)
                }}
              >
                clear filters
              </button>
            ) : null}

            <span className="spacer" />
            <span className="dim">
              showing {fmtInt(rows.length)} / {fmtInt(list?.total ?? 0)} matched
              {list && list.evicted > 0 ? ` · ${fmtInt(list.evicted)} evicted` : ''}
            </span>
          </div>

          <div className="card wide">
            <div className="src-scroll">
              <table className="mini dt-table">
                <thead>
                  <tr>
                    <th>severity</th>
                    <th>class</th>
                    <th className="num">count</th>
                    <th>source</th>
                    <th aria-hidden="true" />
                    <th>destination</th>
                    <th>proto</th>
                    <th className="num">confidence</th>
                    <th>first seen</th>
                    <th>last seen</th>
                    <th>flow</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((d) => (
                    <Row key={d.id} d={d} now={now} onOpenFlow={openFlow} />
                  ))}
                </tbody>
              </table>
            </div>
            {loading ? <div className="foot">loading…</div> : null}
            {!loading && rows.length === 0 ? (
              <div className="foot">
                {filtersOn
                  ? 'no detections match the current filters'
                  : 'no detections — the endpoint answered, it simply has nothing to report'}
              </div>
            ) : null}
            <div className="foot">
              <b>count</b> is the deduplicated occurrence total: one row can stand for hundreds of
              probes. <b>first seen</b> is the detection&apos;s own <code>ts</code>, <b>last seen</b>{' '}
              its <code>last_ts</code>, and <b>confidence</b> the maximum observed across those
              occurrences.
            </div>
          </div>
        </>
      ) : null}

      {inspect ? <FlowInspector cls={inspect} onClose={() => setInspect(null)} /> : null}
    </div>
  )
}
