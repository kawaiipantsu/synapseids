import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  getHost,
  getHostClassifications,
  getHostFlows,
  getHosts,
  getHostSimilar,
  getTimeline,
  hostReportURL,
  type BucketWidth,
} from '../api/client'
import { useStream } from '../api/stream'
import type {
  Classification,
  FlowRecord,
  HostProfile,
  HostSimilarResult,
  TimelineSeries,
} from '../api/types'
import { FlowInspector } from '../components/FlowInspector'
import { IssueLink } from '../components/IssueLink'
import { TimelineChart, type Range } from '../components/TimelineChart'
import { CLASS_NAMES, classColor } from '../lib/classes'
import { fmtAgo, fmtBytes, fmtDateTime, fmtDuration, fmtInt, fmtPct } from '../lib/format'
import { Link, navigateWith, useHashQuery } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'

// Investigation mode (PROJECT.md §19.4, issue #40): the whole view pivots around
// one host, selected via #/investigate?host=<ip>. Everything on the page is
// scoped to that address — flows, verdicts, peers, ports, volume and the
// classification timeline.
//
// The host string comes from a decoded packet and is therefore untrusted (§21,
// §28.11). It is rendered as text and URL-encoded on the way into a request;
// the daemon re-validates it with net/netip and answers 400 if it is not an IP.

const REFRESH_MS = 3000
const LIST_LIMIT = 200

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="card">
      <h3>{label}</h3>
      <div className="big">{value}</div>
      {sub ? <div className="foot">{sub}</div> : null}
    </div>
  )
}

/**
 * Similar hosts (§30, issue #63, ADR 0039). A cosine match over a hand-crafted
 * behavioural fingerprint — a pivot lead, not a verdict. Self-fetches so it does
 * not widen the host view's main load.
 */
function SimilarHostsPanel({ host }: { host: string }) {
  const [data, setData] = useState<HostSimilarResult | null>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let live = true
    setData(null)
    setErr('')
    getHostSimilar(host, { limit: 8 })
      .then((d) => live && setData(d))
      .catch((e: unknown) => live && setErr(e instanceof Error ? e.message : String(e)))
    return () => {
      live = false
    }
  }, [host])

  if (err) return null // the host view already surfaces load errors; stay quiet here
  if (data == null) {
    return (
      <div className="sect">
        <h3>Similar hosts</h3>
        <div className="foot">loading…</div>
      </div>
    )
  }

  // Top behavioural dimensions of this host, for a one-line "why".
  const topDims = [...data.fingerprint.dims]
    .filter((d) => d.name !== 'flow_volume')
    .sort((a, b) => b.value - a.value)
    .slice(0, 4)

  return (
    <div className="sect">
      <h3>Similar hosts</h3>
      <p className="foot">
        {data.method}{' '}
        {data.fingerprint.flow_count < 20 ? (
          <b>Thin fingerprint ({fmtInt(data.fingerprint.flow_count)} flows) — treat with caution.</b>
        ) : null}
      </p>
      <p className="foot mono">
        fingerprint:{' '}
        {topDims.map((d) => `${d.name}=${d.value.toFixed(2)}`).join('  ·  ')}
      </p>
      {data.similar.length === 0 ? (
        <div className="foot">
          no other host has ≥ {data.min_flows} flows to compare against.
        </div>
      ) : (
        <table className="flow comfortable">
          <thead>
            <tr>
              <th>address</th>
              <th className="num">cosine</th>
              <th className="num">flows</th>
            </tr>
          </thead>
          <tbody>
            {data.similar.map((s) => (
              <tr
                key={s.ip}
                onClick={() => navigateWith('/investigate', { host: s.ip })}
                style={{ cursor: 'pointer' }}
              >
                <td className="mono">{s.ip}</td>
                <td className="num">{s.cosine.toFixed(3)}</td>
                <td className="num">{fmtInt(s.flow_count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

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
 * Download report (issue #66, ADR 0023). Two plain links, because the daemon
 * sends `Content-Disposition: attachment` and the browser's own download path is
 * better than anything a fetch+Blob would give us.
 *
 * The URL carries whatever the operator has already framed: the brushed timeline
 * range and the active class/disagreement filters. That is the natural
 * interaction — they have narrowed the view to what they care about, and the
 * artefact should describe exactly that, not silently widen back to everything.
 */
function ReportLinks({
  host,
  range,
  bucket,
  classFilter,
  disagreeOnly,
}: {
  host: string
  range: Range | null
  bucket: BucketWidth
  classFilter: string
  disagreeOnly: boolean
}) {
  const p = {
    from: range?.from,
    to: range?.to,
    bucket,
    class: classFilter || undefined,
    disagreement: disagreeOnly || undefined,
  }
  const scope = range ? 'brushed range' : 'retained window'
  return (
    <span className="rep-dl">
      <span className="rep-dl-lbl">download report</span>
      <a
        className="rep-dl-btn"
        href={hostReportURL(host, { ...p, format: 'html' })}
        title={`standalone HTML report for ${host} — ${scope}`}
      >
        HTML
      </a>
      <a
        className="rep-dl-btn"
        href={hostReportURL(host, { ...p, format: 'json' })}
        title={`JSON report for ${host} — ${scope}`}
      >
        JSON
      </a>
      <span className="rep-dl-scope dim">{scope}</span>
    </span>
  )
}

/** Host picker shown when no ?host= is set. */
function HostPicker() {
  const [rows, setRows] = useState<HostProfile[]>([])
  const [err, setErr] = useState('')
  useEffect(() => {
    getHosts({ sort: 'flows', limit: 25 })
      .then(setRows)
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
  }, [])
  return (
    <div>
      <div className="page-h">
        <h1>Investigate</h1>
        <span className="sub">pick a host to pivot the view around it (§19.4)</span>
      </div>
      {err ? <p className="err">{err}</p> : null}
      {rows.length === 0 && !err ? (
        <p className="dim">no hosts observed yet — replay a capture first.</p>
      ) : (
        <table className="mini">
          <thead>
            <tr>
              <th>address</th>
              <th className="num">flows</th>
              <th className="num">volume</th>
              <th>last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((h) => (
              <tr
                key={h.ip}
                style={{ cursor: 'pointer' }}
                onClick={() => navigateWith('/investigate', { host: h.ip })}
              >
                <td className="mono">{h.ip}</td>
                <td className="num">{fmtInt(h.flows)}</td>
                <td className="num">{fmtBytes(h.bytes_in + h.bytes_out)}</td>
                <td className="dim">{fmtAgo(h.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export function Investigate() {
  const params = useHashQuery()
  const host = params.get('host') ?? ''
  const { connected } = useStream()

  const [profile, setProfile] = useState<HostProfile | null>(null)
  const [flows, setFlows] = useState<FlowRecord[]>([])
  const [cls, setCls] = useState<Classification[]>([])
  const [series, setSeries] = useState<TimelineSeries | null>(null)
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState<Classification | null>(null)

  const [bucket, setBucket] = usePersistedState<BucketWidth>('investigate.bucket', '1s')
  const [classFilter, setClassFilter] = usePersistedState<string>('investigate.class', '')
  const [disagreeOnly, setDisagreeOnly] = usePersistedState<boolean>('investigate.disagree', false)
  const [live, setLive] = usePersistedState<boolean>('investigate.live', true)

  // The brushed range is intentionally not persisted: it is a transient
  // investigation gesture, not a saved preference.
  const [range, setRange] = useState<Range | null>(null)

  const filters = useMemo(
    () => ({
      limit: LIST_LIMIT,
      class: classFilter || undefined,
      disagreement: disagreeOnly || undefined,
      from: range?.from,
      to: range?.to,
    }),
    [classFilter, disagreeOnly, range],
  )

  const load = useCallback(() => {
    if (!host) return
    Promise.all([
      getHost(host),
      getHostFlows(host, filters),
      getHostClassifications(host, filters),
      getTimeline({ bucket, host, class: classFilter || undefined }),
    ])
      .then(([p, f, c, s]) => {
        setProfile(p)
        setFlows(f)
        setCls(c)
        setSeries(s)
        setErr('')
      })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
  }, [host, filters, bucket, classFilter])

  useEffect(() => {
    setProfile(null)
    setRange(null)
  }, [host])

  useEffect(() => {
    load()
    if (!live) return
    const t = setInterval(load, REFRESH_MS)
    return () => clearInterval(t)
  }, [load, live])

  if (!host) return <HostPicker />

  const peerMax = profile?.top_peers?.reduce((m, p) => Math.max(m, p.flows), 0) ?? 0
  const portMax = profile?.top_ports.reduce((m, p) => Math.max(m, p.flows), 0) ?? 0

  return (
    <div>
      <div className="page-h">
        <h1>
          Investigate <span className="mono host-pivot">{host}</span>
        </h1>
        <span className="sub">
          every panel is scoped to this host (§19.4) · <code>/api/v1/hosts/{'{ip}'}</code>
        </span>
      </div>

      <div className="flowbar">
        <button onClick={() => navigateWith('/investigate', {})}>change host</button>
        <label>
          class
          <select value={classFilter} onChange={(e) => setClassFilter(e.target.value)}>
            <option value="">all</option>
            {CLASS_NAMES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={disagreeOnly}
            onChange={(e) => setDisagreeOnly(e.target.checked)}
          />
          disagreements only
        </label>
        <label>
          bucket
          <select value={bucket} onChange={(e) => setBucket(e.target.value as BucketWidth)}>
            <option value="1s">1s</option>
            <option value="10s">10s</option>
            <option value="1m">1m</option>
          </select>
        </label>
        <label>
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          auto-refresh
        </label>
        <button onClick={load}>refresh</button>
        <ReportLinks
          host={host}
          range={range}
          bucket={bucket}
          classFilter={classFilter}
          disagreeOnly={disagreeOnly}
        />
        <span className="spacer" />
        <span className="dim">{connected ? 'stream live' : 'stream down'}</span>
      </div>

      {err ? <p className="err">{err}</p> : null}
      {!profile && !err ? <p className="dim">loading {host}…</p> : null}

      {profile ? (
        <>
          <div className="cards">
            <Stat
              label="Flows"
              value={fmtInt(profile.flows)}
              sub={`${fmtInt(profile.flows_initiated)} initiated · ${fmtInt(profile.flows_responded)} answered`}
            />
            <Stat
              label="Volume"
              value={fmtBytes(profile.bytes_in + profile.bytes_out)}
              sub={`${fmtBytes(profile.bytes_in)} in · ${fmtBytes(profile.bytes_out)} out`}
            />
            <Stat
              label="Packets"
              value={fmtInt(profile.packets_in + profile.packets_out)}
              sub={`${fmtInt(profile.packets_in)} in · ${fmtInt(profile.packets_out)} out`}
            />
            <Stat
              label="Model disagreement"
              value={fmtInt(profile.disagreements)}
              sub={`of ${fmtInt(profile.classifications)} verdicts`}
            />
            <Stat label="First seen" value={fmtAgo(profile.first_seen)} sub={fmtDateTime(profile.first_seen)} />
            <Stat label="Last seen" value={fmtAgo(profile.last_seen)} sub={fmtDateTime(profile.last_seen)} />
            {profile.anomaly_available ? (
              <Stat
                label="Anomaly score"
                value={`peak ${profile.anomaly_max.toFixed(2)}`}
                sub={`mean ${profile.anomaly_mean.toFixed(2)} over ${fmtInt(
                  profile.anomaly_flows,
                )} flows · ${fmtInt(profile.anomaly_exceeded)} over threshold`}
              />
            ) : null}
          </div>

          <div className="sect">
            <h2>Classification timeline</h2>
            {series && series.buckets.length > 0 ? (
              <TimelineChart
                buckets={series.buckets}
                bucketSec={series.bucket_sec}
                onBrush={setRange}
                selection={range}
                ariaLabel={`classification timeline for ${host}`}
              />
            ) : (
              <p className="dim">no verdicts in the retained window.</p>
            )}
          </div>

          <div className="cards">
            <div className="card span2">
              <h3>Top peers</h3>
              {profile.top_peers && profile.top_peers.length > 0 ? (
                profile.top_peers.map((p) => (
                  <div key={p.ip} onClick={() => navigateWith('/investigate', { host: p.ip })} style={{ cursor: 'pointer' }}>
                    <BarRow label={p.ip} value={p.flows} max={peerMax} />
                  </div>
                ))
              ) : (
                <div className="foot">no peers recorded</div>
              )}
            </div>

            <div className="card span2">
              <h3>Top service ports</h3>
              {profile.top_ports.length > 0 ? (
                profile.top_ports.map((p) => (
                  <BarRow key={p.port} label={String(p.port)} value={p.flows} max={portMax} />
                ))
              ) : (
                <div className="foot">no ports recorded</div>
              )}
            </div>

            <div className="card span2">
              <h3>Class mix</h3>
              {profile.classes.length > 0 ? (
                profile.classes.map((c) => (
                  <BarRow
                    key={c.class}
                    label={c.class}
                    value={c.count}
                    max={profile.classes.reduce((m, x) => Math.max(m, x.count), 0)}
                    color={classColor(c.class)}
                  />
                ))
              ) : (
                <div className="foot">no verdicts yet</div>
              )}
            </div>

            <div className="card span2">
              <h3>Protocols</h3>
              {profile.protocols.length > 0 ? (
                profile.protocols.map((p) => (
                  <BarRow
                    key={p.proto}
                    label={p.proto}
                    value={p.flows}
                    max={profile.protocols.reduce((m, x) => Math.max(m, x.flows), 0)}
                  />
                ))
              ) : (
                <div className="foot">none</div>
              )}
            </div>
          </div>

          <div className="sect">
            <h2>
              Classification history{' '}
              <span className="dim">
                {fmtInt(cls.length)} shown
                {range ? ' · time-filtered' : ''}
              </span>
            </h2>
            <div className="flowscroll short">
              <table className="flow compact">
                <thead>
                  <tr>
                    <th>time</th>
                    <th>proto</th>
                    <th>initiator</th>
                    <th>responder</th>
                    <th>class</th>
                    <th className="num">score</th>
                    <th>flags</th>
                  </tr>
                </thead>
                <tbody>
                  {cls.map((c) => (
                    <tr
                      key={`${c.flow_id}-${c.ts}`}
                      className={c.result.disagreement ? 'disagree' : undefined}
                      onClick={() => setSelected(c)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td className="dim">{fmtDateTime(c.ts)}</td>
                      <td>{c.proto}</td>
                      <td className="mono">
                        {c.initiator_ip}:{c.initiator_port}
                      </td>
                      <td className="mono">
                        {c.responder_ip}:{c.responder_port}
                      </td>
                      <td>
                        <span className="pill" style={{ background: classColor(c.result.class) }}>
                          {c.result.class}
                        </span>
                      </td>
                      <td className="num">{fmtPct(c.result.score)}</td>
                      <td>{c.result.disagreement ? <span className="badge-dis">disagree</span> : null}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {cls.length === 0 ? <div className="foot">no verdicts match the current filters</div> : null}
            </div>
          </div>

          <div className="sect">
            <h2>
              Flows <span className="dim">{fmtInt(flows.length)} shown{range ? ' · time-filtered' : ''}</span>
            </h2>
            <div className="flowscroll short">
              <table className="flow compact">
                <thead>
                  <tr>
                    <th className="num">id</th>
                    <th>proto</th>
                    <th>initiator</th>
                    <th>responder</th>
                    <th className="num">duration</th>
                    <th className="num">pkts</th>
                    <th className="num">bytes</th>
                    <th>closed</th>
                  </tr>
                </thead>
                <tbody>
                  {flows.map((f) => (
                    <tr key={`${f.id}-${f.snapshot_index}`}>
                      <td className="num mono">{f.id}</td>
                      <td>{f.proto}</td>
                      <td className="mono">
                        {f.initiator_ip}:{f.initiator_port}
                      </td>
                      <td className="mono">
                        {f.responder_ip}:{f.responder_port}
                      </td>
                      <td className="num">{fmtDuration(f.duration_sec)}</td>
                      <td className="num">{fmtInt(f.fwd_packets + f.bwd_packets)}</td>
                      <td className="num">{fmtBytes(f.fwd_bytes + f.bwd_bytes)}</td>
                      <td className="dim">{f.close_reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {flows.length === 0 ? <div className="foot">no flows match the current filters</div> : null}
            </div>
          </div>

          <SimilarHostsPanel host={host} />

          <div className="sect stub">
            <span className="tag">
              <IssueLink n={63} />
            </span>{' '}
            "Similar hosts" is a cosine match over a <b>hand-crafted</b> behavioural fingerprint
            (ADR 0039) — a lateral-movement lead, not a verdict. A <i>learned</i> per-host embedding
            and a behavioural baseline (§19.4) are still <IssueLink n={63} />, so{' '}
            <code>baseline_available: false</code> and nothing here invents a range to compare
            against.
          </div>
          <div className="sect stub">
            <span className="tag">
              <IssueLink n={117} />
            </span>{' '}
            Related detections (§19.4) need the <code>/api/v1/detections</code> resource from{' '}
            <IssueLink n={117} />. The <Link to="/detections">LIVE ▸ Detections</Link> view is built
            and will show them the moment that endpoint answers; until then it reports the endpoint
            as unavailable rather than guessing.
          </div>
        </>
      ) : null}

      {selected ? <FlowInspector cls={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  )
}
