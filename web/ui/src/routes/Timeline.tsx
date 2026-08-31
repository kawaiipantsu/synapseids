import { useCallback, useEffect, useMemo, useState } from 'react'
import { getClassifications, getTimeline, type BucketWidth } from '../api/client'
import { useStream } from '../api/stream'
import type { Classification, TimelineSeries } from '../api/types'
import { FlowInspector } from '../components/FlowInspector'
import { TimelineChart, type Range } from '../components/TimelineChart'
import { CLASS_NAMES, classColor } from '../lib/classes'
import { fmtDateTime, fmtInt, fmtPct } from '../lib/format'
import { navigateWith } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'

// Classification timeline (PROJECT.md §19.6, issue #41), daemon-wide. The
// unscoped series is the incrementally maintained ring in internal/insight;
// brushing a range filters the verdict list below it, which is the interaction
// the issue is actually about.
//
// The per-host version of this chart lives on #/investigate.

const REFRESH_MS = 2000
const LIST_LIMIT = 300

export function Timeline() {
  const { connected } = useStream()
  const [series, setSeries] = useState<TimelineSeries | null>(null)
  const [rows, setRows] = useState<Classification[]>([])
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState<Classification | null>(null)

  const [bucket, setBucket] = usePersistedState<BucketWidth>('timeline.bucket', '1s')
  const [classFilter, setClassFilter] = usePersistedState<string>('timeline.class', '')
  const [live, setLive] = usePersistedState<boolean>('timeline.live', true)
  const [range, setRange] = useState<Range | null>(null)

  const load = useCallback(() => {
    Promise.all([
      getTimeline({ bucket, class: classFilter || undefined, from: range?.from, to: range?.to }),
      // The daemon-wide verdict list reuses GET /api/v1/classifications, which
      // has no from/to — the brush is applied client-side here. The per-host
      // routes do it server-side.
      getClassifications(LIST_LIMIT),
    ])
      .then(([s, c]) => {
        setSeries(s)
        setRows(c)
        setErr('')
      })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
  }, [bucket, classFilter, range])

  useEffect(() => {
    load()
    if (!live) return
    const t = setInterval(load, REFRESH_MS)
    return () => clearInterval(t)
  }, [load, live])

  const visible = useMemo(() => {
    const lo = range ? Date.parse(range.from) : -Infinity
    const hi = range ? Date.parse(range.to) : Infinity
    return rows.filter((c) => {
      if (classFilter && c.result.class !== classFilter) return false
      const t = Date.parse(c.ts)
      return t >= lo && t <= hi
    })
  }, [rows, range, classFilter])

  const totals = useMemo(() => {
    let total = 0
    let disagree = 0
    for (const b of series?.buckets ?? []) {
      total += b.total
      disagree += b.disagreements
    }
    return { total, disagree }
  }, [series])

  return (
    <div>
      <div className="page-h">
        <h1>Classification timeline</h1>
        <span className="sub">
          volume per class over time from <code>/api/v1/timeline</code> (§19.6) — drag a range to
          filter the verdicts below
        </span>
      </div>

      <div className="flowbar">
        <label>
          bucket
          <select value={bucket} onChange={(e) => setBucket(e.target.value as BucketWidth)}>
            <option value="1s">1s</option>
            <option value="10s">10s</option>
            <option value="1m">1m</option>
          </select>
        </label>
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
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          auto-refresh
        </label>
        <button onClick={load}>refresh</button>
        {range ? <button onClick={() => setRange(null)}>clear range</button> : null}
        <span className="spacer" />
        <span className="dim">
          {fmtInt(totals.total)} verdicts · {fmtInt(totals.disagree)} disagreements ·{' '}
          {connected ? 'stream live' : 'stream down'}
        </span>
      </div>

      {err ? <p className="err">{err}</p> : null}

      {series && series.buckets.length > 0 ? (
        <TimelineChart
          buckets={series.buckets}
          bucketSec={series.bucket_sec}
          height={200}
          onBrush={setRange}
          selection={range}
          ariaLabel="daemon-wide classification timeline"
        />
      ) : (
        <p className="dim">no classifications in the retained window yet.</p>
      )}

      <div className="sect">
        <h2>
          Verdicts{' '}
          <span className="dim">
            {fmtInt(visible.length)} of {fmtInt(rows.length)} retained
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
              {visible.map((c) => (
                <tr
                  key={`${c.flow_id}-${c.ts}`}
                  className={c.result.disagreement ? 'disagree' : undefined}
                >
                  <td className="dim">{fmtDateTime(c.ts)}</td>
                  <td>{c.proto}</td>
                  <td
                    className="mono linkish"
                    onClick={() => navigateWith('/investigate', { host: c.initiator_ip })}
                    title="investigate this host"
                  >
                    {c.initiator_ip}:{c.initiator_port}
                  </td>
                  <td
                    className="mono linkish"
                    onClick={() => navigateWith('/investigate', { host: c.responder_ip })}
                    title="investigate this host"
                  >
                    {c.responder_ip}:{c.responder_port}
                  </td>
                  <td onClick={() => setSelected(c)} style={{ cursor: 'pointer' }}>
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
          {visible.length === 0 ? (
            <div className="foot">no verdicts in the selected range</div>
          ) : null}
        </div>
      </div>

      <div className="sect stub">
        <span className="tag">Phase 7</span> The anomaly-score series (§19.6) needs the anomaly model.
        The API says <code>anomaly_available: false</code> rather than plotting a fabricated zero line.
      </div>

      {selected ? <FlowInspector cls={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  )
}
