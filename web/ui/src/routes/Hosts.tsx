import { useCallback, useEffect, useMemo, useState } from 'react'
import { getHosts, hostReportURL } from '../api/client'
import type { HostProfile } from '../api/types'
import { useStream } from '../api/stream'
import { IssueLink } from '../components/IssueLink'
import { classColor } from '../lib/classes'
import { fmtAgo, fmtBytes, fmtInt } from '../lib/format'
import { navigateWith } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'

// Hosts (PROJECT.md §19.5, issue #39). Every profile comes from
// GET /api/v1/hosts, which is maintained incrementally by internal/insight —
// the browser does no aggregation here, unlike the Dashboard's rolling window.
//
// Addresses are packet-derived strings (§21, §28.11). They are rendered as text
// only; React escapes them, and nothing here uses dangerouslySetInnerHTML.

type SortKey = 'last_seen' | 'flows' | 'bytes'

const REFRESH_MS = 2000

/** The class mix as a single stacked bar. */
function ClassMix({ host }: { host: HostProfile }) {
  const total = host.classes.reduce((n, c) => n + c.count, 0)
  if (total === 0) return <span className="dim">—</span>
  return (
    <span className="mixbar" title={host.classes.map((c) => `${c.class} ${c.count}`).join(' · ')}>
      {host.classes.map((c) => (
        <i
          key={c.class}
          style={{ width: `${(c.count / total) * 100}%`, background: classColor(c.class) }}
        />
      ))}
    </span>
  )
}

function ProtoList({ host }: { host: HostProfile }) {
  if (host.protocols.length === 0) return <span className="dim">—</span>
  return (
    <>
      {host.protocols.slice(0, 3).map((p) => (
        <span key={p.proto} className="chip">
          {p.proto}
          <b>{fmtInt(p.flows)}</b>
        </span>
      ))}
    </>
  )
}

function PortList({ host }: { host: HostProfile }) {
  if (host.top_ports.length === 0) return <span className="dim">—</span>
  return (
    <>
      {host.top_ports.slice(0, 4).map((p) => (
        <span key={p.port} className="chip">
          {p.port}
          <b>{fmtInt(p.flows)}</b>
        </span>
      ))}
    </>
  )
}

/**
 * Per-row report link (issue #66, ADR 0023). No range or filter here — a list
 * row has no framed window, so the report covers whatever the daemon retains and
 * says so in its own scope block. stopPropagation keeps the click off the row's
 * navigate-to-investigate handler.
 */
function ReportCell({ ip }: { ip: string }) {
  return (
    <a
      className="rep-dl-btn"
      href={hostReportURL(ip, { format: 'html' })}
      onClick={(e) => e.stopPropagation()}
      title={`download a standalone HTML investigation report for ${ip}`}
    >
      report
    </a>
  )
}

export function Hosts() {
  const { connected } = useStream()
  const [rows, setRows] = useState<HostProfile[]>([])
  const [err, setErr] = useState<string>('')
  const [loaded, setLoaded] = useState(false)

  const [sort, setSort] = usePersistedState<SortKey>('hosts.sort', 'last_seen')
  const [q, setQ] = usePersistedState<string>('hosts.q', '')
  const [limit, setLimit] = usePersistedState<number>('hosts.limit', 200)
  const [live, setLive] = usePersistedState<boolean>('hosts.live', true)

  const load = useCallback(() => {
    getHosts({ sort, q: q.trim(), limit })
      .then((h) => {
        setRows(h)
        setErr('')
        setLoaded(true)
      })
      .catch((e: unknown) => {
        setErr(e instanceof Error ? e.message : String(e))
        setLoaded(true)
      })
  }, [sort, q, limit])

  useEffect(() => {
    load()
    if (!live) return
    const t = setInterval(load, REFRESH_MS)
    return () => clearInterval(t)
  }, [load, live])

  const totals = useMemo(
    () => ({
      hosts: rows.length,
      flows: rows.reduce((n, h) => n + h.flows, 0),
      bytes: rows.reduce((n, h) => n + h.bytes_in + h.bytes_out, 0),
      disagreements: rows.reduce((n, h) => n + h.disagreements, 0),
    }),
    [rows],
  )

  const header = (key: SortKey, label: string) => (
    <th
      className={'sortable num' + (sort === key ? ' sorted' : '')}
      onClick={() => setSort(key)}
      title={`sort by ${label}`}
    >
      {label}
      {sort === key ? <span className="caret"> ▾</span> : null}
    </th>
  )

  return (
    <div>
      <div className="page-h">
        <h1>Hosts</h1>
        <span className="sub">
          observed host profiles from <code>/api/v1/hosts</code> (§19.5) — click a row to investigate
        </span>
      </div>

      <div className="flowbar">
        <input
          className="txt"
          placeholder="filter address…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          aria-label="filter by address substring"
        />
        <label>
          sort
          <select value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
            <option value="last_seen">last seen</option>
            <option value="flows">flows</option>
            <option value="bytes">bytes</option>
          </select>
        </label>
        <label>
          limit
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {[50, 200, 500, 2000].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <label>
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          auto-refresh
        </label>
        <button onClick={load}>refresh</button>
        <span className="spacer" />
        <span className="dim">
          {fmtInt(totals.hosts)} hosts · {fmtInt(totals.flows)} flow sides ·{' '}
          {fmtBytes(totals.bytes)} · {fmtInt(totals.disagreements)} disagreements ·{' '}
          {connected ? 'stream live' : 'stream down'}
        </span>
      </div>

      {err ? <p className="err">{err}</p> : null}

      <div className="flowscroll hosts-scroll">
        <table className="flow comfortable">
          <thead>
            <tr>
              <th>address</th>
              <th>first seen</th>
              <th>last seen</th>
              {header('flows', 'flows')}
              <th className="num">in</th>
              <th className="num">out</th>
              <th>protocols</th>
              <th>top ports</th>
              <th>class mix</th>
              <th className="num">disagree</th>
              <th className="num">anomaly</th>
              <th>report</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((h) => (
              <tr
                key={h.ip}
                className={h.disagreements > 0 ? 'disagree' : undefined}
                onClick={() => navigateWith('/investigate', { host: h.ip })}
                style={{ cursor: 'pointer' }}
              >
                <td className="mono">{h.ip}</td>
                <td className="dim">{fmtAgo(h.first_seen)}</td>
                <td className="dim">{fmtAgo(h.last_seen)}</td>
                <td className="num">{fmtInt(h.flows)}</td>
                <td className="num">{fmtBytes(h.bytes_in)}</td>
                <td className="num">{fmtBytes(h.bytes_out)}</td>
                <td>
                  <ProtoList host={h} />
                </td>
                <td>
                  <PortList host={h} />
                </td>
                <td>
                  <ClassMix host={h} />
                </td>
                <td className="num">{h.disagreements > 0 ? fmtInt(h.disagreements) : '—'}</td>
                <td
                  className="num"
                  title={
                    h.anomaly_available
                      ? `${fmtInt(h.anomaly_flows)} flows scored · mean ${h.anomaly_mean.toFixed(
                          2,
                        )} · ${fmtInt(h.anomaly_exceeded)} over threshold`
                      : 'no anomaly model active'
                  }
                >
                  {h.anomaly_available ? (
                    <>
                      {h.anomaly_max.toFixed(2)}
                      {h.anomaly_exceeded > 0 ? (
                        <span className="badge-dis" title="flows over the model's threshold">
                          {fmtInt(h.anomaly_exceeded)}
                        </span>
                      ) : null}
                    </>
                  ) : (
                    '—'
                  )}
                </td>
                <td>
                  <ReportCell ip={h.ip} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {loaded && rows.length === 0 && !err ? (
          <div className="foot">
            no hosts observed yet — replay a capture or start a live source, then come back
          </div>
        ) : null}
      </div>

      <div className="sect stub">
        <span className="tag">
          <IssueLink n={63} />
        </span>{' '}
        The <b>anomaly</b> column is the per-host reconstruction score once a{' '}
        <code>flow-anomaly-v1</code> model is active (ADR 0037); it reads <code>—</code> otherwise.
        A behavioural baseline / per-host embedding (§19.5) is still <IssueLink n={63} />, so the
        API reports <code>baseline_available: false</code> rather than an invented range.
      </div>
    </div>
  )
}
