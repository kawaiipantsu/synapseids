import { IPLabel, IPNodeLabel } from './IPContext'
import { useCallback, useMemo, useRef, useState } from 'react'
import { getFlows, getMatrix } from '../api/client'
import { classColor } from '../lib/classes'
import { fmtBytes, fmtInt } from '../lib/format'
import { Link } from '../lib/hashRouter'
import { buildTrafficGraph, layoutGraph } from '../lib/trafficGraph'
import { usePoll } from '../lib/usePoll'
import { Icon } from './Icon'

const NODE_COLOR = { private: '#51d8c6', public: '#a997ff', special: '#92a8bf' }
const loadGraph = () => getMatrix({ limit: 180, sort: 'bytes' })
const loadRecords = () => getFlows(500)

export function TrafficNetwork({ compact = false }: { compact?: boolean }) {
  const [paused, setPaused] = useState(false)
  const { data, error, updated } = usePoll(loadGraph, 5000, paused)
  const records = usePoll(loadRecords, 10000, paused)
  const [layout, setLayout] = useState<'force' | 'ring' | 'grouped'>('force')
  const [selected, setSelected] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [threatsOnly, setThreatsOnly] = useState(false)
  const [focus, setFocus] = useState(false)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const drag = useRef<{ x: number; y: number; px: number; py: number } | null>(
    null,
  )
  const svg = useRef<SVGSVGElement>(null)
  const pairs = useMemo(
    () =>
      (data?.pairs ?? []).filter(
        (p) => !threatsOnly || (p.threat_count ?? 0) > 0,
      ),
    [data, threatsOnly],
  )
  const graph = useMemo(
    () => buildTrafficGraph(pairs, records.data ?? [], compact ? 28 : 60),
    [pairs, records.data, compact],
  )
  // Only topology changes recompute the layout; live counters do not move nodes.
  const topologyKey = JSON.stringify([
    graph.nodes.map((n) => n.id).sort(),
    graph.edges.map((e) => [e.initiator, e.responder]).sort(),
  ])
  const positions = useMemo(
    () => layoutGraph(graph, layout),
    [topologyKey, layout],
  ) // eslint-disable-line react-hooks/exhaustive-deps
  const node = graph.nodes.find((n) => n.id === selected)
  const related = graph.edges.filter(
    (e) => e.initiator === selected || e.responder === selected,
  )
  const neighbors = new Set(related.flatMap((e) => [e.initiator, e.responder]))
  const matches = (ip: string) =>
    (!search || ip.toLowerCase().includes(search.toLowerCase())) &&
    (!focus || !node || neighbors.has(ip))
  const maxBytes = Math.max(1, ...graph.edges.map((e) => e.bytes))
  const reset = useCallback(() => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
    setSelected(null)
    setFocus(false)
    setSearch('')
  }, [])

  return (
    <section
      className={`network-panel ${compact ? 'network-compact' : ''}`}
      aria-label="Network relationships"
    >
      <div className="panel-heading">
        <div>
          <div className="eyebrow">TRAFFIC INTELLIGENCE</div>
          <h2>
            Asset connections{' '}
            <span className="count-badge">{graph.nodes.length}</span>
          </h2>
        </div>
        {compact ? (
          <Link className="text-action" to="/network">
            Explore network ↗
          </Link>
        ) : (
          <span className="data-status">
            {paused
              ? 'Paused'
              : error
                ? 'Update failed'
                : updated
                  ? 'Updates every 5s'
                  : 'Connecting'}
          </span>
        )}
      </div>
      <div className="network-toolbar">
        <label className="search-field">
          <Icon name="search" size={15} />
          <input
            aria-label="Find an asset"
            placeholder="Find an IP address…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>
        <select
          aria-label="Network layout"
          value={layout}
          onChange={(e) => setLayout(e.target.value as typeof layout)}
        >
          <option value="force">Connected</option>
          <option value="ring">Ring</option>
          <option value="grouped">By address scope</option>
        </select>
        <label className="check-label">
          <input
            type="checkbox"
            checked={threatsOnly}
            onChange={(e) => setThreatsOnly(e.target.checked)}
          />
          Threats
        </label>
        {!compact && (
          <button onClick={() => setPaused(!paused)} aria-pressed={paused}>
            {paused ? 'Resume updates' : 'Pause updates'}
          </button>
        )}
      </div>
      {error && (
        <div className="viz-notice err" role="alert">
          {data ? 'Showing the last successful snapshot. ' : ''}
          {error}
        </div>
      )}
      <div
        className={`network-workspace ${!compact && node ? 'has-selection' : ''}`}
      >
        <div className="network-canvas">
          <svg
            ref={svg}
            viewBox="0 0 900 500"
            role="group"
            aria-label="Observed traffic relationships. Select a node to inspect its connections. Drag the background to pan."
            onPointerDown={(e) => {
              if ((e.target as Element).closest('[data-node]')) return
              drag.current = {
                x: e.clientX,
                y: e.clientY,
                px: pan.x,
                py: pan.y,
              }
              e.currentTarget.setPointerCapture(e.pointerId)
            }}
            onPointerMove={(e) => {
              if (!drag.current || !svg.current) return
              const scale = 900 / svg.current.getBoundingClientRect().width
              setPan({
                x: drag.current.px + (e.clientX - drag.current.x) * scale,
                y: drag.current.py + (e.clientY - drag.current.y) * scale,
              })
            }}
            onPointerUp={() => {
              drag.current = null
            }}
            onPointerCancel={() => {
              drag.current = null
            }}
          >
            <g
              transform={`translate(${450 + pan.x},${250 + pan.y}) scale(${zoom}) translate(-450,-250)`}
            >
              {graph.edges.map((edge) => {
                const a = positions.get(edge.initiator)!,
                  b = positions.get(edge.responder)!
                const highlighted =
                  !node ||
                  edge.initiator === selected ||
                  edge.responder === selected
                const visible =
                  (matches(edge.initiator) || matches(edge.responder)) &&
                  highlighted
                const color = edge.threat_class
                  ? classColor(edge.threat_class)
                  : '#427d91'
                const dx = b.x - a.x,
                  dy = b.y - a.y,
                  distance = Math.max(1, Math.hypot(dx, dy))
                const cx = (a.x + b.x) / 2 - dy * 0.12,
                  cy = (a.y + b.y) / 2 + dx * 0.12
                const endX = b.x - (dx / distance) * 26,
                  endY = b.y - (dy / distance) * 26
                const d =
                  edge.initiator === edge.responder
                    ? `M ${a.x - 15} ${a.y - 15} C ${a.x - 70} ${a.y - 85}, ${a.x + 70} ${a.y - 85}, ${a.x + 15} ${a.y - 15}`
                    : `M ${a.x} ${a.y} Q ${cx} ${cy} ${endX} ${endY}`
                return (
                  <g
                    key={JSON.stringify([edge.initiator, edge.responder])}
                    opacity={visible ? 0.8 : 0.08}
                  >
                    <title>
                      {edge.initiator} → {edge.responder}: {fmtInt(edge.flows)}{' '}
                      flows, {fmtBytes(edge.bytes)}
                      {edge.threat_class ? `, ${edge.threat_class}` : ''}
                    </title>
                    <path
                      d={d}
                      fill="none"
                      stroke={color}
                      strokeWidth={1 + Math.sqrt(edge.bytes / maxBytes) * 3}
                    />
                    {edge.initiator !== edge.responder && (
                      <path
                        d="M-7-3L0 0-7 3"
                        transform={`translate(${endX},${endY}) rotate(${(Math.atan2(endY - cy, endX - cx) * 180) / Math.PI})`}
                        fill="none"
                        stroke={color}
                        strokeWidth="1.5"
                      />
                    )}
                  </g>
                )
              })}
              {graph.nodes.map((asset) => {
                const p = positions.get(asset.id)!,
                  color = NODE_COLOR[asset.scope],
                  active = asset.id === selected
                const isDNS = asset.ports.includes(53)
                return (
                  <g
                    data-node="true"
                    key={asset.id}
                    transform={`translate(${p.x},${p.y})`}
                    role="button"
                    tabIndex={0}
                    aria-label={`${asset.id}, ${asset.scope}, ${asset.flows} flows${isDNS ? ', DNS port observed' : ''}`}
                    aria-pressed={active}
                    className="asset-node"
                    opacity={matches(asset.id) ? 1 : 0.18}
                    onClick={() => setSelected(active ? null : asset.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        setSelected(active ? null : asset.id)
                      }
                    }}
                  >
                    <title>
                      {asset.id} · {asset.scope} · {fmtBytes(asset.bytes)} ·{' '}
                      {asset.threats} threat classifications
                    </title>
                    <circle
                      r={active ? 32 : 27}
                      fill={active ? `${color}20` : '#0c1724'}
                      stroke={color}
                      strokeOpacity={active ? 1 : 0.3}
                      strokeWidth={active ? 2 : 1}
                    />
                    <circle
                      r="21"
                      fill={`${color}15`}
                      stroke={color}
                      strokeWidth="1.5"
                    />
                    {asset.threats > 0 && (
                      <circle
                        cx="19"
                        cy="-18"
                        r="5"
                        fill="var(--dos)"
                        stroke="#0c1724"
                        strokeWidth="2"
                      />
                    )}
                    <g color={color}>
                      {isDNS ? (
                        <>
                          <circle r="10" fill="none" stroke="currentColor" />
                          <path
                            d="M-10 0H10M0-10C-7-4-7 4 0 10M0-10C7-4 7 4 0 10"
                            fill="none"
                            stroke="currentColor"
                          />
                        </>
                      ) : (
                        <path
                          d="M-10-8H10V5H-10ZM-5 10H5M0 5V10"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.5"
                        />
                      )}
                    </g>
                    <IPNodeLabel ip={asset.id} />
                    <text
                      y="60"
                      textAnchor="middle"
                      fill="var(--dim)"
                      fontSize="10"
                    >
                      {isDNS ? 'DNS port · ' : ''}
                      {fmtInt(asset.flows)} flows
                    </text>
                  </g>
                )
              })}
            </g>
          </svg>
          {!graph.nodes.length && (
            <div className="graph-empty">
              <Icon name="network" size={42} />
              <h3>
                {!data && !error
                  ? 'Loading connections…'
                  : threatsOnly
                    ? 'No threat connections in this snapshot'
                    : 'Waiting for observed traffic'}
              </h3>
              <p>Replay a capture or connect a sensor to map your assets.</p>
              <Link to="/replay">Open replay →</Link>
            </div>
          )}
          <div className="graph-controls">
            <button
              aria-label="Zoom out"
              onClick={() => setZoom(Math.max(0.5, zoom - 0.25))}
            >
              −
            </button>
            <span>{Math.round(zoom * 100)}%</span>
            <button
              aria-label="Zoom in"
              onClick={() => setZoom(Math.min(3, zoom + 0.25))}
            >
              +
            </button>
            <button onClick={reset}>Reset view</button>
          </div>
        </div>
        {node && !compact && (
          <aside className="asset-detail">
            <div className="eyebrow">SELECTED ASSET</div>
            <h3 className="mono"><IPLabel ip={node.id} /></h3>
            <span
              className="scope-chip"
              style={{ color: NODE_COLOR[node.scope] }}
            >
              {node.scope} address
            </span>
            <dl>
              <dt>Observed flows</dt>
              <dd>{fmtInt(node.flows)}</dd>
              <dt>Traffic volume</dt>
              <dd>{fmtBytes(node.bytes)}</dd>
              <dt>Threat classifications</dt>
              <dd>{fmtInt(node.threats)}</dd>
              <dt>Connected peers</dt>
              <dd>{[...neighbors].filter((ip) => ip !== node.id).length}</dd>
            </dl>
            <h4>Observed endpoint ports</h4>
            <div className="port-chips">
              {node.ports.slice(0, 18).map((p) => (
                <span key={p}>
                  {p === 53
                    ? '53 · DNS'
                    : p === 443
                      ? '443 · HTTPS'
                      : p === 80
                        ? '80 · HTTP'
                        : p}
                </span>
              ))}
              {!node.ports.length && (
                <span>None in the retained flow sample</span>
              )}
            </div>
            <p className="foot">
              Port labels suggest services; they do not verify applications. DNS
              names are not reported.
            </p>
            <label className="check-label">
              <input
                type="checkbox"
                checked={focus}
                onChange={(e) => setFocus(e.target.checked)}
              />
              Focus neighbors
            </label>
            <Link
              className="primary-link"
              to={`/investigate?host=${encodeURIComponent(node.id)}`}
            >
              Investigate asset →
            </Link>
          </aside>
        )}
      </div>
      {compact && node && (
        <div className="viz-notice">
          <b className="mono">{node.id}</b> · {fmtInt(node.flows)} flows ·{' '}
          {fmtBytes(node.bytes)} ·{' '}
          <Link to={`/investigate?host=${encodeURIComponent(node.id)}`}>
            Investigate →
          </Link>
        </div>
      )}
      <div className="network-legend">
        <span>
          <i style={{ background: NODE_COLOR.private }} />
          Private address
        </span>
        <span>
          <i style={{ background: NODE_COLOR.public }} />
          Public address
        </span>
        <span>
          <i style={{ background: NODE_COLOR.special }} />
          Special address
        </span>
        <span>
          <i style={{ background: 'var(--dos)' }} />
          Threat observed
        </span>
        <span className="spacer" />
        <span>{graph.edges.length} connections · line width = bytes</span>
      </div>
      <div className="viz-caption">
        Observed initiator → responder relationships; network hops and ownership
        are not inferred.{' '}
        {data?.partial &&
          'Partial history: some pairs were evicted or the scan was capped. '}
        {data?.truncated && 'Showing top conversations by volume. '}
        {graph.omitted > 0 &&
          `${graph.omitted} additional pairs hidden by the asset limit. `}
        {records.error && 'Port details unavailable. '}
        {updated && `Updated ${updated.toLocaleTimeString()}.`}
      </div>
    </section>
  )
}
