import { useState, type ReactNode } from 'react'
import { useStream } from '../api/stream'
import { classColor } from '../lib/classes'
import { fmtBytes, fmtInt, fmtNum } from '../lib/format'
import { Link } from '../lib/hashRouter'

function Trend({
  values,
  color,
  label,
  unit,
}: {
  values: number[]
  color: string
  label: string
  unit: string
}) {
  const maximum = Math.max(1, ...values)
  const points = values
    .map(
      (n, i) =>
        `${48 + (i / Math.max(1, values.length - 1)) * 712},${155 - (n / maximum) * 130}`,
    )
    .join(' ')
  const [index, setIndex] = useState<number | null>(null)
  const shown =
    index == null ? values.length - 1 : Math.min(index, values.length - 1)
  return (
    <div className="trend-chart">
      <div className="trend-readout">
        <span>{label}</span>
        <b>
          {shown >= 0 ? fmtNum(values[shown]!, 1) : '—'} <small>{unit}</small>
        </b>
      </div>
      <svg
        viewBox="0 0 780 190"
        role="img"
        aria-label={`${label}, last ${values.length} one-second samples`}
        onPointerMove={(e) => {
          const bounds = e.currentTarget.getBoundingClientRect()
          setIndex(
            Math.max(
              0,
              Math.min(
                values.length - 1,
                Math.round(
                  ((((e.clientX - bounds.left) / bounds.width) * 780 - 48) /
                    712) *
                    (values.length - 1),
                ),
              ),
            ),
          )
        }}
        onPointerLeave={() => setIndex(null)}
      >
        {[0, 0.5, 1].map((v) => (
          <g key={v}>
            <line
              x1="48"
              x2="760"
              y1={155 - v * 130}
              y2={155 - v * 130}
              stroke="var(--edge)"
              strokeDasharray="3 5"
            />
            <text
              x="40"
              y={159 - v * 130}
              textAnchor="end"
              fill="var(--dim)"
              fontSize="10"
            >
              {fmtNum(maximum * v, maximum < 2 ? 1 : 0)}
            </text>
          </g>
        ))}
        {values.length > 1 && (
          <>
            <polygon
              points={`48,155 ${points} 760,155`}
              fill={color}
              opacity=".08"
            />
            <polyline
              points={points}
              fill="none"
              stroke={color}
              strokeWidth="2"
              strokeLinejoin="round"
            />
          </>
        )}
        {index != null && shown >= 0 && (
          <g>
            <line
              x1={48 + (shown / Math.max(1, values.length - 1)) * 712}
              x2={48 + (shown / Math.max(1, values.length - 1)) * 712}
              y1="15"
              y2="155"
              stroke={color}
              opacity=".4"
            />
            <circle
              cx={48 + (shown / Math.max(1, values.length - 1)) * 712}
              cy={155 - (values[shown]! / maximum) * 130}
              r="4"
              fill={color}
            />
          </g>
        )}
        <text x="48" y="181" fill="var(--dim)" fontSize="10">
          {Math.max(0, values.length - 1)} seconds ago
        </text>
        <text x="760" y="181" textAnchor="end" fill="var(--dim)" fontSize="10">
          Now
        </text>
      </svg>
    </div>
  )
}

export function TrafficAnalytics({ children }: { children?: ReactNode }) {
  const { status, rollup, ingest, connected } = useStream()
  const [metric, setMetric] = useState<'packets' | 'classifications' | 'bytes'>(
    'packets',
  )
  const total = rollup.classCounts.reduce((n, [, count]) => n + count, 0)
  const threat = rollup.classCounts.reduce(
    (n, [name, count]) => n + (name !== 'normal' ? count : 0),
    0,
  )
  let offset = 0
  const slices = rollup.classCounts.map(([name, count]) => {
    const start = offset
    offset += total ? (count / total) * 100 : 0
    return `${classColor(name)} ${start}% ${offset}%`
  })
  const chart =
    metric === 'packets'
      ? {
          values: ingest.pktPerSec,
          color: '#51d8c6',
          label: 'Packet throughput',
          unit: 'packets/s',
        }
      : metric === 'bytes'
        ? {
            values: ingest.bytesPerSec,
            color: '#a997ff',
            label: 'Ingest bandwidth',
            unit: 'bytes/s',
          }
        : {
            values: rollup.clsPerSec,
            color: '#61a5fa',
            label: 'Classification throughput',
            unit: 'results/s',
          }
  return (
    <>
      <div className="overview-metrics">
        <div>
          <span>CAPTURE THROUGHPUT</span>
          <b>
            {ingest.state === 'ok' && ingest.samples > 1
              ? fmtNum(ingest.pktRate, 1)
              : '—'}
            <small> pkt/s</small>
          </b>
          <em>
            {ingest.state === 'error'
              ? 'Capture telemetry unavailable'
              : `${fmtBytes(ingest.byteRate)}/s · ${ingest.sourcesRunning} active sources`}
          </em>
        </div>
        <div>
          <span>ACTIVE FLOWS</span>
          <b>
            {status.hasFlowTable && !status.error
              ? fmtInt(status.activeFlows)
              : '—'}
          </b>
          <em>{fmtInt(status.flows)} stored flow records</em>
        </div>
        <div>
          <span>THREAT CLASSIFICATIONS</span>
          <b className={threat ? 'threat-text' : ''}>{fmtInt(threat)}</b>
          <em>Non-normal results · since page load</em>
        </div>
        <div>
          <span>CAPTURE DROPS</span>
          <b className={ingest.drops ? 'threat-text' : ''}>
            {ingest.state === 'ok' ? fmtInt(ingest.drops) : '—'}
          </b>
          <em>Capture + sensor counters · not firewall blocks</em>
        </div>
      </div>
      {children}
      <div className="analytics-grid">
        <section className="viz-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">LIVE TELEMETRY</div>
              <h2>Traffic pulse</h2>
            </div>
            <select
              aria-label="Traffic chart metric"
              value={metric}
              onChange={(e) => setMetric(e.target.value as typeof metric)}
            >
              <option value="packets">Packets / sec</option>
              <option value="bytes">Bytes / sec</option>
              <option value="classifications">Classifications / sec</option>
            </select>
          </div>
          <Trend {...chart} />
          <div className="viz-caption">
            {connected
              ? 'Live stream connected'
              : 'Stream disconnected; classification history may be incomplete'}
            .{' '}
            {ingest.state === 'error'
              ? 'Capture telemetry unavailable; last samples shown.'
              : 'Up to 90 seconds of session history.'}{' '}
            Replay does not report byte counts.
          </div>
        </section>
        <section className="viz-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">CLASSIFIER RESULTS</div>
              <h2>Traffic composition</h2>
            </div>
            <Link to="/inference">Inspect →</Link>
          </div>
          <div className="composition">
            <div
              className="donut"
              role="img"
              aria-label={`${total} classifications since page load; ${threat} non-normal`}
              style={{
                background: total
                  ? `conic-gradient(${slices.join(',')})`
                  : 'var(--edge)',
              }}
            >
              <div>
                <b>{fmtInt(total)}</b>
                <span>results</span>
              </div>
            </div>
            <div className="composition-legend">
              {rollup.classCounts.length ? (
                rollup.classCounts.map(([name, count]) => (
                  <div key={name}>
                    <i style={{ background: classColor(name) }} />
                    <span>{name.replace(/_/g, ' ')}</span>
                    <b>{fmtInt(count)}</b>
                  </div>
                ))
              ) : (
                <p className="dim">Waiting for classification events.</p>
              )}
            </div>
          </div>
          <div className="viz-caption">
            Session totals from the live stream. A classification is not a
            firewall access decision.
          </div>
        </section>
      </div>
      <div className="pipeline-strip">
        <span>
          <b>01</b> Capture
          <small>{fmtInt(ingest.packets)} reported packets</small>
        </span>
        <i>→</i>
        <span>
          <b>02</b> Assemble flows
          <small>
            {status.hasFlowTable ? fmtInt(status.flowsClosed) : '—'} closed
          </small>
        </span>
        <i>→</i>
        <span>
          <b>03</b> Classify<small>{status.models.length} loaded models</small>
        </span>
        <i>→</i>
        <Link to="/detections">
          <b>04</b> Investigate<small>Detections & human review ↗</small>
        </Link>
      </div>
      <div className="coverage-strip">
        <span>
          <i className="live-indicator" />
          Passive IDS observation
        </span>
        <span>
          Firewall allows / blocks: <b>not reported</b>
        </span>
        <span>
          Dropped event deliveries:{' '}
          <b>
            {status.raw?.events?.dropped == null
              ? '—'
              : fmtInt(status.raw.events.dropped)}
          </b>
        </span>
        <Link to="/sensors">Sensor health ↗</Link>
      </div>
    </>
  )
}
