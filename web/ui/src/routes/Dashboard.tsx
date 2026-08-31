import { useStream } from '../api/stream'
import { Sparkline } from '../components/Sparkline'
import { classColor } from '../lib/classes'
import { fmtInt } from '../lib/format'

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

function NeedsApi({ title, note }: { title: string; note: string }) {
  return (
    <div className="card needs-api">
      <h3>{title}</h3>
      <div className="big">—</div>
      <div className="note">needs API · {note}</div>
    </div>
  )
}

export function Dashboard() {
  const { status, rollup, connected } = useStream()

  const classMax = rollup.classCounts.reduce((m, [, n]) => Math.max(m, n), 0)
  const protoMax = rollup.protoCounts.reduce((m, [, n]) => Math.max(m, n), 0)
  const talkerMax = rollup.topTalkers.reduce((m, t) => Math.max(m, t.count), 0)
  const portMax = rollup.topPorts.reduce((m, t) => Math.max(m, t.count), 0)
  const windowMin = Math.round(rollup.windowSec / 60)

  return (
    <div>
      <div className="page-h">
        <h1>Dashboard</h1>
        <span className="sub">
          live counters from <code>/api/v1/status</code> plus client-side aggregation of the
          classification stream
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
          <div className="foot">registry, metrics and lineage (§19.12) arrive in Phase 2</div>
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

        <NeedsApi title="Active flows" note="live flow-table size is not on /api/v1/status yet" />
        <NeedsApi title="Packets / sec" note="daemon-wide capture metrics land with Phase 3" />
        <NeedsApi title="Throughput" note="bytes/sec needs the capture-source API (Phase 3, §19.14)" />
        <NeedsApi title="Anomaly rate" note="anomaly model is Phase 7" />
        <NeedsApi title="Recent detections" note="needs /api/v1/detections (Phase 5)" />
        <NeedsApi title="Sensor health" note="distributed sensors are Phase 6 (§19.15)" />
        <NeedsApi title="Inference latency p50/p95/p99" note="needs a performance API (§19.16)" />
      </div>
    </div>
  )
}
