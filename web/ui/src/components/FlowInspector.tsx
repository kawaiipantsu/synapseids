import { useEffect, useState } from 'react'

import { getClassSchema, getFeatureSchema, getFlow } from '../api/client'
import type { Classification, ClassSchema, FeatureSchema, FlowRecord } from '../api/types'
import { classColor } from '../lib/classes'
import {
  endpoint,
  fmtBytes,
  fmtDateTime,
  fmtDuration,
  fmtInt,
  fmtNum,
  fmtPct,
} from '../lib/format'

interface Props {
  cls: Classification
  onClose: () => void
}

function featIndex(schema: FeatureSchema | null, name: string): number {
  return schema?.features.find((f) => f.name === name)?.index ?? -1
}

function featVal(flow: FlowRecord | null, schema: FeatureSchema | null, name: string): number | null {
  const i = featIndex(schema, name)
  if (i < 0 || !flow) return null
  const v = flow.features.values[i]
  return typeof v === 'number' ? v : null
}

const TCP_FEATURES = [
  'tcp_syn_count',
  'tcp_ack_count',
  'tcp_fin_count',
  'tcp_rst_count',
  'tcp_psh_count',
  'tcp_urg_count',
  'initial_tcp_window',
  'average_tcp_window',
]

export function FlowInspector({ cls, onClose }: Props) {
  const [flow, setFlow] = useState<FlowRecord | null>(null)
  const [fSchema, setFSchema] = useState<FeatureSchema | null>(null)
  const [cSchema, setCSchema] = useState<ClassSchema | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    setLoading(true)
    setError(null)
    Promise.all([getFlow(cls.flow_id), getFeatureSchema(), getClassSchema()])
      .then(([f, fs, cs]) => {
        if (!alive) return
        setFlow(f)
        setFSchema(fs)
        setCSchema(cs)
      })
      .catch((e: unknown) => {
        if (alive) setError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [cls.flow_id])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const r = cls.result
  const primary = r.models.find((m) => m.role === 'primary') ?? r.models[0]
  const isTCP = /tcp/i.test(cls.proto)
  const classNames =
    cSchema?.classes.map((c) => c.name) ??
    primary?.scores.map((_, i) => `class_${i}`) ??
    []

  const total =
    flow != null ? flow.fwd_packets + flow.bwd_packets : 0
  const totalBytes = flow != null ? flow.fwd_bytes + flow.bwd_bytes : 0

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`Flow ${cls.flow_id}`}>
        <header>
          <span className="id">#{cls.flow_id}</span>
          <span className="mono">
            {endpoint(cls.initiator_ip, cls.initiator_port)} → {endpoint(cls.responder_ip, cls.responder_port)}
          </span>
          <span className="dim">{cls.proto}</span>
          <span className="spacer" />
          <button onClick={onClose} autoFocus aria-label="Close inspector">
            ✕
          </button>
        </header>

        <div className="body">
          {loading ? <p className="dim">loading flow {cls.flow_id}…</p> : null}
          {error ? <p className="err">could not load flow: {error}</p> : null}

          {/* ---- verdict summary ---- */}
          <div className="sect">
            <h4>Classification</h4>
            <p style={{ margin: '0 0 8px' }}>
              <span className="pill" style={{ background: classColor(r.class) }}>
                {r.class.toUpperCase()}
              </span>{' '}
              <b>{fmtPct(r.score)}</b>{' '}
              <span className="dim">
                · model {primary?.model_id ?? '—'} ({primary?.role ?? '—'})
              </span>{' '}
              {r.disagreement ? <span className="badge-dis">model disagreement</span> : null}
            </p>

            {primary ? (
              <div>
                <div className="dim" style={{ margin: '4px 0' }}>
                  full class-probability vector (traffic-classes-v1)
                </div>
                {primary.scores.map((p, i) => (
                  <div className="probrow" key={i}>
                    <span>{classNames[i] ?? `class_${i}`}</span>
                    <span className="track">
                      <span
                        className="fill"
                        style={{ width: `${Math.max(1, p * 100)}%`, background: classColor(classNames[i] ?? '') }}
                      />
                    </span>
                    <span className="p">{fmtPct(p, 1)}</span>
                  </div>
                ))}
              </div>
            ) : null}

            <div style={{ marginTop: 10 }}>
              <div className="dim" style={{ margin: '4px 0' }}>
                per-model outputs
              </div>
              <table className="mini">
                <thead>
                  <tr>
                    <th>model</th>
                    <th>role</th>
                    <th>class</th>
                    <th className="num">score</th>
                  </tr>
                </thead>
                <tbody>
                  {r.models.map((m) => (
                    <tr key={m.model_id + m.role}>
                      <td className="mono">{m.model_id}</td>
                      <td>{m.role}</td>
                      <td>
                        <span className="pill" style={{ background: classColor(m.class) }}>
                          {m.class}
                        </span>
                      </td>
                      <td className="num">{fmtPct(m.score)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="dim" style={{ marginTop: 4 }}>
                disagreement flag: <b>{r.disagreement ? 'yes' : 'no'}</b> ({r.models.length}{' '}
                model{r.models.length === 1 ? '' : 's'} loaded)
              </p>
            </div>
          </div>

          {/* ---- tuple & direction ---- */}
          <div className="sect">
            <h4>5-tuple &amp; direction</h4>
            <dl className="kv">
              <dt>initiator</dt>
              <dd className="mono">{endpoint(cls.initiator_ip, cls.initiator_port)}</dd>
              <dt>responder</dt>
              <dd className="mono">{endpoint(cls.responder_ip, cls.responder_port)}</dd>
              <dt>protocol</dt>
              <dd>{cls.proto}</dd>
              <dt>direction</dt>
              <dd>initiator → responder</dd>
              <dt>sensor</dt>
              <dd>{cls.sensor || '—'}</dd>
              <dt>close reason</dt>
              <dd>{flow?.close_reason ?? '—'}</dd>
              <dt>snapshot index</dt>
              <dd>{flow ? fmtInt(flow.snapshot_index) : '—'}</dd>
            </dl>
          </div>

          {/* ---- timing ---- */}
          <div className="sect">
            <h4>Timing</h4>
            <dl className="kv">
              <dt>first seen</dt>
              <dd className="mono">{flow ? fmtDateTime(flow.first_seen) : '—'}</dd>
              <dt>last seen</dt>
              <dd className="mono">{flow ? fmtDateTime(flow.last_seen) : '—'}</dd>
              <dt>duration</dt>
              <dd>{flow ? fmtDuration(flow.duration_sec) : '—'}</dd>
            </dl>
          </div>

          {/* ---- packet / byte stats ---- */}
          <div className="sect">
            <h4>Packet &amp; byte statistics</h4>
            <dl className="kv">
              <dt>packets fwd / bwd</dt>
              <dd className="mono">
                {flow ? `${fmtInt(flow.fwd_packets)} / ${fmtInt(flow.bwd_packets)}` : '—'}{' '}
                <span className="dim">(total {fmtInt(total)})</span>
              </dd>
              <dt>bytes fwd / bwd</dt>
              <dd className="mono">
                {flow ? `${fmtBytes(flow.fwd_bytes)} / ${fmtBytes(flow.bwd_bytes)}` : '—'}{' '}
                <span className="dim">(total {fmtBytes(totalBytes)})</span>
              </dd>
              <dt>packet size mean</dt>
              <dd className="mono">{fmtNum(featVal(flow, fSchema, 'packet_size_mean') ?? 0, 1)} B</dd>
              <dt>avg payload length</dt>
              <dd className="mono">
                {fmtNum(featVal(flow, fSchema, 'average_payload_length') ?? 0, 1)} B
              </dd>
            </dl>
          </div>

          {/* ---- tcp metadata ---- */}
          {isTCP ? (
            <div className="sect">
              <h4>TCP metadata</h4>
              <table className="mini">
                <tbody>
                  {TCP_FEATURES.map((name) => {
                    const v = featVal(flow, fSchema, name)
                    return (
                      <tr key={name}>
                        <th>{name}</th>
                        <td className="num mono">{v == null ? '—' : fmtNum(v, 2)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : null}

          {/* ---- raw feature vector ---- */}
          <div className="sect">
            <h4>flow-features-v1 — all raw values ({flow?.features.values.length ?? 0})</h4>
            <table className="mini">
              <thead>
                <tr>
                  <th>#</th>
                  <th>feature</th>
                  <th className="num">value</th>
                  <th>unit</th>
                </tr>
              </thead>
              <tbody>
                {(fSchema?.features ?? []).map((f) => {
                  const v = flow?.features.values[f.index]
                  return (
                    <tr key={f.index}>
                      <td className="dim">{f.index}</td>
                      <td>
                        {f.name}
                        <div className="feat-calc">{f.calc}</div>
                      </td>
                      <td className="num mono">{typeof v === 'number' ? fmtNum(v, 4) : '—'}</td>
                      <td className="dim">{f.unit}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* ---- phase 2 stubs ---- */}
          <div className="sect stub">
            <h4>
              Normalized model inputs <span className="tag">Phase 2</span>
            </h4>
            <p className="dim">
              A trained model applies its bundle’s normalizer.json; the Phase-1 heuristic scores raw
              values, so there is no normalized vector to show yet.
            </p>
          </div>
          <div className="sect stub">
            <h4>
              Flow snapshot history <span className="tag">Phase 2</span>
            </h4>
            <p className="dim">
              Periodic snapshots of a long-lived flow. The API exposes only the latest record per id
              today; snapshot history needs the SQLite store.
            </p>
          </div>
          <div className="sect stub">
            <h4>
              Human review status <span className="tag">Phase 2</span>
            </h4>
            <p className="dim">Part of the Phase-5 human-review loop; no review state is persisted yet.</p>
          </div>
          <div className="sect stub">
            <h4>
              Explanation — top feature contributions <span className="tag">Phase 2</span>
            </h4>
            <p className="dim">
              Deviation-from-baseline and per-feature attribution arrive with trained models and a
              baseline distribution.
            </p>
          </div>
        </div>
      </aside>
    </>
  )
}
