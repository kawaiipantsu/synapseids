import { useEffect, useState } from 'react'

import {
  getClassSchema,
  getFeatureSchema,
  getFlow,
  getFlowExplain,
  getFlowSnapshots,
  getReview,
} from '../api/client'
import type { Classification, ClassSchema, FeatureSchema, FlowRecord, Review } from '../api/types'
import type { FlowExplain, FlowSnapshots } from '../api/types'
import { classColor } from '../lib/classes'
import { IssueLink } from './IssueLink'
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

  // Human review status (§19.3, §16). Fetched separately from the flow so a
  // review-store outage never blanks the rest of the drawer; a flow nobody has
  // reviewed resolves to null, which is the common case and not an error.
  const [review, setReview] = useState<Review | null>(null)
  const [reviewErr, setReviewErr] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    setReview(null)
    setReviewErr(null)
    getReview(cls.flow_id)
      .then((r) => {
        if (alive) setReview(r)
      })
      .catch((e: unknown) => {
        if (alive) setReviewErr(e instanceof Error ? e.message : String(e))
      })
    return () => {
      alive = false
    }
  }, [cls.flow_id])

  // Normalized inputs, the explanation and the snapshot history (§19.3, #38).
  // Fetched separately from the flow record, and separately from each other, so
  // one unavailable panel never blanks the rest of the drawer — the same posture
  // the review fetch above takes.
  const [explain, setExplain] = useState<FlowExplain | null>(null)
  const [explainErr, setExplainErr] = useState<string | null>(null)
  const [snaps, setSnaps] = useState<FlowSnapshots | null>(null)
  const [snapsErr, setSnapsErr] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    setExplain(null)
    setExplainErr(null)
    setSnaps(null)
    setSnapsErr(null)
    getFlowExplain(cls.flow_id)
      .then((e) => {
        if (alive) setExplain(e)
      })
      .catch((e: unknown) => {
        if (alive) setExplainErr(e instanceof Error ? e.message : String(e))
      })
    getFlowSnapshots(cls.flow_id)
      .then((s) => {
        if (alive) setSnaps(s)
      })
      .catch((e: unknown) => {
        if (alive) setSnapsErr(e instanceof Error ? e.message : String(e))
      })
    return () => {
      alive = false
    }
  }, [cls.flow_id])

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

          {/* ---- normalized model inputs (§19.3; issue #38) ---- */}
          <NormalizedInputs explain={explain} err={explainErr} />

          {/* ---- snapshot history (§19.3; issue #38) ---- */}
          <SnapshotHistory snaps={snaps} err={snapsErr} />
          {/* ---- human review status (§19.3, §16; issue #42) ---- */}
          <div className="sect">
            <h4>Human review status</h4>
            {reviewErr ? (
              <p className="dim">review status unavailable — {reviewErr}</p>
            ) : review == null ? (
              <p className="dim">
                not reviewed. Confirm or correct this verdict in{' '}
                <a href="#/review">LIVE ▸ Review</a>.
              </p>
            ) : (
              <dl className="kv">
                <dt>state</dt>
                <dd>
                  <span className={`rv-state rv-${review.state}`}>
                    {review.state.replace('_', ' ')}
                  </span>
                </dd>
                <dt>human label</dt>
                <dd>
                  {review.effective_label ? (
                    <span className="pill" style={{ background: classColor(review.effective_label) }}>
                      {review.effective_label.toUpperCase()}
                    </span>
                  ) : (
                    <span className="dim">— (this state asserts no class)</span>
                  )}
                </dd>
                {/* The §16 invariant, made visible: the prediction as it was at
                    review time, shown alongside and never replaced. */}
                <dt>model said (frozen)</dt>
                <dd>
                  <span className="pill" style={{ background: classColor(review.predicted_class) }}>
                    {review.predicted_class.toUpperCase()}
                  </span>{' '}
                  <b>{fmtPct(review.predicted_score)}</b>{' '}
                  <span className="dim">· {review.model_id || '—'}</span>
                </dd>
                <dt>note</dt>
                <dd>{review.note || <span className="dim">—</span>}</dd>
                <dt>reviewer</dt>
                <dd>{review.reviewer}</dd>
                <dt>revisions</dt>
                <dd title={review.history.map((h) => `${h.ts}: ${h.state}`).join('\n')}>
                  {fmtInt(review.history.length)}
                </dd>
                <dt>updated</dt>
                <dd className="mono">{fmtDateTime(review.updated_at)}</dd>
              </dl>
            )}
          </div>
          {/* ---- why this verdict (§19.3; issue #38) ---- */}
          <ExplanationPanel explain={explain} err={explainErr} />

          {/* ---- anomaly score: issue #47, a labelled stub with no number ---- */}
          <AnomalyStub explain={explain} />
        </div>
      </aside>
    </>
  )
}

// ===========================================================================
// Flow Inspector §19.3 completions — issue #38, ADR 0025
// ---------------------------------------------------------------------------
// Normalized model inputs, snapshot history and the explanation panel. Kept as
// self-contained components at the end of the file so the block has its own
// merge surface, and so the drawer body above reads as a list of sections.
//
// The drawer is already dense, so the two long tables (48 normalized features,
// and a snapshot list that can run to 64 rows) are collapsed by default behind
// <details>. The verdict rationale is NOT collapsed — it is the reason an
// operator opened the drawer.
//
// What these components must never do:
//   * render a baseline column, or any "expected range". §19.3's example shows
//     one; this build has no training baselines (issues #47 / #63) and inventing
//     a range would turn an absent check into an apparent clean bill of health.
//   * render an anomaly number. Issue #47 as well.
//   * render a per-feature contribution for a trained model. The API returns
//     kind:'unavailable' there, and this panel says so in words instead of
//     drawing bars from a proxy.
// ===========================================================================

/**
 * A section that says why it has nothing to show.
 *
 * `tag` is the tracking-issue citation, not a development phase: a phase number
 * stops being checkable as soon as its epic closes (issue #118).
 */
function UnavailableSect({
  title,
  tag,
  children,
}: {
  title: string
  tag?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="sect stub">
      <h4>
        {title} {tag ? <span className="tag">{tag}</span> : null}
      </h4>
      <p className="dim">{children}</p>
    </div>
  )
}

/** Backend-authored notes about retention gaps and caps. */
function Notes({ notes }: { notes?: string[] }) {
  if (notes == null || notes.length === 0) return null
  return (
    <ul className="fi-notes">
      {notes.map((n, i) => (
        <li key={i}>{n}</li>
      ))}
    </ul>
  )
}

/**
 * Normalized model inputs (§19.3), presented per model.
 *
 * Normalization is a per-model concern in this codebase: the heuristic reads raw
 * values and a trained model applies its own bundle's normalizer.json. So this
 * shows, for each model that produced the verdict, what that model actually saw
 * — and for the heuristic it says "raw" in words rather than drawing an identity
 * transformation that would imply a step which does not happen.
 */
function NormalizedInputs({ explain, err }: { explain: FlowExplain | null; err: string | null }) {
  if (err != null) {
    return (
      <UnavailableSect title="Normalized model inputs">
        could not load model inputs — {err}
      </UnavailableSect>
    )
  }
  if (explain == null) {
    return <UnavailableSect title="Normalized model inputs">loading…</UnavailableSect>
  }
  if (!explain.verdict_available || explain.models.length === 0) {
    return (
      <UnavailableSect title="Normalized model inputs">
        No stored verdict for this flow, so there is no record of which models scored it.
        <Notes notes={explain.notes} />
      </UnavailableSect>
    )
  }

  return (
    <div className="sect">
      <h4>Normalized model inputs</h4>
      {explain.models.map((m) => (
        <div className="fi-model" key={m.model_id}>
          <div className="fi-model-head">
            <span className="mono">{m.model_id}</span>
            <span className="dim"> · {m.role}</span>
            <span className={`fi-kind fi-kind-${m.input.kind}`}>
              {m.input.kind === 'raw'
                ? 'reads raw values'
                : m.input.kind === 'normalized'
                  ? `normalizer: ${m.input.normalizer_id ?? '—'}`
                  : 'not resolvable'}
            </span>
          </div>
          <p className="dim">{m.input.note}</p>

          {/* Only a model that really transforms its input gets a table. */}
          {m.input.features != null && m.input.features.length > 0 ? (
            <details>
              <summary>
                raw → normalized, all {m.input.features.length} features
              </summary>
              <table className="mini">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>feature</th>
                    <th className="num">raw</th>
                    <th className="num">normalized</th>
                    <th>unit</th>
                  </tr>
                </thead>
                <tbody>
                  {m.input.features.map((f) => (
                    <tr key={f.index}>
                      <td className="dim">{f.index}</td>
                      <td>{f.name}</td>
                      <td className="num mono">{fmtNum(f.raw, 4)}</td>
                      <td className="num mono">{fmtNum(f.normalized, 4)}</td>
                      <td className="dim">{f.unit}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          ) : null}
        </div>
      ))}
      <Notes notes={explain.notes} />
    </div>
  )
}

/**
 * Snapshot history (§19.3).
 *
 * A long-lived flow emits a snapshot record every snapshot_interval and then a
 * terminal record; the investigative value is watching the counters and the
 * verdict move between them. Counters are cumulative, which the header states
 * so nobody reads a row as per-interval traffic.
 */
function SnapshotHistory({ snaps, err }: { snaps: FlowSnapshots | null; err: string | null }) {
  if (err != null) {
    return (
      <UnavailableSect title="Flow snapshot history">
        could not load snapshot history — {err}
      </UnavailableSect>
    )
  }
  if (snaps == null) {
    return <UnavailableSect title="Flow snapshot history">loading…</UnavailableSect>
  }

  // The common case: a short flow that only ever produced its terminal record.
  // That is not a gap, so it must not read like one.
  if (!snaps.snapshotting) {
    return (
      <div className="sect">
        <h4>Flow snapshot history</h4>
        <p className="dim">
          This flow closed within one snapshot interval, so it produced a single record and has no
          intermediate history. Only a flow still open at a snapshot interval emits snapshots.
        </p>
      </div>
    )
  }

  return (
    <div className="sect">
      <h4>
        Flow snapshot history <span className="dim">({snaps.retained} retained)</span>
        {snaps.truncated ? <span className="tag">truncated</span> : null}
      </h4>
      <p className="dim">
        Cumulative counters as of each version’s <code>last_seen</code>, oldest first — not
        per-interval traffic. History is capped at {snaps.cap} versions per flow.
      </p>
      <details open={snaps.versions.length <= 12}>
        <summary>{snaps.versions.length} versions</summary>
        <table className="mini">
          <thead>
            <tr>
              <th>#</th>
              <th>last seen</th>
              <th className="num">dur</th>
              <th className="num">pkts</th>
              <th className="num">bytes</th>
              <th>verdict</th>
            </tr>
          </thead>
          <tbody>
            {snaps.versions.map((v, i) => (
              <tr key={i} className={v.terminal ? 'fi-terminal' : undefined}>
                <td className="dim">
                  {v.snapshot_index}
                  {v.terminal ? <span className="fi-close">{v.close_reason}</span> : null}
                </td>
                <td className="mono">{fmtDateTime(v.last_seen)}</td>
                <td className="num mono">{fmtDuration(v.duration_sec)}</td>
                <td className="num mono">{fmtInt(v.fwd_packets + v.bwd_packets)}</td>
                <td className="num mono">{fmtBytes(v.fwd_bytes + v.bwd_bytes)}</td>
                <td>
                  {v.verdict != null ? (
                    <>
                      <span
                        className="pill"
                        style={{ background: classColor(v.verdict.class) }}
                      >
                        {v.verdict.class.toUpperCase()}
                      </span>{' '}
                      <b>{fmtPct(v.verdict.score)}</b>
                    </>
                  ) : (
                    <span className="dim">not retained</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
      <Notes notes={snaps.notes} />
    </div>
  )
}

/**
 * The explanation panel (§19.3).
 *
 * For the rule-based heuristic this is an exact account of the decision: the
 * rules that fired, the feature values they compared, and the pre-softmax class
 * weights those produced. That turns "SCAN 99.3%" into "because tcp_syn_count=1,
 * packets_backward=0, flow_duration=0.001s".
 *
 * For a trained model the API returns kind:'unavailable' and this renders the
 * reason as prose. No bars, no percentages, no proxy.
 */
function ExplanationPanel({ explain, err }: { explain: FlowExplain | null; err: string | null }) {
  if (err != null) {
    return (
      <UnavailableSect title="Explanation — why this verdict">
        could not load the explanation — {err}
      </UnavailableSect>
    )
  }
  if (explain == null) {
    return <UnavailableSect title="Explanation — why this verdict">loading…</UnavailableSect>
  }
  if (!explain.verdict_available || explain.models.length === 0) {
    return (
      <UnavailableSect title="Explanation — why this verdict">
        No stored verdict for this flow, so there is nothing to explain.
        <Notes notes={explain.notes} />
      </UnavailableSect>
    )
  }

  return (
    <div className="sect">
      <h4>Explanation — why this verdict</h4>

      {explain.models.map((m) => (
        <div className="fi-model" key={m.model_id}>
          <div className="fi-model-head">
            <span className="mono">{m.model_id}</span>
            <span className="dim"> · {m.role} · </span>
            <span className="pill" style={{ background: classColor(m.class) }}>
              {m.class.toUpperCase()}
            </span>{' '}
            <b>{fmtPct(m.score)}</b>
          </div>

          {m.explanation.kind === 'rules' ? (
            // The daemon always sends a list, never null (see
            // inference.Explain) — the fallback is belt-and-braces for a dev
            // proxy pointed at an older build.
            (m.explanation.rules ?? []).length > 0 ? (
              <>
                <ul className="fi-rules">
                  {(m.explanation.rules ?? []).map((r) => (
                    <li key={r.rule}>
                      <div className="fi-rule-head">
                        <span className="fi-rule-id mono">{r.rule}</span>
                        <span className="pill" style={{ background: classColor(r.class) }}>
                          {r.class.toUpperCase()}
                        </span>
                      </div>
                      <div className="fi-rule-detail">{r.detail}</div>
                      <div className="fi-rule-feats">
                        {r.features.map((f) => (
                          <span className="fi-feat" key={f.name}>
                            <span className="mono">{f.name}</span>
                            <b>{fmtNum(f.value, 4)}</b>
                            {f.unit ? <span className="dim">{f.unit}</span> : null}
                          </span>
                        ))}
                      </div>
                    </li>
                  ))}
                </ul>

                {m.explanation.class_weights != null &&
                m.explanation.class_weights.length > 0 ? (
                  <details>
                    <summary>pre-softmax class weights</summary>
                    <table className="mini">
                      <thead>
                        <tr>
                          <th>class</th>
                          <th className="num">weight</th>
                        </tr>
                      </thead>
                      <tbody>
                        {m.explanation.class_weights.map((cw) => (
                          <tr key={cw.class_id}>
                            <td>{cw.class}</td>
                            <td className="num mono">{fmtNum(cw.weight, 3)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </details>
                ) : null}
              </>
            ) : (
              <p className="dim fi-norules">
                <b>No rule fired.</b> This model classifies by explicit rules over named
                flow-features-v1 values, so the verdict is its standing{' '}
                <code>normal</code> prior (weight {m.explanation.normal_prior ?? '—'}) rather than a
                positive finding.
              </p>
            )
          ) : null}

          <p className="dim fi-claim">{m.explanation.note}</p>
        </div>
      ))}

      {/* Where §19.3's example puts a "Baseline" column. There isn't one. */}
      <p className="dim fi-claim">
        <b>No baseline comparison.</b> {explain.baseline.note}
      </p>
      <Notes notes={explain.notes} />
    </div>
  )
}

/** Anomaly score (§19.3) — issue #47. A labelled gap, never a number. */
function AnomalyStub({ explain }: { explain: FlowExplain | null }) {
  return (
    <UnavailableSect title="Anomaly score" tag={<IssueLink n={47} />}>
      {explain?.anomaly.note ?? (
        <>
          Not available in this build. Anomaly scoring needs the autoencoder tracked by{' '}
          <IssueLink n={47} /> (PROJECT.md §13).
        </>
      )}
    </UnavailableSect>
  )
}
