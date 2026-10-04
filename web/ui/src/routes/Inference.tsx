import { IPLabel } from '../components/IPContext'
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  getBehaviorSchema, getAttackSchema, getApplicationSchema,
  getClassifications,
  getFeatureSchema,
  getFlow,
  getFlowExplain,
  getModels,
} from '../api/client'
import { useStream } from '../api/stream'
import type { Classification } from '../api/types'
import { FlowInspector } from '../components/FlowInspector'
import { ActivationGraph } from '../components/ActivationGraph'
import { NeuralDiagram } from '../components/NeuralDiagram'
import { CLASS_NAMES, classColor } from '../lib/classes'
import { fmtNum, fmtPct } from '../lib/format'
import { usePoll } from '../lib/usePoll'

const loadRecent = () => getClassifications(80)
export function Inference() {
  const { connected } = useStream()
  const [follow, setFollow] = useState(true)
  const recent = usePoll(loadRecent, 2000, !follow)
  const registry = usePoll(getModels, 10000)
  const schema = usePoll(getFeatureSchema, 60000)
 const richSchema=usePoll(getBehaviorSchema,60000)
 const attacks=usePoll(getAttackSchema,60000)
 const applications=usePoll(getApplicationSchema,60000)
  const [flowID, setFlowID] = useState<number | null>(null)
  const [modelID, setModelID] = useState('')
  const [inspect, setInspect] = useState<Classification | null>(null)
  const [pinned, setPinned] = useState<Classification | null>(null)
  const rows = useMemo(
    () =>
      [...(recent.data ?? [])].sort(
        (a, b) => Date.parse(b.ts) - Date.parse(a.ts),
      ),
    [recent.data],
  )
  useEffect(() => {
    if (follow && rows[0]) setFlowID(rows[0].flow_id)
  }, [follow, rows])
  const cls =
    rows.find((r) => r.flow_id === flowID) ??
    (pinned?.flow_id === flowID ? pinned : null)
  const loadDetail = useCallback(async () => {
    if (flowID == null) return null
    const [flow, explanation] = await Promise.allSettled([
      getFlow(flowID),
      getFlowExplain(flowID, true),
    ])
    return {
      id: flowID,
      flow: flow.status === 'fulfilled' ? flow.value : null,
      explanation:
        explanation.status === 'fulfilled' ? explanation.value : null,
      errors: [flow, explanation]
        .filter((v) => v.status === 'rejected')
        .map((v) => String((v as PromiseRejectedResult).reason)),
    }
  }, [flowID])
  const detail = usePoll(loadDetail, 5000)
  const snapshot = detail.data?.id === flowID ? detail.data : null
  const modelOutputs = [...(cls?.result.models ?? [])]
  if(cls?.result.application) {const a=cls.result.application;modelOutputs.push({model_id:a.model_id,role:'application',class:a.class,class_id:a.class_id,score:a.score,scores:a.scores,detail:a})}
  const output = modelOutputs.find(m => m.model_id === modelID) ?? modelOutputs.find(m => !!m.detail) ?? modelOutputs[0]
  const model = registry.data?.models.find(
    (m) => m.model_id === output?.model_id,
  )
  const rawArch = model?.architecture as
    | {
        hidden?: Array<{ width: number }>
        input_size?: number
        output_size?: number
      }
    | undefined
  const architecture =
    rawArch &&
    Array.isArray(rawArch.hidden) &&
    rawArch.hidden.every((h) => Number.isInteger(h.width) && h.width > 0)
      ? rawArch
      : null
  const explanation = snapshot?.explanation?.models.find(
    (m) => m.model_id === output?.model_id,
  )
  const rich = model?.feature_schema === 'traffic-behavior-v1'
  const features = (rich ? richSchema : schema).data?.features ?? []
  const scores = output?.detail?.scores ?? output?.scores
  const scoreNames = output?.detail ? (output.detail.schema === 'application-classes-v1' ? applications : attacks).data?.classes.map(c => c.name) ?? [] : CLASS_NAMES.slice()
  const validScores = scores?.length === scoreNames.length && scores.every(v => Number.isFinite(v) && v >= 0 && v <= 1)
  return (
    <div className="visual-page">
      <div className="page-h">
        <div>
          <div className="eyebrow">ML / LIVE INFERENCE</div>
          <h1>Inside the decision.</h1>
          <p className="sub">
            Follow a traffic flow from behavioral features to each model’s
            classification.
          </p>
        </div>
        <button
          className={follow ? 'primary' : ''}
          onClick={() => {
            if (follow) setPinned(cls)
            setFollow(!follow)
          }}
        >
          {follow ? 'Pause on this flow' : 'Follow latest flow'}
        </button>
      </div>
      <div className="inference-flowbar">
        <span className={`conn${connected ? ' live' : ''}`}>
          <span className="dot" />
          {follow ? 'Following latest' : 'Paused'}
        </span>
        <label>
          Flow{' '}
          <select
            aria-label="Select traffic flow"
            value={flowID ?? ''}
            onChange={(e) => {
              const id = Number(e.target.value)
              setFollow(false)
              setFlowID(id)
              setPinned(rows.find((r) => r.flow_id === id) ?? null)
            }}
          >
            <option value="" disabled>
              Select a flow
            </option>
            {rows.map((r) => (
              <option key={r.flow_id} value={r.flow_id}>
                #{r.flow_id} · {r.proto} · {r.result.class}
              </option>
            ))}
          </select>
        </label>
        {cls && (
          <>
            <span className="mono">
              <IPLabel ip={cls.initiator_ip} port={cls.initiator_port} /> → <IPLabel ip={cls.responder_ip} port={cls.responder_port} />
            </span>
            <button onClick={() => setInspect(cls)}>Inspect flow ↗</button>
          </>
        )}
      </div>
      {recent.error && (
        <p className="err" role="alert">
          {recent.error}
        </p>
      )}
      {detail.error && (
        <p className="err" role="alert">
          {detail.error}
        </p>
      )}
      {snapshot?.errors.map((e) => (
        <p key={e} className="err" role="alert">
          {e}
        </p>
      ))}
      <div className="pipeline-strip">
        <span>
          <b>01</b> Network traffic
          <small>{cls?.proto ?? 'Waiting for traffic'}</small>
        </span>
        <i>→</i>
        <span>
          <b>02</b> Behavioral features
          <small>
            {snapshot?.flow
              ? `${(rich ? snapshot.flow.behavior?.values.length ?? 0 : snapshot.flow.features.values.length)} recorded inputs`
              : 'Waiting for flow record'}
          </small>
        </span>
        <i>→</i>
        <span>
          <b>03</b> Model inference
          <small>{cls?.result.models.length ?? 0} model outputs</small>
        </span>
        <i>→</i>
        <span>
          <b>04</b> Classification
          <small>
            {cls
              ? `${cls.result.class} · ${fmtPct(cls.result.score)}`
              : 'No verdict yet'}
          </small>
        </span>
      </div>
      {cls?.result.signals?.length ? <section className="viz-panel" style={{padding:20,marginBottom:20}}><h2>Observed patterns</h2><p className="viz-caption">Heuristic evidence, independent of the neural prediction.</p>{cls.result.signals.map(s => <p key={s.kind}><b>{s.kind.replace(/_/g,' ')}</b> · {s.evidence}</p>)}</section> : null}
      <div className="inference-layout">
        <section className="viz-panel feature-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">INPUT SIGNALS</div>
              <h2>Flow features</h2>
            </div>
            <span className="count-badge">{features.length}</span>
          </div>
          <p className="viz-caption">
            {explanation?.input.kind === 'normalized'
              ? 'Raw values and the normalized inputs this model received.'
              : 'Recorded raw values. Model normalization is not available here.'}
          </p>
          <div className="feature-grid">
            {features.map((feature) => {
              const value = (rich ? snapshot?.flow?.behavior : snapshot?.flow?.features)?.values[feature.index]
              const normalized = explanation?.input.features?.find(
                (f) => f.index === feature.index,
              )?.normalized
              return (
                <div key={feature.index} title={feature.calc}>
                  <span>{feature.name.replace(/_/g, ' ')}</span>
                  <b>{value == null ? '—' : fmtNum(value, 3)}</b>
                  {normalized != null && (
                    <small>normalized {fmtNum(normalized, 3)}</small>
                  )}
                </div>
              )
            })}
          </div>
        </section>
        <div className="inference-main">
          <section className="viz-panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">MODEL STRUCTURE</div>
                <h2>{model?.name || output?.model_id || 'Waiting for a model result'}</h2>{output?.role === 'experimental' && <small>Shadow comparison · this network does not drive alerts</small>}
              </div>
              {cls && (
                <select
                  aria-label="Select inference model"
                  value={output?.model_id ?? ''}
                  onChange={(e) => setModelID(e.target.value)}
                >
                  {modelOutputs.map((m) => (
                    <option key={m.model_id} value={m.model_id}>
                      {registry.data?.models.find(entry => entry.model_id === m.model_id)?.name || m.model_id} · {m.role}
                    </option>
                  ))}
                </select>
              )}
            </div>
            {explanation?.trace ? (<ActivationGraph outputNames={scoreNames} trace={explanation.trace} flowID={flowID ?? 0} playing={follow} />) : architecture ? (
              <NeuralDiagram
                widths={[
                  model?.input_size ?? 48,
                  ...architecture.hidden!.map((h) => h.width),
                  model?.output_size ?? 7,
                ]}
                active={false}
              />
            ) : (
              <div className="model-fallback">
                <span className="model-symbol">ƒ(x)</span>
                <h3>
                  {output ? 'Model scoring' : 'Waiting for classified traffic'}
                </h3>
                <p>
                  {output
                    ? 'This model has no registered neural topology. Its recorded inputs and results appear here when available.'
                    : 'Start a capture or replay to watch real classifier results arrive.'}
                </p>
              </div>
            )}
            <p className="viz-caption">
              {explanation?.trace ? explanation.trace.note : (explanation?.trace_note || 'Waiting for a trained model with retained input and output. The fallback schematic shows architecture only.') }
            </p>
          </section>
          <section className="viz-panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">RECORDED RESULT</div>
                <h2>Class scores</h2>
              </div>
              {cls?.result.disagreement && (
                <span className="warning-chip">Models disagree</span>
              )}
            </div>
            {validScores ? (
              <div className="score-bars">
                {scoreNames.map((name, i) => (
                  <div key={name}>
                    <span>{name.replace(/_/g, ' ')}</span>
                    <div className="score-track">
                      <i
                        style={{
                          width: `${scores![i]! * 100}%`,
                          background: classColor(name),
                        }}
                      />
                    </div>
                    <b>{fmtPct(scores![i]!, 1)}</b>
                  </div>
                ))}
              </div>
            ) : (
              <p className="viz-caption">
                A complete score vector is not available for this model.
              </p>
            )}
            {explanation?.explanation.kind === 'rules' && (
              <div className="viz-caption">
                <b>Rule evidence</b>
                <p>{explanation.explanation.note}</p>
                {explanation.explanation.rules.map((rule, i) => (
                  <p key={i}>
                    {rule.rule}: {rule.detail}
                  </p>
                ))}
              </div>
            )}
            {snapshot?.explanation?.anomaly.available && (
              <div className="viz-notice">
                Anomaly score:{' '}
                {fmtNum(snapshot.explanation.anomaly.score ?? 0, 3)} ·{' '}
                {snapshot.explanation.anomaly.exceeds
                  ? 'above calibrated threshold'
                  : 'within calibrated threshold'}
              </div>
            )}
          </section>
        </div>
      </div>
      {inspect && (
        <FlowInspector cls={inspect} onClose={() => setInspect(null)} />
      )}
    </div>
  )
}
