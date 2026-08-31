import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { estimateArchitecture, type ArchEstimate } from '../api/client'
import {
  ACTIVATIONS,
  DEFAULT_HIDDEN,
  EXCESSIVE_PARAM_FACTOR,
  INPUT_SIZE,
  MAX_SANE_WIDTH,
  OUTPUT_SIZE,
  excessiveReasons,
  hiddenFromUnknown,
  layerBreakdown,
  newLayer,
  normalizeHidden,
  parameterCount,
  prevWidth,
  residualEligible,
  roughFlops,
  toArchitecture,
  type HiddenLayer,
} from '../lib/arch'
import { fmtBytes, fmtInt } from '../lib/format'
import { Link } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'

const PERSIST_KEY = 'architecture.hidden'

export function Architecture() {
  const [stored, setStored] = usePersistedState<HiddenLayer[]>(PERSIST_KEY, DEFAULT_HIDDEN)
  // Anything the persisted store (or an older build) hands back is clamped before use.
  const hidden = useMemo(() => normalizeHidden(stored), [stored])
  const setHidden = useCallback(
    (next: HiddenLayer[]) => setStored(normalizeHidden(next)),
    [setStored],
  )

  const [estimate, setEstimate] = useState<ArchEstimate | null>(null)
  const [estimateKey, setEstimateKey] = useState('')
  const [estimateErr, setEstimateErr] = useState<string | null>(null)

  const [importText, setImportText] = useState('')
  const [importErr, setImportErr] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const draftKey = useMemo(() => JSON.stringify(hidden), [hidden])

  // Debounced call to the daemon, the source of truth for the numbers and the
  // validity verdict. The local formulas (identical to the server's) fill the
  // ~300 ms gap and stand in when the daemon is unreachable.
  useEffect(() => {
    let alive = true
    const t = setTimeout(() => {
      estimateArchitecture(toArchitecture(hidden))
        .then((e) => {
          if (!alive) return
          setEstimate(e)
          setEstimateKey(draftKey)
          setEstimateErr(null)
        })
        .catch((err: unknown) => {
          if (alive) setEstimateErr(err instanceof Error ? err.message : String(err))
        })
    }, 300)
    return () => {
      alive = false
      clearTimeout(t)
    }
  }, [hidden, draftKey])

  const fresh = estimate != null && estimateKey === draftKey
  const local = useMemo(
    () => ({
      params: parameterCount(hidden),
      flops: roughFlops(hidden),
      breakdown: layerBreakdown(hidden),
    }),
    [hidden],
  )
  const params = fresh ? estimate.parameter_count : local.params
  const bytes = fresh ? estimate.approx_bytes : local.params * 4
  const flops = fresh ? estimate.rough_flops : local.flops
  const breakdown = fresh ? estimate.layers : local.breakdown
  const invalidReason = fresh && !estimate.valid ? (estimate.error ?? 'invalid architecture') : null
  const warnings = useMemo(() => excessiveReasons(hidden), [hidden])

  // ---- layer mutations ------------------------------------------------------
  const patch = (i: number, p: Partial<HiddenLayer>) =>
    setHidden(hidden.map((h, j) => (j === i ? { ...h, ...p } : h)))
  const remove = (i: number) => setHidden(hidden.filter((_, j) => j !== i))
  const add = () => setHidden([...hidden, newLayer(hidden.length ? hidden[hidden.length - 1]!.width : 32)])
  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir
    if (j < 0 || j >= hidden.length) return
    const next = hidden.slice()
    ;[next[i], next[j]] = [next[j]!, next[i]!]
    setHidden(next)
  }

  // ---- export / import ----------------------------------------------------
  const json = useMemo(() => JSON.stringify(toArchitecture(hidden), null, 2), [hidden])
  const copyRef = useRef<number | undefined>(undefined)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(json)
      setCopied(true)
      window.clearTimeout(copyRef.current)
      copyRef.current = window.setTimeout(() => setCopied(false), 1500)
    } catch {
      setImportErr('clipboard unavailable — select the JSON below and copy manually')
    }
  }
  const download = () => {
    const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'architecture.json'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }
  const load = () => {
    try {
      setHidden(hiddenFromUnknown(JSON.parse(importText)))
      setImportErr(null)
      setImportText('')
    } catch (e) {
      setImportErr(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="arch">
      <div className="page-h">
        <h1>Architecture Builder</h1>
        <span className="sub">
          design the hidden stack for <code>flow-classifier-v1</code>; the <b>{INPUT_SIZE}</b>-feature
          input and <b>{OUTPUT_SIZE}</b>-class output are locked (§10, §19.9)
        </span>
      </div>

      {invalidReason ? <div className="arch-warn err-banner">not buildable: {invalidReason}</div> : null}
      {warnings.length > 0 ? (
        <div className="arch-warn">
          <b>heads up</b> — this looks large for {INPUT_SIZE} input features (experiment freely, this
          does not block anything):
          <ul>
            {warnings.map((wn) => (
              <li key={wn}>{wn}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="cards">
        <div className="card span2">
          <h3>Layer stack</h3>
          <div className="arch-stack">
            <div className="arch-node locked">
              INPUT <b>{INPUT_SIZE}</b> &middot; flow-features-v1 <span className="tag">LOCKED</span>
            </div>

            {hidden.map((h, i) => {
              const resOk = residualEligible(hidden, i)
              return (
                <div key={i}>
                  <div className="arch-conn" />
                  <div className="arch-node arch-layer">
                    <span className="idx">{i + 1}</span>
                    <div className="arch-fields">
                      <label>
                        width
                        <input
                          type="number"
                          min={1}
                          step={1}
                          value={h.width}
                          onChange={(e) => patch(i, { width: Math.max(1, Math.floor(Number(e.target.value) || 1)) })}
                        />
                      </label>
                      <label>
                        activation
                        <select
                          value={h.activation}
                          onChange={(e) => patch(i, { activation: e.target.value as HiddenLayer['activation'] })}
                        >
                          {ACTIVATIONS.map((a) => (
                            <option key={a} value={a}>
                              {a}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        dropout
                        <input
                          type="number"
                          min={0}
                          max={0.99}
                          step={0.05}
                          value={h.dropout}
                          onChange={(e) =>
                            patch(i, { dropout: Math.min(0.99, Math.max(0, Number(e.target.value) || 0)) })
                          }
                        />
                      </label>
                      <label>
                        <input
                          type="checkbox"
                          checked={h.batchnorm}
                          onChange={(e) => patch(i, { batchnorm: e.target.checked })}
                        />
                        batchnorm
                      </label>
                      <label title={resOk ? '' : `residual needs the previous width (${prevWidth(hidden, i)}) to equal this width (${h.width})`}>
                        <input
                          type="checkbox"
                          checked={h.residual && resOk}
                          disabled={!resOk}
                          onChange={(e) => patch(i, { residual: e.target.checked })}
                        />
                        residual
                      </label>
                      {!resOk ? (
                        <span className="hint">
                          residual off: prev width {prevWidth(hidden, i)} &ne; {h.width}
                        </span>
                      ) : null}
                    </div>
                    <div className="arch-ops">
                      <button onClick={() => move(i, -1)} disabled={i === 0} aria-label={`move layer ${i + 1} up`}>
                        ↑
                      </button>
                      <button
                        onClick={() => move(i, 1)}
                        disabled={i === hidden.length - 1}
                        aria-label={`move layer ${i + 1} down`}
                      >
                        ↓
                      </button>
                      <button onClick={() => remove(i)} aria-label={`delete layer ${i + 1}`}>
                        ✕
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}

            <div className="arch-conn" />
            <div className="arch-node locked">
              OUTPUT <b>{OUTPUT_SIZE}</b> &middot; traffic-classes-v1 <span className="tag">LOCKED</span>
            </div>
          </div>

          <div className="arch-actions">
            <button onClick={add}>+ Add hidden layer</button>
            <button onClick={() => setHidden(DEFAULT_HIDDEN)}>Reset to default</button>
            <button onClick={() => setHidden([])}>Clear hidden layers</button>
          </div>
        </div>

        <div className="card span2">
          <h3>Estimates</h3>
          <dl className="kv">
            <dt>parameters</dt>
            <dd className="mono">{fmtInt(params)}</dd>
            <dt>approx. size</dt>
            <dd className="mono">{fmtBytes(bytes)} <span className="dim">(fp32 weights)</span></dd>
            <dt>rough inference FLOPs</dt>
            <dd className="mono">{fmtInt(flops)} <span className="dim">/ forward pass</span></dd>
            <dt>source</dt>
            <dd className="dim">
              {fresh
                ? 'daemon · POST /api/v1/architecture/estimate'
                : estimateErr
                  ? `daemon unreachable (${estimateErr}) — local estimate`
                  : 'computing…'}
            </dd>
          </dl>

          <table className="mini" style={{ marginTop: 10 }}>
            <thead>
              <tr>
                <th>#</th>
                <th>dense layer</th>
                <th>in → out</th>
                <th className="num">params</th>
              </tr>
            </thead>
            <tbody>
              {breakdown.map((row, i) => (
                <tr key={row.name}>
                  <td className="dim">{i + 1}</td>
                  <td>{row.name}</td>
                  <td className="mono">
                    {row.in} → {row.out}
                  </td>
                  <td className="num mono">{fmtInt(row.params)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card span2 arch-io">
          <h3>Export / import</h3>
          <p className="dim" style={{ margin: '0 0 8px' }}>
            The <code>schema.Architecture</code> shape — paste this straight into a training recipe&rsquo;s
            <code>architecture</code> field.
          </p>
          <div className="arch-actions" style={{ marginTop: 0, marginBottom: 8 }}>
            <button onClick={copy}>{copied ? 'copied ✓' : 'Copy JSON'}</button>
            <button onClick={download}>Download architecture.json</button>
          </div>
          <pre className="arch-json mono">{json}</pre>
          <label className="dim" htmlFor="arch-import">
            import — paste an architecture JSON and load its hidden stack
          </label>
          <textarea
            id="arch-import"
            value={importText}
            placeholder='{ "hidden": [ { "width": 128, "activation": "relu", "dropout": 0.2, "batchnorm": true } ] }'
            onChange={(e) => setImportText(e.target.value)}
          />
          <div className="arch-actions" style={{ marginTop: 8 }}>
            <button onClick={load} disabled={!importText.trim()}>
              Load JSON
            </button>
            {importErr ? <span className="err">{importErr}</span> : null}
          </div>
        </div>
      </div>

      <p className="dim" style={{ marginTop: 12 }}>
        Widths &gt; {MAX_SANE_WIDTH} or a total over {EXCESSIVE_PARAM_FACTOR}× the baseline net raise a
        warning only. Training is launched from <Link to="/training">ML ▸ Training</Link>, not here —
        this view designs, estimates and exports. <span className="thugs">&#10214;THUGS&#10215;</span>
      </p>
    </div>
  )
}
