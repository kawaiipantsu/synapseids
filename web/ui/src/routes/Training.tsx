import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { getTrainingRun, getTrainingRuns } from '../api/client'
import type { TrainingEpoch, TrainingFinal, TrainingPerClass, TrainingRun } from '../api/types'
import { CLASS_NAMES } from '../lib/classes'
import { fmtAgo, fmtDateTime, fmtDuration, fmtNum, fmtPct } from '../lib/format'
import { usePersistedState } from '../lib/persist'
import { TrainingChart, type Series } from '../components/TrainingChart'

// ML ▸ Training — the live training dashboard (PROJECT.md §19.8, issue #35).
//
// The Go daemon does not run training: synapse-trainer runs elsewhere and
// reports progress over HTTP (ADR 0019). This view is a read-only mirror. It
// polls GET /api/v1/training for the run list and GET /api/v1/training/{id} for
// the selected run every ~1.5 s while that run is `running`, then stops.

const LIST_POLL_MS = 4000
const RUN_POLL_MS = 1500

const STATUS_LABEL: Record<string, string> = {
  running: 'running',
  completed: 'completed',
  failed: 'failed',
  stale: 'stale',
}

function StatusPill({ status }: { status: string }) {
  return <span className={`tr-pill tr-${status}`}>{STATUS_LABEL[status] ?? status}</span>
}

/** Latest history entry, or an empty object. */
function latest(run: TrainingRun): TrainingEpoch {
  const h = run.history
  return h && h.length ? h[h.length - 1]! : {}
}

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

/** current-accuracy/precision/recall/F1: prefer the final block, else the last epoch. */
function headlineMetrics(run: TrainingRun): {
  accuracy: number | null
  precision: number | null
  recall: number | null
  f1: number | null
  source: 'final' | 'epoch' | 'none'
} {
  const f = run.final
  if (f) {
    return {
      accuracy: num(f.accuracy),
      precision: num(f.macro_precision),
      recall: num(f.macro_recall),
      f1: num(f.macro_f1),
      source: 'final',
    }
  }
  const e = latest(run)
  const acc = num(e.accuracy) ?? num(e.val_accuracy)
  if (acc == null && e.val_macro_f1 == null) {
    return { accuracy: null, precision: null, recall: null, f1: null, source: 'none' }
  }
  return {
    accuracy: acc,
    precision: num(e.val_macro_precision),
    recall: num(e.val_macro_recall),
    f1: num(e.val_macro_f1),
    source: 'epoch',
  }
}

function elapsedSeconds(run: TrainingRun): number | null {
  const e = latest(run)
  if (typeof e.elapsed_s === 'number') return e.elapsed_s
  if (run.final && typeof run.final.elapsed_s === 'number') return run.final.elapsed_s
  const start = Date.parse(run.started_at)
  const end = run.finished_at ? Date.parse(run.finished_at) : Date.parse(run.updated_at)
  if (Number.isNaN(start) || Number.isNaN(end)) return null
  return Math.max(0, (end - start) / 1000)
}

function deviceLabel(run: TrainingRun): string {
  const d = latest(run).device ?? run.final?.device
  if (typeof d !== 'string' || !d) return 'not reported'
  if (d === 'cpu') return 'CPU'
  if (d === 'cuda' || d === 'gpu') return 'GPU (CUDA)'
  return d
}

// ---- confusion matrix ---------------------------------------------------

function ConfusionMatrix({ matrix, classes }: { matrix: number[][]; classes: string[] }) {
  const n = matrix.length
  const labels = classes.length === n ? classes : Array.from({ length: n }, (_, i) => `c${i}`)
  const rowTotals = matrix.map((r) => r.reduce((a, b) => a + b, 0))
  const max = Math.max(1, ...matrix.flat())
  return (
    <div className="tr-cm-wrap">
      <table className="tr-cm">
        <thead>
          <tr>
            <th className="tr-cm-corner">actual ╲ pred</th>
            {labels.map((c) => (
              <th key={c} title={c}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, i) => (
            <tr key={i}>
              <th title={labels[i]}>{labels[i]}</th>
              {row.map((v, j) => {
                const frac = rowTotals[i] ? v / rowTotals[i]! : 0
                const intensity = v / max
                const diag = i === j
                // Accent is #35c1d6 = rgb(53,193,214); uPlot/canvas aside, plain
                // rgba keeps this readable in the dark theme without color-mix.
                const alpha = v ? 0.1 + intensity * 0.75 : 0
                return (
                  <td
                    key={j}
                    className={diag ? 'tr-cm-diag' : ''}
                    style={{ background: v ? `rgba(53,193,214,${alpha.toFixed(3)})` : 'transparent' }}
                    title={`${labels[i]} → ${labels[j]}: ${v} (${fmtPct(frac)})`}
                  >
                    {v || ''}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="foot">
        cell = count of <b>actual</b> class (row) predicted as <b>pred</b> class (column); the diagonal
        is correct. Shading is per-cell relative to the largest cell.
      </div>
    </div>
  )
}

function PerClassTable({ rows }: { rows: TrainingPerClass[] }) {
  return (
    <div className="src-scroll">
      <table className="mini">
        <thead>
          <tr>
            <th>class</th>
            <th className="num">precision</th>
            <th className="num">recall</th>
            <th className="num">F1</th>
            <th className="num">support</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.class}>
              <td>{r.class}</td>
              <td className="num mono">{fmtNum(r.precision, 3)}</td>
              <td className="num mono">{fmtNum(r.recall, 3)}</td>
              <td className="num mono">{fmtNum(r.f1, 3)}</td>
              <td className="num mono">{r.support}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---- metric card ------------------------------------------------------

function MetricCard({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="card tr-metric">
      <h3>{label}</h3>
      <div className="big">{value == null ? '—' : fmtPct(value, 1)}</div>
    </div>
  )
}

// ---- selected-run panel ---------------------------------------------------

function RunDetail({ run }: { run: TrainingRun }) {
  const hist = run.history ?? []
  const xs = hist.map((e, i) => (typeof e.epoch === 'number' ? e.epoch : i + 1))

  const lossSeries: Series[] = [
    { label: 'train loss', values: hist.map((e) => num(e.train_loss)), color: 'var(--accent)' },
    { label: 'val loss', values: hist.map((e) => num(e.val_loss)), color: 'var(--scan)' },
  ]
  const accSeries: Series[] = [
    {
      label: 'accuracy',
      values: hist.map((e) => num(e.accuracy) ?? num(e.val_accuracy)),
      color: 'var(--normal)',
    },
    { label: 'macro F1', values: hist.map((e) => num(e.val_macro_f1)), color: 'var(--web)' },
  ]
  const lrSeries: Series[] = [
    { label: 'learning rate', values: hist.map((e) => num(e.lr)), color: 'var(--brute)' },
  ]
  const hasLR = lrSeries[0]!.values.some((v) => v != null && v > 0)

  const m = headlineMetrics(run)
  const elapsed = elapsedSeconds(run)
  const last = latest(run)
  const batchLine =
    typeof last.batches === 'number' && typeof last.batches_total === 'number' && last.batches_total > 0
      ? `${last.batches}/${last.batches_total} batches`
      : null

  const final: TrainingFinal | undefined = run.final
  const perClass = final?.per_class ?? []
  const confusion = final?.confusion ?? []

  return (
    <div className="tr-detail">
      <div className="page-h">
        <h1>
          {run.name} <StatusPill status={run.status} />
        </h1>
        <span className="sub">
          run <code>{run.id}</code>
          {run.trainer_version ? <> · synapse-trainer {run.trainer_version}</> : null} · started{' '}
          {fmtDateTime(run.started_at)}
        </span>
      </div>

      {run.status === 'failed' && run.fail_reason ? (
        <div className="src-msg err">training failed — {run.fail_reason}</div>
      ) : null}
      {run.status === 'stale' ? (
        <div className="arch-warn">
          no progress update for a while — the trainer process may have died. The last known state is
          shown below.
        </div>
      ) : null}

      <div className="cards tr-head">
        <div className="card tr-metric">
          <h3>Epoch</h3>
          <div className="big">
            {run.epoch || 0}
            <span className="dim"> / {run.epochs_total || '—'}</span>
          </div>
          <div className="foot">{batchLine ?? (run.status === 'running' ? 'training…' : run.status)}</div>
        </div>
        <div className="card tr-metric">
          <h3>Elapsed</h3>
          <div className="big">{elapsed == null ? '—' : fmtDuration(elapsed)}</div>
          <div className="foot">{run.status === 'running' ? fmtAgo(run.updated_at) + ' since last update' : deviceLabel(run)}</div>
        </div>
        <MetricCard label="Accuracy" value={m.accuracy} />
        <MetricCard label="Precision (macro)" value={m.precision} />
        <MetricCard label="Recall (macro)" value={m.recall} />
        <MetricCard label="F1 (macro)" value={m.f1} />
      </div>
      <p className="foot tr-src">
        metrics from {m.source === 'final' ? 'the held-out final evaluation' : m.source === 'epoch' ? `the latest validation epoch` : 'no data yet'} ·
        compute: <b>{deviceLabel(run)}</b>
        {deviceLabel(run) === 'not reported' ? ' (the trainer did not report CPU/GPU)' : ''}
      </p>

      <div className="cards tr-charts">
        <div className="card span2">
          <h3>Loss</h3>
          {hist.length ? (
            <TrainingChart xs={xs} series={lossSeries} yLabel="loss" ariaLabel="training and validation loss by epoch" />
          ) : (
            <div className="foot">no epochs reported yet</div>
          )}
        </div>
        <div className="card span2">
          <h3>Accuracy / F1</h3>
          {hist.length ? (
            <TrainingChart xs={xs} series={accSeries} yLabel="score" ariaLabel="validation accuracy and macro F1 by epoch" />
          ) : (
            <div className="foot">no epochs reported yet</div>
          )}
        </div>
        <div className="card span2">
          <h3>Learning rate</h3>
          {hist.length && hasLR ? (
            <TrainingChart xs={xs} series={lrSeries} yLabel="lr" logY ariaLabel="learning rate by epoch" />
          ) : (
            <div className="foot">not reported</div>
          )}
        </div>
      </div>

      <div className="card wide">
        <h3>Per-class metrics {perClass.length ? '' : <span className="dim">— on completion</span>}</h3>
        {perClass.length ? (
          <PerClassTable rows={perClass} />
        ) : (
          <div className="foot">
            the trainer emits the per-class precision/recall/F1 table with the final <code>done</code>{' '}
            report.
          </div>
        )}
      </div>

      <div className="card wide">
        <h3>Confusion matrix {confusion.length ? '' : <span className="dim">— on completion</span>}</h3>
        {confusion.length ? (
          <ConfusionMatrix matrix={confusion} classes={CLASS_NAMES.slice()} />
        ) : (
          <div className="foot">
            a {CLASS_NAMES.length}×{CLASS_NAMES.length} <code>traffic-classes-v1</code> grid appears here
            once the run completes.
          </div>
        )}
      </div>

      {final?.test ? (
        <div className="card wide">
          <h3>Held-out test set</h3>
          <dl className="kv">
            <dt>accuracy</dt>
            <dd className="mono">{fmtPct(final.test.accuracy ?? NaN)}</dd>
            <dt>macro F1</dt>
            <dd className="mono">{fmtNum(final.test.macro_f1 ?? NaN, 3)}</dd>
            <dt>macro precision</dt>
            <dd className="mono">{fmtNum(final.test.macro_precision ?? NaN, 3)}</dd>
            <dt>macro recall</dt>
            <dd className="mono">{fmtNum(final.test.macro_recall ?? NaN, 3)}</dd>
          </dl>
        </div>
      ) : null}
    </div>
  )
}

// ---- the page ----------------------------------------------------------

export function Training() {
  const [runs, setRuns] = useState<TrainingRun[]>([])
  const [listErr, setListErr] = useState<string | null>(null)
  const [selectedId, setSelectedId] = usePersistedState<string | null>('training.selected', null)
  const [detail, setDetail] = useState<TrainingRun | null>(null)
  const [detailErr, setDetailErr] = useState<string | null>(null)
  const [now, setNow] = useState(() => Date.now())

  const loadList = useCallback(() => {
    getTrainingRuns(50)
      .then((r) => {
        setRuns(r.runs ?? [])
        setListErr(null)
      })
      .catch((e: unknown) => setListErr(e instanceof Error ? e.message : String(e)))
  }, [])

  const listRef = useRef(loadList)
  listRef.current = loadList
  useEffect(() => {
    listRef.current()
    const id = window.setInterval(() => {
      setNow(Date.now())
      listRef.current()
    }, LIST_POLL_MS)
    return () => window.clearInterval(id)
  }, [])

  // Auto-select the newest run when nothing is chosen (or the choice is gone).
  useEffect(() => {
    if (runs.length === 0) return
    if (!selectedId || !runs.some((r) => r.id === selectedId)) {
      setSelectedId(runs[0]!.id)
    }
  }, [runs, selectedId, setSelectedId])

  // Poll the selected run; fast while it is running, stop once terminal.
  useEffect(() => {
    if (!selectedId) {
      setDetail(null)
      return
    }
    let alive = true
    let timer = 0
    const tick = () => {
      getTrainingRun(selectedId)
        .then((run) => {
          if (!alive) return
          setDetail(run)
          setDetailErr(null)
          if (run.status === 'running' || run.status === 'stale') {
            timer = window.setTimeout(tick, RUN_POLL_MS)
          }
        })
        .catch((e: unknown) => {
          if (!alive) return
          setDetailErr(e instanceof Error ? e.message : String(e))
          timer = window.setTimeout(tick, RUN_POLL_MS * 3)
        })
    }
    tick()
    return () => {
      alive = false
      window.clearTimeout(timer)
    }
  }, [selectedId])

  const selected = detail && detail.id === selectedId ? detail : runs.find((r) => r.id === selectedId) ?? null

  const sorted = useMemo(() => runs, [runs])

  return (
    <div className="tr">
      <div className="page-h">
        <h1>Training</h1>
        <span className="sub">
          live view of <code>synapse-trainer</code> runs reported to the daemon over HTTP —{' '}
          <code>GET /api/v1/training</code> (§19.8, ADR 0019). The daemon mirrors progress; it does not
          launch training.
        </span>
      </div>

      {listErr ? <div className="src-msg err">run list unavailable — {listErr}</div> : null}

      <div className="tr-layout">
        <aside className="card tr-runs">
          <h3>Runs ({sorted.length})</h3>
          {sorted.length === 0 ? (
            <div className="foot">
              no runs yet. Start one with{' '}
              <code>synapse-trainer train --recipe … --data … --out … --report-to http://&lt;daemon&gt;</code>.
            </div>
          ) : (
            <ul className="tr-runlist">
              {sorted.map((r) => {
                const el = elapsedSeconds(r)
                return (
                  <li key={r.id}>
                    <button
                      className={r.id === selectedId ? 'sel' : ''}
                      onClick={() => setSelectedId(r.id)}
                    >
                      <span className="tr-runname">{r.name}</span>
                      <StatusPill status={r.status} />
                      <span className="tr-runmeta">
                        epoch {r.epoch || 0}/{r.epochs_total || '—'} · {fmtAgo(r.started_at, now)}
                        {el != null ? <> · {fmtDuration(el)}</> : null}
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </aside>

        <section className="tr-main">
          {detailErr && !selected ? (
            <div className="src-msg err">run unavailable — {detailErr}</div>
          ) : selected ? (
            <RunDetail run={selected} />
          ) : (
            <div className="placeholder">
              <h1>No run selected</h1>
              <p className="dim">Pick a run on the left, or start one that reports with --report-to.</p>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
