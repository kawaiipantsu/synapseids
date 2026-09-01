import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import {
  activateModel,
  deactivateModel,
  getAudit,
  getModel,
  getModels,
} from '../api/client'
import type {
  AuditRecord,
  ModelEntry,
  ModelStatus,
  ModelTreeNode,
  RuntimeModel,
} from '../api/types'
import { IssueLink } from '../components/IssueLink'
import { hiddenFromUnknown, layerBreakdown } from '../lib/arch'
import { CLASS_NAMES } from '../lib/classes'
import { fmtAgo, fmtBytes, fmtDateTime, fmtInt, fmtNum, fmtPct } from '../lib/format'
import { navigateWith, useHashQuery } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'

// ML ▸ Models — the model registry, the confirmation-gated activation
// workflow, and the audit trail (PROJECT.md §19.12, §15, §21, §28.10;
// issue #36, ADR 0022).
//
// The one rule this view exists to enforce: a model only ever goes live because
// an operator asked for it, in a dialog that names the model and says plainly
// what changes. There is deliberately no "activate on register", no "activate
// newest", and no bulk action — §28.10 forbids a trained model becoming live
// without an explicit human step, so this file offers no affordance that could
// become one.

const LIST_POLL_MS = 5000
const AUDIT_LIMIT = 200
/** Subject types that always get a filter chip, even with no records yet. */
const BASE_SUBJECT_TYPES = ['model', 'dataset', 'training']

// ---- small helpers -------------------------------------------------------

/** "sha256:9f86d081884c7d65…" — enough to eyeball, short enough to fit a cell. */
function shortHash(h: string): string {
  if (!h) return '—'
  const i = h.indexOf(':')
  const algo = i === -1 ? '' : h.slice(0, i + 1)
  const hex = i === -1 ? h : h.slice(i + 1)
  return hex.length <= 16 ? h : `${algo}${hex.slice(0, 16)}…`
}

function statusLabel(e: ModelEntry): ModelStatus {
  return e.status
}

/** A number from an unknown JSON value, or null. Metrics come straight from a
 *  bundle's metrics.json and are never schema-checked, so everything that
 *  reads them has to tolerate a string, a null or a missing key. */
function num(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return v
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v)
    if (Number.isFinite(n)) return n
  }
  return null
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null
}

/** A 2-D numeric matrix from an unknown value, or null. */
function asMatrix(v: unknown): number[][] | null {
  if (!Array.isArray(v) || v.length === 0) return null
  const rows: number[][] = []
  for (const r of v) {
    if (!Array.isArray(r)) return null
    const row: number[] = []
    for (const c of r) {
      const n = num(c)
      if (n == null) return null
      row.push(n)
    }
    rows.push(row)
  }
  // Only square matrices are a confusion matrix.
  return rows.every((r) => r.length === rows.length) ? rows : null
}

function StatusPill({ entry }: { entry: ModelEntry }) {
  const st = statusLabel(entry)
  const live = entry.runtime?.loaded === true
  return (
    <span className={`mr-pill mr-${st}`} title={live ? 'loaded in the live inference runtime' : st}>
      {st}
      {live ? ' ▪ live' : ''}
    </span>
  )
}

// ---- architecture (read-only; the builder in ML ▸ Architecture edits) ----

function ArchitecturePanel({ entry }: { entry: ModelEntry }) {
  let rows: ReturnType<typeof layerBreakdown> | null = null
  let parseErr = ''
  try {
    rows = layerBreakdown(hiddenFromUnknown(entry.architecture))
  } catch (e: unknown) {
    parseErr = e instanceof Error ? e.message : String(e)
  }

  return (
    <div className="card wide">
      <h3>Architecture</h3>
      <dl className="kv">
        <dt>feature schema</dt>
        <dd className="mono">
          {entry.feature_schema} ({fmtInt(entry.input_size)} in)
        </dd>
        <dt>output schema</dt>
        <dd className="mono">
          {entry.output_schema} ({fmtInt(entry.output_size)} out)
        </dd>
        <dt>parameters</dt>
        <dd className="mono">{fmtInt(entry.parameter_count)}</dd>
      </dl>
      {rows ? (
        <div className="src-scroll">
          <table className="mini">
            <thead>
              <tr>
                <th>layer</th>
                <th className="num">in</th>
                <th className="num">out</th>
                <th className="num">params</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.name}>
                  <td className="mono">{r.name}</td>
                  <td className="num mono">{fmtInt(r.in)}</td>
                  <td className="num mono">{fmtInt(r.out)}</td>
                  <td className="num mono">{fmtInt(r.params)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="foot">
          architecture not renderable — {parseErr || 'the bundle reported no hidden layers'}. The
          registry stores whatever the bundle's <code>metadata.json</code> carried; it is not
          rewritten here.
        </div>
      )}
    </div>
  )
}

// ---- metrics + confusion matrix (both pass-throughs, render defensively) -

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
                const alpha = v ? 0.1 + (v / max) * 0.75 : 0
                return (
                  <td
                    key={j}
                    className={i === j ? 'tr-cm-diag' : ''}
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
        Reported by the bundle's <code>metrics.json</code>, measured by the trainer on its own
        held-out split — not by this daemon on live traffic.
      </div>
    </div>
  )
}

/** Known top-level metric keys we render as headline numbers; anything else in
 *  metrics.json is listed verbatim below so nothing is silently dropped. */
const HEADLINE_METRICS: Array<{ key: string; alt?: string; label: string; pct: boolean }> = [
  { key: 'accuracy', alt: 'val_accuracy', label: 'accuracy', pct: true },
  { key: 'macro_precision', alt: 'val_macro_precision', label: 'macro precision', pct: true },
  { key: 'macro_recall', alt: 'val_macro_recall', label: 'macro recall', pct: true },
  { key: 'macro_f1', alt: 'val_macro_f1', label: 'macro F1', pct: true },
]

const MATRIX_KEYS = ['confusion', 'confusion_matrix']
const PER_CLASS_KEYS = ['per_class', 'per_class_metrics', 'classes_report']

function MetricsPanel({ entry }: { entry: ModelEntry }) {
  const m = asRecord(entry.metrics)
  if (!m) {
    return (
      <div className="card wide">
        <h3>Metrics</h3>
        <div className="foot">
          the bundle carries no <code>metrics.json</code>, or it is not a JSON object. Nothing is
          inferred: an unreported metric is shown as missing, never as zero.
        </div>
      </div>
    )
  }

  const headline = HEADLINE_METRICS.map((h) => ({
    ...h,
    value: num(m[h.key]) ?? (h.alt ? num(m[h.alt]) : null),
  })).filter((h) => h.value != null)

  let matrix: number[][] | null = null
  let matrixKey = ''
  for (const k of MATRIX_KEYS) {
    const mm = asMatrix(m[k])
    if (mm) {
      matrix = mm
      matrixKey = k
      break
    }
  }

  // Per-class rows: either an array of objects, or an object keyed by class.
  const perClassRaw = PER_CLASS_KEYS.map((k) => m[k]).find((v) => v != null)
  const perClass: Array<{ name: string; row: Record<string, unknown> }> = []
  if (Array.isArray(perClassRaw)) {
    perClassRaw.forEach((r, i) => {
      const rec = asRecord(r)
      if (rec) perClass.push({ name: String(rec.class ?? rec.name ?? `c${i}`), row: rec })
    })
  } else {
    const rec = asRecord(perClassRaw)
    if (rec) {
      for (const [name, v] of Object.entries(rec)) {
        const row = asRecord(v)
        if (row) perClass.push({ name, row })
      }
    }
  }

  // Whatever is left: scalars we did not claim as a headline.
  const claimed = new Set<string>([
    ...HEADLINE_METRICS.flatMap((h) => [h.key, h.alt ?? '']),
    ...MATRIX_KEYS,
    ...PER_CLASS_KEYS,
    'classes',
  ])
  const extras = Object.entries(m).filter(
    ([k, v]) => !claimed.has(k) && (typeof v === 'number' || typeof v === 'string' || typeof v === 'boolean'),
  )

  const classes = Array.isArray(m.classes) ? m.classes.map(String) : [...CLASS_NAMES]

  return (
    <>
      <div className="card wide">
        <h3>Metrics</h3>
        {headline.length > 0 ? (
          <div className="cards mr-metrics">
            {headline.map((h) => (
              <div className="card mr-metric" key={h.label}>
                <h3>{h.label}</h3>
                <div className="big">{h.pct ? fmtPct(h.value!, 2) : fmtNum(h.value!, 4)}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="foot">
            no recognised headline metric in <code>metrics.json</code>.
          </div>
        )}
        {perClass.length > 0 ? (
          <div className="src-scroll">
            <table className="mini">
              <thead>
                <tr>
                  <th>class</th>
                  <th className="num">precision</th>
                  <th className="num">recall</th>
                  <th className="num">f1</th>
                  <th className="num">support</th>
                </tr>
              </thead>
              <tbody>
                {perClass.map((p) => (
                  <tr key={p.name}>
                    <td className="mono">{p.name}</td>
                    {(['precision', 'recall', 'f1'] as const).map((k) => {
                      const v = num(p.row[k]) ?? num(p.row[`${k}_score`])
                      return (
                        <td className="num mono" key={k}>
                          {v == null ? '—' : fmtPct(v, 2)}
                        </td>
                      )
                    })}
                    <td className="num mono">
                      {num(p.row.support) == null ? '—' : fmtInt(num(p.row.support)!)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {extras.length > 0 ? (
          <dl className="kv">
            {extras.map(([k, v]) => (
              <div key={k} style={{ display: 'contents' }}>
                <dt>{k}</dt>
                <dd className="mono">{String(v)}</dd>
              </div>
            ))}
          </dl>
        ) : null}
      </div>

      <div className="card wide">
        <h3>Confusion matrix</h3>
        {matrix ? (
          <>
            <ConfusionMatrix matrix={matrix} classes={classes} />
            <div className="foot">
              from <code>metrics.json → {matrixKey}</code>.
            </div>
          </>
        ) : (
          <div className="foot">
            not reported — the registry entry passes the bundle's <code>metrics.json</code> through
            unchanged, and this bundle carries no square <code>confusion</code> matrix. A trained
            model exported with one will render it here; ML ▸ Training shows the matrix for a run in
            progress.
          </div>
        )}
      </div>
    </>
  )
}

// ---- lineage (§15) -------------------------------------------------------

function TreeRows({ nodes, depth, selected }: { nodes: ModelTreeNode[]; depth: number; selected: string }) {
  return (
    <>
      {nodes.map((n) => (
        <div key={n.entry.model_id}>
          <div
            className={'mr-treerow' + (n.entry.model_id === selected ? ' sel' : '')}
            style={{ paddingLeft: `${depth * 16}px` }}
          >
            <button className="mr-treelink" onClick={() => navigateWith('/models', { id: n.entry.model_id })}>
              {depth > 0 ? '└ ' : ''}
              {n.entry.model_id}
            </button>
            <StatusPill entry={n.entry} />
          </div>
          {n.children.length > 0 ? (
            <TreeRows nodes={n.children} depth={depth + 1} selected={selected} />
          ) : null}
        </div>
      ))}
    </>
  )
}

function LineagePanel({
  entry,
  lineage,
  children,
}: {
  entry: ModelEntry
  lineage: ModelEntry[]
  children: ModelEntry[]
}) {
  // The chain the API returns is root-first with this model last. Present it as
  // a tree so a derived model reads the way §15 draws it.
  const chain: ModelTreeNode[] =
    lineage.length > 0
      ? (() => {
          let node: ModelTreeNode = { entry: lineage[lineage.length - 1]!, children: [] }
          for (let i = lineage.length - 2; i >= 0; i--) {
            node = { entry: lineage[i]!, children: [node] }
          }
          // Hang this model's own children off the deepest node (itself).
          let deepest = node
          while (deepest.children.length > 0) deepest = deepest.children[0]!
          deepest.children = children.map((c) => ({ entry: c, children: [] }))
          return [node]
        })()
      : [{ entry, children: children.map((c) => ({ entry: c, children: [] })) }]

  return (
    <div className="card wide">
      <h3>Lineage</h3>
      <div className="mr-tree">
        <TreeRows nodes={chain} depth={0} selected={entry.model_id} />
      </div>
      <div className="foot">
        {entry.derived_from ? (
          <>
            derived from <code>{entry.derived_from}</code>.{' '}
          </>
        ) : (
          <>a lineage root — no parent model. </>
        )}
        {children.length === 0
          ? 'Nothing is derived from it yet.'
          : `${children.length} model(s) derive from it.`}{' '}
        Click a node to open it.
      </div>
    </div>
  )
}

// ---- audit trail ---------------------------------------------------------

function AuditTable({ records, showSubject }: { records: AuditRecord[]; showSubject: boolean }) {
  if (records.length === 0) {
    return <div className="foot">no audit records match.</div>
  }
  return (
    <div className="src-scroll">
      <table className="mini mr-audit">
        <thead>
          <tr>
            <th>when</th>
            <th>event</th>
            <th>actor</th>
            {showSubject ? <th>subject</th> : null}
            <th>detail</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r, i) => (
            <tr key={`${r.ts}-${r.event}-${r.subject}-${i}`}>
              <td className="mono" title={r.ts}>
                {fmtDateTime(r.ts)}
              </td>
              <td>
                <span className={'mr-ev mr-ev-' + r.subject_type}>{r.event}</span>
              </td>
              <td className="mono">{r.actor}</td>
              {showSubject ? (
                <td className="mono" title={`${r.subject_type}: ${r.subject}`}>
                  <span className="mr-subjtype">{r.subject_type}</span> {r.subject}
                </td>
              ) : null}
              <td className="mono mr-detail">{r.detail || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** The global trail across every subject type, with a chip per type. The chip
 *  set is derived from the records themselves plus a fixed base, so a subject
 *  type introduced elsewhere (the review loop, issue #42) appears here on its
 *  own with no change to this file. */
function GlobalAudit() {
  const [subjectType, setSubjectType] = usePersistedState<string>('models.audit.subjectType', '')
  const [all, setAll] = useState<AuditRecord[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [bounds, setBounds] = useState<{ limit: number; max: number; scan: number } | null>(null)

  const load = useCallback(() => {
    getAudit({ limit: AUDIT_LIMIT })
      .then((r) => {
        setAll(r.records)
        setBounds({ limit: r.limit, max: r.max_limit, scan: r.scan_bytes_cap })
        setErr(null)
      })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
  }, [])

  const loadRef = useRef(load)
  loadRef.current = load
  useEffect(() => {
    loadRef.current()
    const t = window.setInterval(() => loadRef.current(), LIST_POLL_MS)
    return () => window.clearInterval(t)
  }, [])

  const types = useMemo(() => {
    const seen = new Set<string>(BASE_SUBJECT_TYPES)
    for (const r of all) if (r.subject_type) seen.add(r.subject_type)
    return [...seen].sort()
  }, [all])

  const shown = subjectType ? all.filter((r) => r.subject_type === subjectType) : all

  return (
    <div className="card wide">
      <h3>Audit trail — all subjects</h3>
      {err ? <div className="src-msg err">audit log unavailable — {err}</div> : null}
      <div className="mr-chips">
        <button className={subjectType === '' ? 'on' : ''} onClick={() => setSubjectType('')}>
          all ({all.length})
        </button>
        {types.map((t) => (
          <button key={t} className={subjectType === t ? 'on' : ''} onClick={() => setSubjectType(t)}>
            {t} ({all.filter((r) => r.subject_type === t).length})
          </button>
        ))}
      </div>
      <AuditTable records={shown} showSubject />
      <div className="foot">
        Newest first. Who activated what and when, plus dataset edits and training runs — the
        durable record from <code>GET /api/v1/audit</code>. The log is{' '}
        <b>append-only forever</b>: there is no route, and no button anywhere in this UI, that can
        edit or delete a line.
        {bounds
          ? ` Showing at most ${fmtInt(bounds.limit)} of a possible ${fmtInt(bounds.max)} records; the reader scans back at most ${fmtBytes(bounds.scan)} from the end of the file, so older history stays on disk but is not served here.`
          : ''}
      </div>
    </div>
  )
}

// ---- detail pane ---------------------------------------------------------

function ModelDetailPane({
  id,
  onChanged,
  runtime,
}: {
  id: string
  onChanged: () => void
  runtime: RuntimeModel[]
}) {
  const [entry, setEntry] = useState<ModelEntry | null>(null)
  const [lineage, setLineage] = useState<ModelEntry[]>([])
  const [children, setChildren] = useState<ModelEntry[]>([])
  const [audit, setAudit] = useState<AuditRecord[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [auditErr, setAuditErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [now, setNow] = useState(() => Date.now())

  const load = useCallback(() => {
    getModel(id)
      .then((d) => {
        setEntry(d.entry)
        setLineage(d.lineage ?? [])
        setChildren(d.children ?? [])
        setErr(null)
      })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
    getAudit({ subject_type: 'model', subject: id, limit: AUDIT_LIMIT })
      .then((r) => {
        setAudit(r.records)
        setAuditErr(null)
      })
      .catch((e: unknown) => setAuditErr(e instanceof Error ? e.message : String(e)))
    setNow(Date.now())
  }, [id])

  const loadRef = useRef(load)
  loadRef.current = load
  useEffect(() => {
    setEntry(null)
    setMsg(null)
    loadRef.current()
    const t = window.setInterval(() => loadRef.current(), LIST_POLL_MS)
    return () => window.clearInterval(t)
  }, [id])

  if (err && !entry) {
    return <div className="src-msg err">model {id} unavailable — {err}</div>
  }
  if (!entry) {
    return <div className="foot">loading {id}…</div>
  }

  const activeOther = runtime.find((r) => r.registered && r.id !== entry.model_id && r.role === 'primary')
  const isLive = entry.runtime?.loaded === true

  // §28.10 — the confirmation step. It names the model, states in plain words
  // that every live flow will be scored by it, names what it replaces, and says
  // activation is audited and does not survive a restart. No default-yes, no
  // "don't ask again", and nothing anywhere calls activateModel() without it.
  const onActivate = async () => {
    const replaces = activeOther ? activeOther.id : 'the built-in heuristic classifier'
    const ok = window.confirm(
      `Activate ${entry.name} ${entry.version} (${entry.model_id})?\n\n` +
        `This model will become the PRIMARY classifier for ALL live traffic. ` +
        `Every flow classified from now on is scored by it instead of ${replaces}.\n\n` +
        `  model_id      ${entry.model_id}\n` +
        `  family        ${entry.family}\n` +
        `  content hash  ${entry.content_hash}\n` +
        `  parameters    ${fmtInt(entry.parameter_count)}\n` +
        `  artifact      ${fmtBytes(entry.artifact_bytes)}\n` +
        `  trained       ${fmtDateTime(entry.created_at)} by trainer ${entry.trainer_version || '?'}\n\n` +
        `The bundle is re-validated before it goes live; if it no longer passes, nothing changes.\n` +
        `This action is written to the audit log. It does not survive a daemon restart — ` +
        `after a restart you must activate a model explicitly again.`,
    )
    if (!ok) return
    setBusy(true)
    setMsg(null)
    const r = await activateModel(entry.model_id)
    setBusy(false)
    setMsg({ ok: r.ok, text: r.ok ? `activated ${entry.model_id}` : `${r.status}: ${r.message}` })
    load()
    onChanged()
  }

  const onDeactivate = async () => {
    const ok = window.confirm(
      `Deactivate ${entry.name} ${entry.version} (${entry.model_id})?\n\n` +
        `The built-in heuristic classifier is restored as the primary for ALL live traffic. ` +
        `This model stops scoring flows immediately.\n\n` +
        `The model stays registered and can be activated again later.\n` +
        `This action is written to the audit log.`,
    )
    if (!ok) return
    setBusy(true)
    setMsg(null)
    const r = await deactivateModel(entry.model_id)
    setBusy(false)
    setMsg({ ok: r.ok, text: r.ok ? `deactivated ${entry.model_id}` : `${r.status}: ${r.message}` })
    load()
    onChanged()
  }

  const datasets = entry.training_dataset_ids ?? []

  return (
    <div className="mr-detail">
      <div className="page-h">
        <h1>
          {entry.name} <span className="dim">{entry.version}</span> <StatusPill entry={entry} />
        </h1>
        <span className="sub mono">{entry.model_id}</span>
      </div>

      {/* ---- the activation workflow (§28.10) ---- */}
      <div className="card wide mr-actions">
        <h3>Deployment</h3>
        <div className="mr-actionrow">
          <button className="on" disabled={busy || isLive} onClick={onActivate}>
            Activate
          </button>
          <button className="src-rm" disabled={busy || !isLive} onClick={onDeactivate}>
            Deactivate
          </button>
          {msg ? <span className={`src-msg ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</span> : null}
        </div>
        <div className="foot">
          {isLive ? (
            <>
              This model is <b>live</b>: it is scoring every flow the daemon classifies right now.
              Deactivating restores the built-in heuristic.
            </>
          ) : (
            <>
              This model is <b>not live</b>. Registering a model never activates it — activation is
              always a separate, explicit operator action (PROJECT.md §28.10), and it is confirmed
              before anything changes.{' '}
              {activeOther ? (
                <>
                  Activating it will replace <code>{activeOther.id}</code>, which is primary now.
                </>
              ) : (
                <>The built-in heuristic is primary now.</>
              )}
            </>
          )}
        </div>
      </div>

      {/* ---- the §19.12 field set ---- */}
      <div className="card wide">
        <h3>Registry entry</h3>
        <dl className="kv">
          <dt>model_id</dt>
          <dd className="mono">{entry.model_id}</dd>
          <dt>family</dt>
          <dd className="mono">{entry.family}</dd>
          <dt>status</dt>
          <dd>
            <StatusPill entry={entry} />
          </dd>
          <dt>content hash</dt>
          <dd className="mono" title={entry.content_hash}>
            {entry.content_hash}
          </dd>
          <dt>parameter count</dt>
          <dd className="mono">{fmtInt(entry.parameter_count)}</dd>
          <dt>artifact size</dt>
          <dd className="mono">{fmtBytes(entry.artifact_bytes)}</dd>
          <dt>created</dt>
          <dd className="mono" title={entry.created_at}>
            {fmtDateTime(entry.created_at)} ({fmtAgo(entry.created_at, now)})
          </dd>
          <dt>trainer version</dt>
          <dd className="mono">{entry.trainer_version || '—'}</dd>
          <dt>registered</dt>
          <dd className="mono" title={entry.registered_at}>
            {fmtDateTime(entry.registered_at)}
          </dd>
          <dt>last activated</dt>
          <dd className="mono">
            {entry.activated_at ? fmtDateTime(entry.activated_at) : 'never'}
          </dd>
          <dt>runtime</dt>
          <dd className="mono">
            {isLive ? `loaded as ${entry.runtime?.role ?? 'primary'}` : 'not loaded'}
          </dd>
          <dt>bundle dir</dt>
          <dd className="mono">{entry.dir}</dd>
        </dl>
        <div className="foot">
          Inference benchmarks (§19.12) are not recorded per model yet — SYSTEM ▸ Performance
          reports live inference latency for the runtime as a whole.
        </div>
      </div>

      <ArchitecturePanel entry={entry} />

      <div className="card wide">
        <h3>Training datasets</h3>
        {datasets.length === 0 ? (
          <div className="foot">the bundle names no training dataset ids.</div>
        ) : (
          <ul className="list-plain">
            {datasets.map((d) => (
              <li key={d} className="mono">
                <a href={`#/dataset-explorer?ref=${encodeURIComponent(d)}`}>{d}</a>
              </li>
            ))}
          </ul>
        )}
        <div className="foot">
          Recorded by the trainer in the bundle (§28.9). A link opens the dataset in ML ▸ Dataset
          Explorer if that version is still on disk.
        </div>
      </div>

      <MetricsPanel entry={entry} />

      <LineagePanel entry={entry} lineage={lineage} children={children} />

      <div className="card wide">
        <h3>Audit trail — this model</h3>
        {auditErr ? <div className="src-msg err">audit log unavailable — {auditErr}</div> : null}
        <AuditTable records={audit} showSubject={false} />
        <div className="foot">
          Every registration, activation and deactivation for <code>{entry.model_id}</code>, newest
          first. Activating a different model also lands here as a deactivation of this one.
        </div>
      </div>
    </div>
  )
}

// ---- the page -----------------------------------------------------------

export function Models() {
  const q = useHashQuery()
  const deepLinked = q.get('id') ?? ''
  const [stored, setStored] = usePersistedState<string | null>('models.selected', null)
  const [models, setModels] = useState<ModelEntry[]>([])
  const [runtime, setRuntime] = useState<RuntimeModel[]>([])
  const [listErr, setListErr] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [now, setNow] = useState(() => Date.now())

  const load = useCallback(() => {
    getModels()
      .then((r) => {
        setModels(r.models ?? [])
        setRuntime(r.runtime ?? [])
        setListErr(null)
        setLoaded(true)
      })
      .catch((e: unknown) => {
        setListErr(e instanceof Error ? e.message : String(e))
        setLoaded(true)
      })
    setNow(Date.now())
  }, [])

  const loadRef = useRef(load)
  loadRef.current = load
  useEffect(() => {
    loadRef.current()
    const t = window.setInterval(() => loadRef.current(), LIST_POLL_MS)
    return () => window.clearInterval(t)
  }, [])

  const selected = deepLinked || stored || ''
  // Drop a stale selection once the list has actually loaded.
  useEffect(() => {
    if (!loaded || models.length === 0) return
    if (selected && !models.some((m) => m.model_id === selected)) {
      setStored(null)
      if (deepLinked) navigateWith('/models', {})
    }
  }, [loaded, models, selected, deepLinked, setStored])

  const select = (id: string) => {
    setStored(id)
    navigateWith('/models', { id })
  }

  const heuristic = runtime.find((r) => !r.registered)
  const classGap = runtime.flatMap((r) => r.unsupported_classes ?? [])

  return (
    <div className="mr">
      <div className="page-h">
        <h1>Models</h1>
        <span className="sub">
          The model registry (§19.12) and the explicit activation workflow (§28.10) —{' '}
          <code>GET /api/v1/models</code>, <code>POST /api/v1/models/{'{id}'}/activate</code>,{' '}
          <code>GET /api/v1/audit</code>.
        </span>
      </div>

      {listErr ? <div className="src-msg err">model registry unavailable — {listErr}</div> : null}

      <div className="card wide">
        <h3>Live inference runtime</h3>
        {runtime.length === 0 ? (
          <div className="foot">no classifier reported by the runtime.</div>
        ) : (
          <div className="src-scroll">
            <table className="mini">
              <thead>
                <tr>
                  <th>model</th>
                  <th>family</th>
                  <th>role</th>
                  <th>registered</th>
                </tr>
              </thead>
              <tbody>
                {runtime.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.id}</td>
                    <td className="mono">{r.family}</td>
                    <td className="mono">{r.role}</td>
                    <td className="mono">{r.registered ? 'yes' : 'no — built in'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="foot">
          What is scoring traffic right now.{' '}
          {heuristic ? (
            <>
              <code>{heuristic.id}</code> is the built-in rule-based classifier; it is never
              registered and is restored whenever a trained model is deactivated.
            </>
          ) : null}{' '}
          A trained model appears here only after an operator activates it.
        </div>
        {classGap.length > 0 ? (
          <div className="foot">
            Labelled gap: the current classifier never emits{' '}
            {classGap.map((c, i) => (
              <span key={c}>
                {i > 0 ? ', ' : ''}
                <code>{c}</code>
              </span>
            ))}
            . Its byte-asymmetry rule fired only on ordinary uploads and was removed (
            <IssueLink n={135} />); whether <code>traffic-classes-v1</code> can carry the class
            at all without payload inspection is open (<IssueLink n={134} />). The class stays in
            the frozen output vector, and a trained model may still learn it.
          </div>
        ) : null}
      </div>

      <div className="card wide">
        <h3>Registered models ({models.length})</h3>
        {models.length === 0 ? (
          <div className="foot">
            no models registered. <code>synapsed</code> registers every bundle under{' '}
            <code>models.directory</code> that passes the validation gate at startup, as{' '}
            <b>INACTIVE</b> — registration never makes a model live.
          </div>
        ) : (
          <div className="src-scroll">
            <table className="mini src-table mr-table">
              <thead>
                <tr>
                  <th>model_id</th>
                  <th>name / version</th>
                  <th>family</th>
                  <th>status</th>
                  <th className="num">params</th>
                  <th className="num">artifact</th>
                  <th>hash</th>
                  <th>created</th>
                  <th>trainer</th>
                </tr>
              </thead>
              <tbody>
                {models.map((m) => (
                  <tr
                    key={m.model_id}
                    className={m.model_id === selected ? 'sel' : ''}
                    onClick={() => select(m.model_id)}
                  >
                    <td className="mono">
                      <button className="mr-idlink">{m.model_id}</button>
                    </td>
                    <td>
                      {m.name} <span className="dim">{m.version}</span>
                    </td>
                    <td className="mono">{m.family}</td>
                    <td>
                      <StatusPill entry={m} />
                    </td>
                    <td className="num mono">{fmtInt(m.parameter_count)}</td>
                    <td className="num mono">{fmtBytes(m.artifact_bytes)}</td>
                    <td className="mono" title={m.content_hash}>
                      {shortHash(m.content_hash)}
                    </td>
                    <td className="mono" title={m.created_at}>
                      {fmtAgo(m.created_at, now)}
                    </td>
                    <td className="mono">{m.trainer_version || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="foot">
          Pick a model to see its full entry, architecture, metrics, lineage and audit trail, and to
          activate or deactivate it. These routes are unauthenticated and loopback-only for now
          (issue #58) — so is the audit trail below, which is sensitive operational history.
        </div>
      </div>

      {selected ? (
        <ModelDetailPane id={selected} onChanged={load} runtime={runtime} />
      ) : (
        <div className="placeholder">
          <h1>No model selected</h1>
          <p className="dim">
            Pick a registered model above to inspect it and to activate it. Nothing is activated
            automatically.
          </p>
        </div>
      )}

      <GlobalAudit />
    </div>
  )
}
