import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from 'react'

import {
  createDataset,
  datasetDownloadURL,
  deleteDataset,
  getDatasets,
} from '../api/client'
import type { Dataset, DatasetCreateInput, DatasetSelection } from '../api/types'
import { CLASS_NAMES, classColor } from '../lib/classes'
import { fmtAgo, fmtBytes, fmtDateTime, fmtInt } from '../lib/format'
import { usePersistedState } from '../lib/persist'

// ML ▸ Datasets (PROJECT.md §19.10, issue #33). A dataset is a first-class,
// versioned, immutable object: this view lists what has been cut, and cuts new
// ones from the stored classifications using the same filters the flow log
// uses. The distribution/correlation/PCA explorer is §19.11 (issue #37) and is
// deliberately not here.

const POLL_MS = 5000
const PROTOS = ['', 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'IP']

// ---- small presentational pieces ----------------------------------------

/** A one-line stacked bar of the label distribution, in schema class order. */
function LabelBar({ counts, total }: { counts: Record<string, number>; total: number }) {
  const present = CLASS_NAMES.filter((c) => (counts[c] ?? 0) > 0)
  const other = Object.keys(counts).filter((c) => !CLASS_NAMES.includes(c as never))
  if (total <= 0) return <span className="dim">—</span>
  return (
    <div className="ds-dist">
      <span className="ds-bar" role="img" aria-label={`label distribution: ${present.map((c) => `${c} ${counts[c]}`).join(', ')}`}>
        {[...present, ...other].map((c) => (
          <span
            key={c}
            className="seg"
            style={{ width: `${((counts[c] ?? 0) / total) * 100}%`, background: classColor(c) }}
            title={`${c}: ${fmtInt(counts[c] ?? 0)} (${(((counts[c] ?? 0) / total) * 100).toFixed(1)}%)`}
          />
        ))}
      </span>
      <span className="ds-legend">
        {[...present, ...other].map((c) => (
          <span key={c} className="ds-chip" title={`${c}: ${fmtInt(counts[c] ?? 0)}`}>
            <i style={{ background: classColor(c) }} />
            {c} {fmtInt(counts[c] ?? 0)}
          </span>
        ))}
      </span>
    </div>
  )
}

/** How the labels were produced, rendered so it cannot be mistaken for truth. */
function LabelingSource({ source }: { source: string }) {
  const human = source.startsWith('human_review')
  const models = source.startsWith('model_prediction:') ? source.slice('model_prediction:'.length) : ''
  if (human) {
    return <span className="ds-label-src human">human review</span>
  }
  return (
    <span
      className="ds-label-src model"
      title={`labels are this daemon's own predictions from ${models || 'an unknown model'} — not reviewed by a person`}
    >
      model prediction
      {models ? <span className="dim"> · {models}</span> : null}
    </span>
  )
}

function shortHash(h: string): string {
  const hex = h.startsWith('sha256:') ? h.slice(7) : h
  return hex.slice(0, 12)
}

function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="src-field">
      <span>{label}</span>
      {children}
      {hint ? <span className="hint">{hint}</span> : null}
    </label>
  )
}

// ---- the create form's draft --------------------------------------------

interface DraftState {
  id: string
  version: string
  name: string
  description: string
  location: string
  tags: string
  source_capture_ids: string
  derive_from: string
  // selection
  from: string
  to: string
  cls: string
  model: string
  proto: string
  initiator_ip: string
  responder_ip: string
  min_confidence: string
  disagreement: boolean
  limit: string
}

const EMPTY_DRAFT: DraftState = {
  id: '',
  version: '',
  name: '',
  description: '',
  location: '',
  tags: '',
  source_capture_ids: '',
  derive_from: '',
  from: '',
  to: '',
  cls: '',
  model: '',
  proto: '',
  initiator_ip: '',
  responder_ip: '',
  min_confidence: '',
  disagreement: false,
  limit: '',
}

const csvList = (v: string): string[] =>
  v
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)

/** A datetime-local value is wall-clock with no zone; send it as UTC RFC3339
 *  only once the operator has actually typed one. */
function toRFC3339(v: string): string | undefined {
  if (!v.trim()) return undefined
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? v : d.toISOString()
}

function toBody(d: DraftState): DatasetCreateInput {
  const s = (v: string) => (v.trim() ? v.trim() : undefined)
  const n = (v: string) => {
    const x = Number(v)
    return v.trim() && Number.isFinite(x) ? x : undefined
  }
  const selection: DatasetSelection = {}
  const from = toRFC3339(d.from)
  const to = toRFC3339(d.to)
  if (from) selection.from = from
  if (to) selection.to = to
  if (s(d.cls)) selection.class = d.cls.trim()
  if (s(d.model)) selection.model = d.model.trim()
  if (s(d.proto)) selection.proto = d.proto.trim()
  if (s(d.initiator_ip)) selection.initiator_ip = d.initiator_ip.trim()
  if (s(d.responder_ip)) selection.responder_ip = d.responder_ip.trim()
  const mc = n(d.min_confidence)
  if (mc != null) selection.min_confidence = mc
  if (d.disagreement) selection.disagreement = true
  const lim = n(d.limit)
  if (lim != null) selection.limit = lim

  const body: DatasetCreateInput = { id: d.id.trim(), selection }
  if (s(d.version)) body.version = d.version.trim()
  if (s(d.name)) body.name = d.name.trim()
  if (s(d.description)) body.description = d.description.trim()
  if (s(d.location)) body.location = d.location.trim()
  if (csvList(d.tags).length) body.tags = csvList(d.tags)
  if (csvList(d.source_capture_ids).length) body.source_capture_ids = csvList(d.source_capture_ids)
  if (s(d.derive_from)) body.derive_from = d.derive_from.trim()
  return body
}

// ---- the table row -------------------------------------------------------

function DatasetRow({
  d,
  now,
  busy,
  onDelete,
  onDerive,
}: {
  d: Dataset
  now: number
  busy: boolean
  onDelete: (d: Dataset) => void
  onDerive: (d: Dataset) => void
}) {
  const ref = `${d.id}@${d.version}`
  return (
    <>
      <tr>
        <td>
          <b>{d.id}</b>
          <span className="src-badge">{d.version}</span>
          {d.name && d.name !== d.id ? <div className="dim">{d.name}</div> : null}
        </td>
        <td className="num">{fmtInt(d.flow_count)}</td>
        <td className="ds-distcell">
          <LabelBar counts={d.label_counts} total={d.flow_count} />
        </td>
        <td>
          <LabelingSource source={d.labeling_source} />
        </td>
        <td title={fmtDateTime(d.created_at)}>{fmtAgo(d.created_at, now)}</td>
        <td className="mono" title={d.content_hash}>
          {shortHash(d.content_hash)}
        </td>
        <td className="mono">
          {d.parent_datasets.length === 0 ? (
            <span className="dim">—</span>
          ) : (
            d.parent_datasets.map((p) => (
              <div key={p} title={p}>
                {p}
              </div>
            ))
          )}
        </td>
        <td className="num">{fmtBytes(d.csv_bytes)}</td>
        <td className="ds-actions">
          <a
            className="ds-dl"
            href={datasetDownloadURL(d.id, d.version)}
            title={`download ${d.csv_file} — ${d.columns.length} columns`}
          >
            csv
          </a>
          <button disabled={busy} onClick={() => onDerive(d)} title={`prefill the form to derive from ${ref}`}>
            derive
          </button>
          <button className="src-rm" disabled={busy} onClick={() => onDelete(d)} title={`delete ${ref}`}>
            delete
          </button>
        </td>
      </tr>
      {d.warnings && d.warnings.length > 0 ? (
        <tr className="ds-warnrow">
          <td colSpan={9}>
            <ul>
              {d.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </td>
        </tr>
      ) : null}
    </>
  )
}

// ---- the page ------------------------------------------------------------

export function Datasets() {
  const [rows, setRows] = useState<Dataset[]>([])
  const [minRows, setMinRows] = useState(0)
  const [columns, setColumns] = useState<string[]>([])
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [now, setNow] = useState(() => Date.now())

  const [draft, setDraft] = usePersistedState<DraftState>('datasets.draft', EMPTY_DRAFT)
  const set = <K extends keyof DraftState>(k: K, v: DraftState[K]) => setDraft({ ...draft, [k]: v })

  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const load = useCallback(() => {
    getDatasets()
      .then((r) => {
        setRows(r.datasets ?? [])
        setMinRows(r.min_rows ?? 0)
        setColumns(r.columns ?? [])
        setLoadErr(null)
      })
      .catch((e: unknown) => setLoadErr(e instanceof Error ? e.message : String(e)))
  }, [])

  const loadRef = useRef(load)
  loadRef.current = load
  useEffect(() => {
    loadRef.current()
    const id = window.setInterval(() => {
      setNow(Date.now())
      loadRef.current()
    }, POLL_MS)
    return () => window.clearInterval(id)
  }, [])

  const totals = useMemo(() => {
    const flows = rows.reduce((a, d) => a + d.flow_count, 0)
    const ids = new Set(rows.map((d) => d.id))
    return { versions: rows.length, ids: ids.size, flows }
  }, [rows])

  const canSubmit = !busy && draft.id.trim().length > 0

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return
    setBusy(true)
    setMsg(null)
    const r = await createDataset(toBody(draft))
    setBusy(false)
    if (r.ok && r.dataset) {
      const d = r.dataset
      const warn = d.warnings?.length ? ` · ${d.warnings.length} warning(s)` : ''
      setMsg({ ok: true, text: `created ${d.id}@${d.version} — ${fmtInt(d.flow_count)} flows, ${shortHash(d.content_hash)}${warn}` })
      setDraft({ ...EMPTY_DRAFT })
    } else {
      setMsg({ ok: false, text: `${r.status}: ${r.message}` })
    }
    load()
  }

  const onDelete = async (d: Dataset) => {
    const ref = `${d.id}@${d.version}`
    if (
      !window.confirm(
        `Delete dataset ${ref}?\n\n${fmtInt(d.flow_count)} flows, ${d.content_hash}.\n` +
          `A dataset version is immutable but not undeletable. Any model trained on it keeps ` +
          `the hash in its metadata, but the rows themselves are gone unless you rebuild them.`,
      )
    ) {
      return
    }
    setBusy(true)
    setMsg(null)
    const r = await deleteDataset(d.id, d.version)
    setBusy(false)
    setMsg(r.ok ? { ok: true, text: `deleted ${ref}` } : { ok: false, text: `${r.status}: ${r.message}` })
    load()
  }

  const onDerive = (d: Dataset) => {
    setDraft({
      ...draft,
      id: d.id,
      version: '',
      name: d.name,
      description: d.description,
      location: d.location,
      tags: d.tags.join(', '),
      source_capture_ids: d.source_capture_ids.join(', '),
      derive_from: `${d.id}@${d.version}`,
      cls: d.selection.class ?? '',
      model: d.selection.model ?? '',
      proto: d.selection.proto ?? '',
      initiator_ip: d.selection.initiator_ip ?? '',
      responder_ip: d.selection.responder_ip ?? '',
      min_confidence: d.selection.min_confidence != null ? String(d.selection.min_confidence) : '',
      disagreement: d.selection.disagreement ?? false,
      limit: d.selection.limit != null ? String(d.selection.limit) : '',
    })
    setMsg({ ok: true, text: `form prefilled to derive from ${d.id}@${d.version}` })
  }

  return (
    <div>
      <div className="page-h">
        <h1>Datasets</h1>
        <span className="sub">
          versioned, immutable, content-hashed training sets cut from stored classifications —{' '}
          <code>GET/POST /api/v1/datasets</code> (§14, §19.10). Feature distributions, correlations
          and PCA are the Dataset Explorer (§19.11), not this view.
        </span>
      </div>

      <div className="arch-warn ds-honesty">
        <b>These labels are model predictions, not ground truth.</b> The human review loop
        (issue&nbsp;#42) does not exist yet, so every dataset built here is labelled by the daemon&rsquo;s
        own classifier — the heuristic, or whichever model was active. Training on it teaches a new
        model to imitate the old one; it does not teach it what is actually true. Each row&rsquo;s
        <code> labeling_source</code> records exactly which model produced the labels. A dataset that
        says <code>human_review</code> will only be possible once reviewed labels exist.
      </div>

      {loadErr ? <div className="src-msg err">dataset list unavailable — {loadErr}</div> : null}

      <div className="cards ds-cards">
        <div className="card">
          <h3>Dataset versions</h3>
          <div className="big">{fmtInt(totals.versions)}</div>
          <div className="foot">{fmtInt(totals.ids)} distinct id(s)</div>
        </div>
        <div className="card">
          <h3>Flows materialised</h3>
          <div className="big">{fmtInt(totals.flows)}</div>
          <div className="foot">rows written to disk, not a live view</div>
        </div>
        <div className="card">
          <h3>Trainer contract</h3>
          <div className="big">{columns.length ? columns.length - 1 : 48}+1</div>
          <div className="foot">
            flow-features-v1 columns + <code>label</code>
          </div>
        </div>
        <div className="card">
          <h3>Row floor</h3>
          <div className="big">{fmtInt(minRows)}</div>
          <div className="foot">a selection below this, or of one class, is refused</div>
        </div>
      </div>

      <div className="card wide">
        <h3>Versions ({rows.length})</h3>
        {rows.length === 0 ? (
          <div className="foot">
            no datasets yet — replay or capture some traffic, then cut one below. Each version lands
            in <code>datasets.directory</code> as <code>&lt;id&gt;/&lt;version&gt;/</code> holding{' '}
            <code>dataset.csv</code> and <code>manifest.json</code>.
          </div>
        ) : (
          <div className="src-scroll">
            <table className="mini src-table ds-table">
              <thead>
                <tr>
                  <th>id / version</th>
                  <th className="num">flows</th>
                  <th>label distribution</th>
                  <th>labels from</th>
                  <th>created</th>
                  <th>content hash</th>
                  <th>parents</th>
                  <th className="num">csv</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((d) => (
                  <DatasetRow
                    key={`${d.id}@${d.version}`}
                    d={d}
                    now={now}
                    busy={busy}
                    onDelete={onDelete}
                    onDerive={onDerive}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <form className="card wide src-form" onSubmit={submit}>
        <h3>Cut a dataset</h3>

        <div className="src-grid">
          <Field label="id" hint="lowercase slug, optionally one &quot;/&quot; — e.g. thugs/lab-attacks-2026-08">
            <input value={draft.id} onChange={(e) => set('id', e.target.value)} placeholder="thugs/lab-attacks-2026-08" />
          </Field>
          <Field label="version" hint="blank = next v&lt;n&gt;; an existing version is never overwritten">
            <input value={draft.version} onChange={(e) => set('version', e.target.value)} placeholder="v1" />
          </Field>
          <Field label="name" hint="blank = the id">
            <input value={draft.name} onChange={(e) => set('name', e.target.value)} />
          </Field>
          <Field label="location / site" hint="§15 — which site this traffic is from">
            <input value={draft.location} onChange={(e) => set('location', e.target.value)} placeholder="hq-copenhagen" />
          </Field>
          <Field label="tags" hint="comma separated">
            <input value={draft.tags} onChange={(e) => set('tags', e.target.value)} placeholder="lab, baseline" />
          </Field>
          <Field label="source capture ids" hint="comma separated; what this traffic came from">
            <input
              value={draft.source_capture_ids}
              onChange={(e) => set('source_capture_ids', e.target.value)}
              placeholder="replay:nmap_scan.pcap"
            />
          </Field>
          <Field label="description">
            <input value={draft.description} onChange={(e) => set('description', e.target.value)} />
          </Field>
          <Field label="derive from" hint="&lt;id&gt;@&lt;version&gt; — recorded in parent_datasets">
            <input value={draft.derive_from} onChange={(e) => set('derive_from', e.target.value)} placeholder="" />
          </Field>
        </div>

        <h3 className="ds-subhead">Selection</h3>
        <div className="foot ds-selnote">
          <code>class</code>, <code>model</code>, <code>min_confidence</code> and{' '}
          <code>disagreement</code> mean exactly what they mean on{' '}
          <code>GET /api/v1/classifications</code>, so you can preview a cut in the Flow Log first.
          One row per flow, newest verdict wins, sorted by flow id so the content hash is
          reproducible.
        </div>
        <div className="src-grid">
          <Field label="from" hint="local time; sent as UTC">
            <input type="datetime-local" value={draft.from} onChange={(e) => set('from', e.target.value)} />
          </Field>
          <Field label="to" hint="local time; sent as UTC">
            <input type="datetime-local" value={draft.to} onChange={(e) => set('to', e.target.value)} />
          </Field>
          <Field label="class" hint="a single-class selection is refused">
            <select value={draft.cls} onChange={(e) => set('cls', e.target.value)}>
              <option value="">(all classes)</option>
              {CLASS_NAMES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </Field>
          <Field label="protocol">
            <select value={draft.proto} onChange={(e) => set('proto', e.target.value)}>
              {PROTOS.map((p) => (
                <option key={p} value={p}>
                  {p || '(all)'}
                </option>
              ))}
            </select>
          </Field>
          <Field label="model" hint="keep rows any model in the ensemble scored">
            <input value={draft.model} onChange={(e) => set('model', e.target.value)} placeholder="heuristic-v1" />
          </Field>
          <Field label="min confidence" hint="0..1, or a 0..100 percentage">
            <input
              type="number"
              step="0.01"
              value={draft.min_confidence}
              onChange={(e) => set('min_confidence', e.target.value)}
            />
          </Field>
          <Field label="initiator ip">
            <input value={draft.initiator_ip} onChange={(e) => set('initiator_ip', e.target.value)} />
          </Field>
          <Field label="responder ip">
            <input value={draft.responder_ip} onChange={(e) => set('responder_ip', e.target.value)} />
          </Field>
          <Field label="limit" hint="newest N matching flows; 0 = no cap">
            <input type="number" value={draft.limit} onChange={(e) => set('limit', e.target.value)} />
          </Field>
          <label className="src-field row">
            <input
              type="checkbox"
              checked={draft.disagreement}
              onChange={(e) => set('disagreement', e.target.checked)}
            />
            <span>only rows the ensemble disagreed on</span>
          </label>
        </div>

        <div className="src-actions">
          <button type="submit" className="on" disabled={!canSubmit}>
            {busy ? 'working…' : draft.derive_from ? 'Derive dataset' : 'Create dataset'}
          </button>
          <button type="button" disabled={busy} onClick={() => setDraft({ ...EMPTY_DRAFT })}>
            Reset
          </button>
          {msg ? <span className={`src-msg ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</span> : null}
        </div>
        <div className="foot">
          A version is written once and never changed — a correction is a new version with the old
          one in <code>parent_datasets</code>. The daemon refuses a selection that yields no rows,
          only one class, or fewer than {fmtInt(minRows)} rows, and warns in the manifest about class
          imbalance and duplicate rows. Creating and deleting are audited. These endpoints are
          loopback-only and unauthenticated for now (issue&nbsp;#58).
        </div>
      </form>
    </div>
  )
}
