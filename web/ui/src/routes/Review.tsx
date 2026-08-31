import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { getReviewQueue, getReviews, putReview } from '../api/client'
import type {
  Review,
  ReviewQueueItem,
  ReviewSort,
  ReviewState,
  ReviewStats,
  ReviewWriteInput,
} from '../api/types'
import { REVIEW_STATES } from '../api/types'
import { CLASS_NAMES, classColor } from '../lib/classes'
import { endpoint, fmtAgo, fmtClock, fmtInt, fmtPct } from '../lib/format'
import { usePersistedState, writePersisted } from '../lib/persist'
import { DATASETS_DRAFT_KEY, EMPTY_DRAFT } from './Datasets'

// LIVE ▸ Review — the human review loop (PROJECT.md §16; issues #42 and #64).
//
// The invariant this whole view is built around: the model's prediction is shown
// *next to* the human's label, never replaced by it. Every row has a "model
// says" column and a "human says" column, and they stay side by side after a
// correction. The daemon enforces it structurally (internal/review); this page's
// job is to make it impossible to misread.
//
// The queue is ranked. `uncertainty` is the active-learning order issue #64 asks
// for: smallest top1-top2 margin first, so the flows the model is least able to
// settle reach the operator first. `disagreement` leads with the flows the
// ensemble could not agree on. `recent` is plain newest-first.
//
// Note this is NOT #/detections, which stays a Phase-5 placeholder: there is no
// detections store and nothing emits AlertCreated yet.

const POLL_MS = 5000
const QUEUE_LIMIT = 200

const SORTS: { value: ReviewSort; label: string; hint: string }[] = [
  {
    value: 'uncertainty',
    label: 'uncertainty',
    hint: 'least-confident first — smallest gap between the top two classes (active learning, issue #64)',
  },
  { value: 'recent', label: 'recent', hint: 'newest verdict first' },
  {
    value: 'disagreement',
    label: 'disagreement',
    hint: 'flows the ensemble disagreed on first, then by uncertainty',
  },
]

/** The states an operator can assign, in the order the buttons appear. The
 *  §16 enum minus nothing: `unreviewed` is offered last as "un-review", which is
 *  how a decision is put back in the queue without losing its history. */
const ASSIGNABLE: { state: ReviewState; label: string; hint: string }[] = [
  { state: 'correct', label: 'correct', hint: 'the model was right — the label is the prediction it made' },
  { state: 'incorrect', label: 'incorrect', hint: 'the model was wrong — pick the right class' },
  { state: 'unsure', label: 'unsure', hint: 'you cannot tell; the flow stays in the queue' },
  {
    state: 'ignored_pattern',
    label: 'ignore pattern',
    hint: 'stop showing me this — leaves the queue, and is excluded from curated datasets by default',
  },
  { state: 'unreviewed', label: 'un-review', hint: 'clear the decision and put the flow back in the queue' },
]

// ---- small presentational pieces ----------------------------------------

function ClassPill({ name, title }: { name: string; title?: string }) {
  if (!name) return <span className="dim">—</span>
  return (
    <span className="rv-pill" style={{ background: classColor(name) }} title={title}>
      {name.toUpperCase()}
    </span>
  )
}

function StatePill({ state }: { state: ReviewState }) {
  return <span className={`rv-state rv-${state}`}>{state.replace('_', ' ')}</span>
}

/** The uncertainty read-out: the margin, the two classes fighting over it, and
 *  the entropy. Only shown when the queue is sorted by uncertainty, where it is
 *  the reason a row is where it is. */
function Uncertainty({ it }: { it: ReviewQueueItem }) {
  if (!it.scores_available) {
    return (
      <span className="rv-unc none" title="this verdict carried no probability vector, so the model's confidence is unknown — treated as maximally uncertain">
        no vector
      </span>
    )
  }
  return (
    <span className="rv-unc" title={`margin = p(${it.top1}) - p(${it.top2}) = ${it.margin.toFixed(4)}; normalised entropy ${it.entropy.toFixed(3)}`}>
      <span className="rv-unc-bar">
        <span className="fill" style={{ width: `${Math.round(it.uncertainty * 100)}%` }} />
      </span>
      <span className="mono">{fmtPct(it.uncertainty, 0)}</span>
      <span className="dim">
        {' '}
        margin {it.margin.toFixed(3)} · H {it.entropy.toFixed(2)}
      </span>
      {it.top2 ? (
        <div className="dim rv-unc-pair">
          {it.top1} vs {it.top2}
        </div>
      ) : null}
    </span>
  )
}

/** "model says X @ 97%" — the prediction, always visible. */
function ModelSays({
  cls,
  score,
  modelID,
  disagreement,
}: {
  cls: string
  score: number
  modelID: string
  disagreement?: boolean
}) {
  return (
    <span className="rv-model">
      <ClassPill name={cls} title={`the model's prediction — never overwritten by a review (§16)`} />
      <span className="mono"> {fmtPct(score)}</span>
      <div className="dim">{modelID || '—'}</div>
      {disagreement ? <div className="rv-dis">ensemble disagreement</div> : null}
    </span>
  )
}

// ---- the per-row review controls ----------------------------------------

interface RowControlsProps {
  flowID: number
  predicted: string
  current: Review | null
  busy: boolean
  onSubmit: (flowID: number, body: ReviewWriteInput) => void
}

function RowControls({ flowID, predicted, current, busy, onSubmit }: RowControlsProps) {
  const [label, setLabel] = useState(() => current?.human_label ?? '')
  const [note, setNote] = useState(() => current?.note ?? '')
  const [pending, setPending] = useState<ReviewState | null>(null)

  // A class picker only appears for `incorrect`, and it must not offer the class
  // the model already picked — agreeing with the model is `correct`.
  const options = useMemo(() => CLASS_NAMES.filter((c) => c !== predicted), [predicted])

  const send = (state: ReviewState) => {
    const body: ReviewWriteInput = { state }
    if (state === 'incorrect') body.human_label = label || options[0] || ''
    if (note.trim()) body.note = note.trim()
    setPending(state)
    onSubmit(flowID, body)
  }

  return (
    <div className="rv-controls">
      <div className="rv-buttons">
        {ASSIGNABLE.map((a) => {
          const active = current?.state === a.state
          const needsLabel = a.state === 'incorrect' && pending !== 'incorrect' && label === ''
          return (
            <button
              key={a.state}
              className={`rv-btn rv-btn-${a.state}${active ? ' on' : ''}`}
              disabled={busy}
              title={needsLabel ? `${a.hint} (defaults to ${options[0]})` : a.hint}
              onClick={() => send(a.state)}
            >
              {a.label}
            </button>
          )
        })}
      </div>
      <div className="rv-inputs">
        <label>
          <span className="dim">corrected class</span>
          <select
            value={label}
            disabled={busy}
            onChange={(e) => setLabel(e.target.value)}
            title="the class this flow really is — required for “incorrect”"
          >
            <option value="">(pick a class)</option>
            {options.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <label className="rv-note">
          <span className="dim">note</span>
          <input
            type="text"
            value={note}
            disabled={busy}
            placeholder="why — for whoever reads this next"
            onChange={(e) => setNote(e.target.value)}
          />
        </label>
      </div>
    </div>
  )
}

// ---- the stats strip -----------------------------------------------------

function StatsStrip({ stats }: { stats: ReviewStats | null }) {
  const n = (k: string) => stats?.by_state[k] ?? 0
  return (
    <div className="cards rv-cards">
      {REVIEW_STATES.map((s) => (
        <div className={`card rv-card rv-card-${s}`} key={s}>
          <h3>{s.replace('_', ' ')}</h3>
          <div className="big">{fmtInt(n(s))}</div>
          <div className="foot">
            {s === 'correct'
              ? 'prediction confirmed'
              : s === 'incorrect'
                ? 'prediction corrected'
                : s === 'unsure'
                  ? 'still in the queue'
                  : s === 'ignored_pattern'
                    ? 'muted, not a class claim'
                    : 'explicitly un-reviewed'}
          </div>
        </div>
      ))}
      <div className="card rv-card rv-card-total">
        <h3>usable for training</h3>
        <div className="big">{fmtInt(stats?.labelled ?? 0)}</div>
        <div className="foot">
          correct + incorrect, of {fmtInt(stats?.total ?? 0)} review(s)
        </div>
      </div>
    </div>
  )
}

// ---- the page ------------------------------------------------------------

export function ReviewQueue() {
  const [sort, setSort] = usePersistedState<ReviewSort>('review.sort', 'uncertainty')
  const [onlyDisagree, setOnlyDisagree] = usePersistedState('review.disagreement', false)
  const [fClass, setFClass] = usePersistedState('review.class', '')
  const [fMinConf, setFMinConf] = usePersistedState('review.minConf', 0)

  const [queue, setQueue] = useState<ReviewQueueItem[]>([])
  const [scanned, setScanned] = useState(0)
  const [reviews, setReviews] = useState<Review[]>([])
  const [stats, setStats] = useState<ReviewStats | null>(null)
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [now, setNow] = useState(() => Date.now())

  const load = useCallback(() => {
    Promise.all([
      getReviewQueue({
        sort,
        limit: QUEUE_LIMIT,
        class: fClass || undefined,
        min_confidence: fMinConf > 0 ? fMinConf : undefined,
        disagreement: onlyDisagree || undefined,
      }),
      getReviews(undefined, 500),
    ])
      .then(([q, l]) => {
        setQueue(q.queue ?? [])
        setScanned(q.scanned ?? 0)
        setReviews(l.reviews ?? [])
        setStats(l.stats ?? null)
        setLoadErr(null)
      })
      .catch((e: unknown) => setLoadErr(e instanceof Error ? e.message : String(e)))
  }, [sort, fClass, fMinConf, onlyDisagree])

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
  // Re-fetch immediately when a filter or the sort changes.
  useEffect(() => {
    load()
  }, [load])

  const byFlow = useMemo(() => {
    const m = new Map<number, Review>()
    for (const r of reviews) m.set(r.flow_id, r)
    return m
  }, [reviews])

  const submit = useCallback(
    async (flowID: number, body: ReviewWriteInput) => {
      setBusy(true)
      setMsg(null)
      const r = await putReview(flowID, body)
      setBusy(false)
      if (r.ok && r.review) {
        const rec = r.review
        setMsg({
          ok: true,
          text:
            `flow ${flowID} → ${rec.state}` +
            (rec.effective_label ? ` (${rec.effective_label})` : '') +
            ` · the model still says ${rec.predicted_class} @ ${fmtPct(rec.predicted_score)}`,
        })
      } else {
        setMsg({ ok: false, text: `flow ${flowID}: ${r.status} ${r.message}` })
      }
      load()
    },
    [load],
  )

  /** Prefill the ML ▸ Datasets create form with a curated `reviewed` cut and
   *  send the operator there. The draft lives in localStorage, which is where
   *  the Datasets form reads it on mount. */
  const cutCuratedDataset = () => {
    const stamp = new Date().toISOString().slice(0, 10)
    writePersisted(DATASETS_DRAFT_KEY, {
      ...EMPTY_DRAFT,
      id: `reviewed/curated-${stamp}`,
      name: `Human-reviewed flows, ${stamp}`,
      description: `Curated from ${fmtInt(stats?.labelled ?? 0)} human review decision(s) — labels are the operator's, not the model's.`,
      tags: 'curated, human-review',
      reviewed: true,
    })
    window.location.hash = '#/datasets'
  }

  const eligible = stats?.labelled ?? 0

  return (
    <div className="rv">
      <div className="page-h">
        <h1>Review</h1>
        <span className="sub">
          the human review loop — <code>GET /api/v1/review/queue</code>,{' '}
          <code>PUT /api/v1/review/&#123;flow_id&#125;</code> (§16, issues&nbsp;#42 and&nbsp;#64).
          Reviewed flows become a curated dataset in <a href="#/datasets">ML ▸ Datasets</a>.
        </span>
      </div>

      <div className="arch-warn rv-honesty">
        <b>The model&rsquo;s prediction is kept, always.</b> Confirming or correcting a verdict never
        overwrites it: each review stores <code>predicted_class</code>,{' '}
        <code>predicted_score</code> and <code>model_id</code> as they were at review time, right
        next to your label, and the daemon has no code path that could change them (PROJECT.md §16).
        That is what makes a curated dataset honest — and what lets you measure the model against
        the humans later.
      </div>

      {loadErr ? <div className="src-msg err">review API unavailable — {loadErr}</div> : null}

      <StatsStrip stats={stats} />

      <div className="card wide rv-bar">
        <label>
          sort
          <select value={sort} onChange={(e) => setSort(e.target.value as ReviewSort)}>
            {SORTS.map((s) => (
              <option key={s.value} value={s.value} title={s.hint}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
        <span className="dim rv-sorthint">{SORTS.find((s) => s.value === sort)?.hint}</span>
        <span className="spacer" />
        <label>
          class
          <select value={fClass} onChange={(e) => setFClass(e.target.value)}>
            <option value="">all</option>
            {CLASS_NAMES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <label>
          min&nbsp;conf
          <input
            type="number"
            min={0}
            max={100}
            step={5}
            value={fMinConf}
            onChange={(e) => setFMinConf(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
          />
        </label>
        <label className="rv-check">
          <input
            type="checkbox"
            checked={onlyDisagree}
            onChange={(e) => setOnlyDisagree(e.target.checked)}
          />
          only ensemble disagreements
        </label>
        <button
          className="on rv-cut"
          disabled={eligible === 0}
          title={
            eligible === 0
              ? 'review some flows first — a curated dataset needs at least one confirmed or corrected label'
              : `prefill the dataset form with a reviewed cut over ${eligible} human decision(s)`
          }
          onClick={cutCuratedDataset}
        >
          Create curated dataset ({fmtInt(eligible)})
        </button>
      </div>

      {msg ? <div className={`src-msg ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</div> : null}

      <div className="card wide">
        <h3>
          Queue ({queue.length}){' '}
          <span className="dim">
            — flows still needing a human, out of {fmtInt(scanned)} stored verdict(s) scanned.
            A <code>correct</code>, <code>incorrect</code> or <code>ignored_pattern</code> decision
            leaves the queue; <code>unsure</code> stays.
          </span>
        </h3>
        {queue.length === 0 ? (
          <div className="foot">
            nothing to review — replay or capture some traffic, or loosen the filters above.
          </div>
        ) : (
          <div className="src-scroll">
            <table className="mini src-table rv-table">
              <thead>
                <tr>
                  <th>flow</th>
                  <th>tuple</th>
                  <th>model says</th>
                  {sort === 'uncertainty' ? <th>uncertainty</th> : null}
                  <th>human says</th>
                  <th>review</th>
                </tr>
              </thead>
              <tbody>
                {queue.map((it) => {
                  const cur = byFlow.get(it.flow_id) ?? null
                  return (
                    <tr key={it.flow_id} className={it.disagreement ? 'rv-row-dis' : ''}>
                      <td>
                        <b>#{it.flow_id}</b>
                        <div className="dim" title={it.ts}>
                          {fmtClock(it.ts)}
                        </div>
                        <div className="dim">{it.sensor || '—'}</div>
                      </td>
                      <td className="mono rv-tuple">
                        {endpoint(it.initiator_ip, it.initiator_port)}
                        <div className="dim">→ {endpoint(it.responder_ip, it.responder_port)}</div>
                        <div className="dim">{it.proto}</div>
                      </td>
                      <td>
                        <ModelSays
                          cls={it.predicted_class}
                          score={it.predicted_score}
                          modelID={it.model_id}
                          disagreement={it.disagreement}
                        />
                      </td>
                      {sort === 'uncertainty' ? (
                        <td className="rv-unccell">
                          <Uncertainty it={it} />
                        </td>
                      ) : null}
                      <td className="rv-human">
                        {cur ? (
                          <>
                            <StatePill state={cur.state} />
                            <div>
                              <ClassPill name={cur.effective_label} />
                            </div>
                            {cur.note ? <div className="dim rv-notetext">{cur.note}</div> : null}
                          </>
                        ) : (
                          <>
                            <StatePill state={it.review_state} />
                            {it.note ? <div className="dim rv-notetext">{it.note}</div> : null}
                          </>
                        )}
                      </td>
                      <td className="rv-ctlcell">
                        <RowControls
                          flowID={it.flow_id}
                          predicted={it.predicted_class}
                          current={cur}
                          busy={busy}
                          onSubmit={submit}
                        />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card wide">
        <h3>
          Decisions ({reviews.length}){' '}
          <span className="dim">— most recently reviewed first. The two right-hand columns never merge.</span>
        </h3>
        {reviews.length === 0 ? (
          <div className="foot">
            no reviews yet. Each one lands in <code>review.directory</code> as one JSON file per
            flow, and is written to the audit log (§21).
          </div>
        ) : (
          <div className="src-scroll">
            <table className="mini src-table rv-table rv-decisions">
              <thead>
                <tr>
                  <th>flow</th>
                  <th>state</th>
                  <th>model said</th>
                  <th>human said</th>
                  <th>note</th>
                  <th>revisions</th>
                  <th>updated</th>
                </tr>
              </thead>
              <tbody>
                {reviews.map((r) => (
                  <tr key={r.flow_id}>
                    <td>
                      <b>#{r.flow_id}</b>
                    </td>
                    <td>
                      <StatePill state={r.state} />
                    </td>
                    <td>
                      <ClassPill name={r.predicted_class} title="frozen at review time (§16)" />
                      <span className="mono"> {fmtPct(r.predicted_score)}</span>
                      <div className="dim">{r.model_id || '—'}</div>
                    </td>
                    <td>
                      <ClassPill name={r.effective_label} />
                      {r.effective_label && r.effective_label === r.predicted_class ? (
                        <div className="dim">agrees</div>
                      ) : r.effective_label ? (
                        <div className="rv-dis">disagrees</div>
                      ) : null}
                    </td>
                    <td className="rv-notetext">{r.note || <span className="dim">—</span>}</td>
                    <td className="num" title={r.history.map((h) => `${h.ts}: ${h.state}`).join('\n')}>
                      {r.history.length}
                    </td>
                    <td title={r.updated_at}>{fmtAgo(r.updated_at, now)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="foot">
          <code>correct</code> means the label <i>is</i> the prediction, so it needs no class.{' '}
          <code>incorrect</code> requires one, and it must differ from the prediction.{' '}
          <code>unsure</code> and <code>ignored_pattern</code> assert no class at all. These routes
          are loopback-only and unauthenticated for now (issue&nbsp;#58); every write is audited.
        </div>
      </div>
    </div>
  )
}
