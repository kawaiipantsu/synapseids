// Thin REST client for /api/v1. Same-origin in production (synapsed serves the
// SPA); the Vite dev server proxies /api to 127.0.0.1:8080. No API contract is
// changed here — these are exactly the endpoints present on origin/develop.

import type {
  CaptureSourceInput,
  CaptureSourceStatus,
  ClassFilterParams,
  Classification,
  ClassSchema,
  DaemonStatus,
  Dataset,
  DatasetCreateInput,
  DatasetList,
  DatasetStats,
  FeatureSchema,
  FlowRecord,
  HostProfile,
  TimelineSeries,
  TrainingList,
  TrainingRun,
  ReportFormat,
} from './types'
import type {
  AuditList,
  AuditQuery,
  ModelDetail,
  ModelEntry,
  ModelLineage,
  ModelList,
} from './types'
import type {
  Review,
  ReviewListResponse,
  ReviewQueueResponse,
  ReviewSort,
  ReviewState,
  ReviewStatsResponse,
  ReviewWriteInput,
} from './types'
// Flow Inspector additions (§19.3, issue #38) — own block, own merge surface.
import type { FlowExplain, FlowSnapshots } from './types'
// Traffic matrix + sensor topology (§19.15, issues #68/#46) — own block.
import type { MatrixSort, SensorStatus, SensorTopology, TrafficMatrix } from './types'
// Detections (§19.1/§19.4, issue #117) — own block, own merge surface.
import type {
  Detection,
  DetectionList,
  DetectionQuery,
  DetectionResult,
  DetectionsResult,
} from './types'

async function getJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { accept: 'application/json' },
    ...init,
  })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`${url} → ${res.status} ${res.statusText}${body ? `: ${body.trim()}` : ''}`)
  }
  return res.json() as Promise<T>
}

export function getStatus(): Promise<DaemonStatus> {
  return getJSON<DaemonStatus>('/api/v1/status')
}

export function getFlows(limit = 100): Promise<FlowRecord[]> {
  return getJSON<FlowRecord[]>(`/api/v1/flows?limit=${limit}`)
}

export function getFlow(id: number): Promise<FlowRecord> {
  return getJSON<FlowRecord>(`/api/v1/flows/${id}`)
}

/**
 * GET /api/v1/flows/{id}/explain — per-model inputs and the verdict's rationale
 * (§19.3, issue #38). A sibling of the flow-detail route rather than part of it,
 * so `getFlow`'s shape is unchanged.
 */
export function getFlowExplain(id: number): Promise<FlowExplain> {
  return getJSON<FlowExplain>(`/api/v1/flows/${id}/explain`)
}

/** GET /api/v1/flows/{id}/snapshots — the retained version history of a flow. */
export function getFlowSnapshots(id: number): Promise<FlowSnapshots> {
  return getJSON<FlowSnapshots>(`/api/v1/flows/${id}/snapshots`)
}

export function getClassifications(limit = 100): Promise<Classification[]> {
  return getJSON<Classification[]>(`/api/v1/classifications?limit=${limit}`)
}

// ---- capture sources (§19.14, issue #32) --------------------------------

export function getCaptures(): Promise<CaptureSourceStatus[]> {
  return getJSON<CaptureSourceStatus[]>('/api/v1/captures')
}

export interface CaptureMutationResult {
  ok: boolean
  /** the new SourceStatus on a 201, else the server's error text */
  message: string
  status: number
  source?: CaptureSourceStatus
}

export async function createCapture(body: CaptureSourceInput): Promise<CaptureMutationResult> {
  const res = await fetch('/api/v1/captures', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = (await res.text().catch(() => '')).trim()
  if (res.ok) {
    let source: CaptureSourceStatus | undefined
    try {
      source = JSON.parse(text) as CaptureSourceStatus
    } catch {
      source = undefined
    }
    return { ok: true, message: 'added', status: res.status, source }
  }
  return { ok: false, message: text || `${res.status} ${res.statusText}`, status: res.status }
}

export async function deleteCapture(name: string): Promise<CaptureMutationResult> {
  const res = await fetch(`/api/v1/captures/${encodeURIComponent(name)}`, { method: 'DELETE' })
  const text = (await res.text().catch(() => '')).trim()
  return {
    ok: res.ok,
    message: res.ok ? 'removed' : text || `${res.status} ${res.statusText}`,
    status: res.status,
  }
}

// ---- datasets (§14, §19.10, issue #33) ----------------------------------

/** The escaped path segment for one dataset version. A dataset id may contain
 *  one "/", so the whole "<id>@<version>" reference is encoded into a single
 *  segment; the daemon's ServeMux unescapes it back intact. */
export function datasetRef(id: string, version: string): string {
  return encodeURIComponent(`${id}@${version}`)
}

export function datasetDownloadURL(id: string, version: string): string {
  return `/api/v1/datasets/${datasetRef(id, version)}/download`
}

export function getDatasets(): Promise<DatasetList> {
  return getJSON<DatasetList>('/api/v1/datasets')
}

/** GET /api/v1/datasets/{ref}/stats — the Dataset Explorer bundle (§19.11,
 *  issues #37/#67). Big but bounded; the daemon caches it per content hash. */
export function getDatasetStats(id: string, version: string): Promise<DatasetStats> {
  return getJSON<DatasetStats>(`/api/v1/datasets/${datasetRef(id, version)}/stats`)
}

export interface DatasetMutationResult {
  ok: boolean
  /** the server's error text verbatim on failure, a short note on success */
  message: string
  status: number
  dataset?: Dataset
}

export async function createDataset(body: DatasetCreateInput): Promise<DatasetMutationResult> {
  const res = await fetch('/api/v1/datasets', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = (await res.text().catch(() => '')).trim()
  if (res.ok) {
    let dataset: Dataset | undefined
    try {
      dataset = (JSON.parse(text) as { dataset: Dataset }).dataset
    } catch {
      dataset = undefined
    }
    return { ok: true, message: 'created', status: res.status, dataset }
  }
  return { ok: false, message: text || `${res.status} ${res.statusText}`, status: res.status }
}

export async function deleteDataset(id: string, version: string): Promise<DatasetMutationResult> {
  const res = await fetch(`/api/v1/datasets/${datasetRef(id, version)}`, { method: 'DELETE' })
  const text = (await res.text().catch(() => '')).trim()
  return {
    ok: res.ok,
    message: res.ok ? 'deleted' : text || `${res.status} ${res.statusText}`,
    status: res.status,
  }
}

// The two frozen schemas never change within a process lifetime; fetch once.
let featureSchemaP: Promise<FeatureSchema> | null = null
export function getFeatureSchema(): Promise<FeatureSchema> {
  return (featureSchemaP ??= getJSON<FeatureSchema>('/api/v1/schemas/features'))
}

let classSchemaP: Promise<ClassSchema> | null = null
export function getClassSchema(): Promise<ClassSchema> {
  return (classSchemaP ??= getJSON<ClassSchema>('/api/v1/schemas/classes'))
}

export interface ReplayStartResult {
  ok: boolean
  message: string
}

export async function startReplay(path: string, speed: string): Promise<ReplayStartResult> {
  const res = await fetch('/api/v1/replay', {
    method: 'POST',
    body: JSON.stringify({ path, speed }),
  })
  const text = (await res.text().catch(() => '')).trim()
  if (res.ok) return { ok: true, message: text || 'accepted' }
  return { ok: false, message: text || `${res.status} ${res.statusText}` }
}

export async function stopReplay(): Promise<ReplayStartResult> {
  const res = await fetch('/api/v1/replay/stop', { method: 'POST' })
  const text = (await res.text().catch(() => '')).trim()
  return { ok: res.ok, message: res.ok ? 'stopped' : text || `${res.status}` }
}

/** POST /api/v1/architecture/estimate — parameter/size/FLOP math + validation
 *  for the ML ▸ Architecture builder. Input/output layers are locked 48/7
 *  server-side regardless of what is sent. */
export interface ArchEstimate {
  valid: boolean
  error?: string
  parameter_count: number
  approx_bytes: number
  rough_flops: number
  layers: { name: string; in: number; out: number; params: number }[]
}

export function estimateArchitecture(arch: unknown): Promise<ArchEstimate> {
  return getJSON<ArchEstimate>('/api/v1/architecture/estimate', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify(arch),
  })
}

// ---- investigation: hosts and timeline (§19.4-6, issues #39/#40/#41) ------

/** Serialise the shared classification filters, dropping unset values. The
 *  parameter names match GET /api/v1/classifications exactly. */
function filterQuery(f: ClassFilterParams = {}): string {
  const q = new URLSearchParams()
  if (f.limit != null) q.set('limit', String(f.limit))
  if (f.class) q.set('class', f.class)
  if (f.model) q.set('model', f.model)
  if (f.min_confidence != null && f.min_confidence > 0) {
    q.set('min_confidence', String(f.min_confidence))
  }
  if (f.disagreement) q.set('disagreement', 'true')
  if (f.from) q.set('from', f.from)
  if (f.to) q.set('to', f.to)
  const s = q.toString()
  return s ? '?' + s : ''
}

export interface HostListParams {
  limit?: number
  /** case-sensitive substring match on the address */
  q?: string
  sort?: 'last_seen' | 'flows' | 'bytes'
}

export function getHosts(p: HostListParams = {}): Promise<HostProfile[]> {
  const q = new URLSearchParams()
  if (p.limit != null) q.set('limit', String(p.limit))
  if (p.q) q.set('q', p.q)
  if (p.sort) q.set('sort', p.sort)
  const s = q.toString()
  return getJSON<HostProfile[]>('/api/v1/hosts' + (s ? '?' + s : ''))
}

export function getHost(ip: string): Promise<HostProfile> {
  return getJSON<HostProfile>('/api/v1/hosts/' + encodeURIComponent(ip))
}

export function getHostFlows(ip: string, f: ClassFilterParams = {}): Promise<FlowRecord[]> {
  return getJSON<FlowRecord[]>('/api/v1/hosts/' + encodeURIComponent(ip) + '/flows' + filterQuery(f))
}

export function getHostClassifications(
  ip: string,
  f: ClassFilterParams = {},
): Promise<Classification[]> {
  return getJSON<Classification[]>(
    '/api/v1/hosts/' + encodeURIComponent(ip) + '/classifications' + filterQuery(f),
  )
}

export type BucketWidth = '1s' | '10s' | '1m'

export interface TimelineParams {
  bucket?: BucketWidth
  from?: string
  to?: string
  class?: string
  host?: string
}

export function getTimeline(p: TimelineParams = {}): Promise<TimelineSeries> {
  const q = new URLSearchParams()
  if (p.bucket) q.set('bucket', p.bucket)
  if (p.from) q.set('from', p.from)
  if (p.to) q.set('to', p.to)
  if (p.class) q.set('class', p.class)
  if (p.host) q.set('host', p.host)
  const s = q.toString()
  return getJSON<TimelineSeries>('/api/v1/timeline' + (s ? '?' + s : ''))
}

// ---- training dashboard (§19.8, issue #35, ADR 0019) --------------------
// Read-only from the SPA: synapse-trainer registers and reports runs over HTTP;
// the SPA polls GET /api/v1/training/{id} while a run is active.

export function getTrainingRuns(limit = 50): Promise<TrainingList> {
  return getJSON<TrainingList>(`/api/v1/training?limit=${limit}`)
}

export function getTrainingRun(id: string): Promise<TrainingRun> {
  return getJSON<TrainingRun>('/api/v1/training/' + encodeURIComponent(id))
}

// ---- model registry, activation and the audit trail ---------------------
// (§19.12, §15, §21, §28.10; issue #36, ADR 0022)
//
// Activation is an explicit operator action and nothing here is called
// implicitly: there is no "register and activate" call, because §28.10 forbids
// a newly trained model going live without a human asking for it. The audit
// read is the only audit call there will ever be — the log is append-only, so
// this client has no way to edit or delete a record.

export function getModels(): Promise<ModelList> {
  return getJSON<ModelList>('/api/v1/models')
}

export function getModel(id: string): Promise<ModelDetail> {
  return getJSON<ModelDetail>('/api/v1/models/' + encodeURIComponent(id))
}

export function getModelLineage(id: string): Promise<ModelLineage> {
  return getJSON<ModelLineage>('/api/v1/models/' + encodeURIComponent(id) + '/lineage')
}

/** The outcome of an activate/deactivate POST. `message` carries the daemon's
 *  error text verbatim so the UI can show a 409 ("bundle no longer validates:
 *  …") exactly as the daemon phrased it, rather than a guess. */
export interface ModelMutationResult {
  ok: boolean
  message: string
  status: number
  entry?: ModelEntry
}

async function modelAction(id: string, action: 'activate' | 'deactivate'): Promise<ModelMutationResult> {
  const res = await fetch(`/api/v1/models/${encodeURIComponent(id)}/${action}`, {
    method: 'POST',
    headers: { accept: 'application/json' },
  })
  const text = (await res.text().catch(() => '')).trim()
  if (!res.ok) {
    return { ok: false, message: text || `${res.status} ${res.statusText}`, status: res.status }
  }
  let entry: ModelEntry | undefined
  try {
    entry = (JSON.parse(text) as { entry: ModelEntry }).entry
  } catch {
    entry = undefined
  }
  return { ok: true, message: action === 'activate' ? 'activated' : 'deactivated', status: res.status, entry }
}

/** Make one registered model the live primary classifier. Call only from an
 *  operator-confirmed action (§28.10). */
export function activateModel(id: string): Promise<ModelMutationResult> {
  return modelAction(id, 'activate')
}

/** Turn a model off and restore the heuristic as primary. */
export function deactivateModel(id: string): Promise<ModelMutationResult> {
  return modelAction(id, 'deactivate')
}

/** GET /api/v1/audit. Read-only and bounded: the daemon clamps `limit` to
 *  max_limit and never scans further back than scan_bytes_cap from the end of
 *  the log. */
export function getAudit(q: AuditQuery = {}): Promise<AuditList> {
  const p = new URLSearchParams()
  if (q.limit) p.set('limit', String(q.limit))
  if (q.subject_type) p.set('subject_type', q.subject_type)
  if (q.subject) p.set('subject', q.subject)
  if (q.event) p.set('event', q.event)
  if (q.from) p.set('from', q.from)
  if (q.to) p.set('to', q.to)
  const s = p.toString()
  return getJSON<AuditList>('/api/v1/audit' + (s ? '?' + s : ''))
}

// ---- human review loop (§16, issues #42 + #64) --------------------------
// The ranked review queue, the review records and the write route. Every
// response carries the model's original prediction next to the human label, and
// no request here can set that prediction — the daemon captures it itself
// (PROJECT.md §16). Sending predicted_class/predicted_score/model_id is a 400.

export interface ReviewQueueParams extends ClassFilterParams {
  sort?: ReviewSort
}

export function getReviewQueue(p: ReviewQueueParams = {}): Promise<ReviewQueueResponse> {
  const q = new URLSearchParams()
  if (p.sort) q.set('sort', p.sort)
  if (p.limit != null) q.set('limit', String(p.limit))
  if (p.class) q.set('class', p.class)
  if (p.model) q.set('model', p.model)
  if (p.min_confidence != null && p.min_confidence > 0) {
    q.set('min_confidence', String(p.min_confidence))
  }
  if (p.disagreement) q.set('disagreement', 'true')
  const s = q.toString()
  return getJSON<ReviewQueueResponse>('/api/v1/review/queue' + (s ? '?' + s : ''))
}

export function getReviews(state?: ReviewState, limit = 500): Promise<ReviewListResponse> {
  const q = new URLSearchParams({ limit: String(limit) })
  if (state) q.set('state', state)
  return getJSON<ReviewListResponse>('/api/v1/review?' + q.toString())
}

export function getReviewStats(): Promise<ReviewStatsResponse> {
  return getJSON<ReviewStatsResponse>('/api/v1/review/stats')
}

/** GET /api/v1/review/{flow_id}. Resolves to null on a 404 — a flow nobody has
 *  reviewed is the normal case, not an error. */
export async function getReview(flowID: number): Promise<Review | null> {
  const res = await fetch(`/api/v1/review/${flowID}`, { headers: { accept: 'application/json' } })
  if (res.status === 404) return null
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`/api/v1/review/${flowID} failed: ${res.status}${body ? ` ${body.trim()}` : ''}`)
  }
  const body = (await res.json()) as { review: Review }
  return body.review
}

export interface ReviewMutationResult {
  ok: boolean
  /** the server's error text verbatim on failure, a short note on success */
  message: string
  status: number
  review?: Review
}

export async function putReview(
  flowID: number,
  body: ReviewWriteInput,
): Promise<ReviewMutationResult> {
  const res = await fetch(`/api/v1/review/${flowID}`, {
    method: 'PUT',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = (await res.text().catch(() => '')).trim()
  if (res.ok) {
    let review: Review | undefined
    try {
      review = (JSON.parse(text) as { review: Review }).review
    } catch {
      review = undefined
    }
    return {
      ok: true,
      message: res.status === 201 ? 'reviewed' : 'updated',
      status: res.status,
      review,
    }
  }
  return { ok: false, message: text || `${res.status} ${res.statusText}`, status: res.status }
}


// ---- downloadable investigation reports (§19.4, issue #66, ADR 0023) -------
// Self-contained block at the end of the file; sibling branches also edit
// client.ts.
//
// Rendering is entirely server-side: these helpers only build the attachment
// URL, and the browser performs the download by navigating to it. There is no
// fetch/Blob dance, so a large HTML report never has to sit in JS memory and the
// Content-Disposition filename the daemon chose is the one the user gets.

export interface ReportParams {
  format: ReportFormat
  /** RFC3339 window bounds — the SPA passes the brushed timeline range here. */
  from?: string
  to?: string
  bucket?: BucketWidth
  /** The same filter dialect as /api/v1/classifications. */
  class?: string
  model?: string
  min_confidence?: number
  disagreement?: boolean
  /** Notable-flow cap; the daemon defaults to 500 and clamps at 2000. */
  limit?: number
}

function reportQuery(p: ReportParams): string {
  const q = new URLSearchParams({ format: p.format })
  if (p.from) q.set('from', p.from)
  if (p.to) q.set('to', p.to)
  if (p.bucket) q.set('bucket', p.bucket)
  if (p.class) q.set('class', p.class)
  if (p.model) q.set('model', p.model)
  if (p.min_confidence != null && p.min_confidence > 0) {
    q.set('min_confidence', String(p.min_confidence))
  }
  if (p.disagreement) q.set('disagreement', 'true')
  if (p.limit != null) q.set('limit', String(p.limit))
  return '?' + q.toString()
}

/**
 * GET /api/v1/reports/host/{ip} — a host investigation report.
 *
 * The address is packet-derived and therefore untrusted (§28.11): it is
 * URL-encoded here and re-parsed with net/netip by the daemon, which answers
 * 400 if it is not an IP literal.
 */
export function hostReportURL(ip: string, p: ReportParams): string {
  return '/api/v1/reports/host/' + encodeURIComponent(ip) + reportQuery(p)
}

/** GET /api/v1/reports/range — a time-window report. */
export function rangeReportURL(p: ReportParams): string {
  return '/api/v1/reports/range' + reportQuery(p)
}


// ---- traffic matrix and sensor topology (§19.15, issues #68 + #46) ----------
// Self-contained block at the end of the file. See ADR 0026.

/**
 * The sensor scope shared by /flows, /classifications and /matrix.
 *
 * Both parameters resolve to the sensor id stored on a classification. Only
 * flow-/feature-mode sensors carry one, so consult a sensor's
 * `flow_attribution` from getSensorTopology() before offering this as a filter —
 * scoping to a raw-mode sensor matches nothing. `location` is matched exactly as
 * the topology response spells it; an unknown location is a 400, not an empty
 * result.
 */
export interface SensorScopeParams {
  sensor?: string
  location?: string
}

export interface MatrixParams extends ClassFilterParams, SensorScopeParams {
  sort?: MatrixSort
}

function scopeInto(q: URLSearchParams, p: SensorScopeParams): void {
  if (p.sensor) q.set('sensor', p.sensor)
  if (p.location) q.set('location', p.location)
}

/**
 * GET /api/v1/matrix — the bounded traffic matrix.
 *
 * Any filter switches the daemon from its incremental table to an on-demand scan
 * of the stored window; the response's `source` says which answered, and
 * `partial`/`truncated` say whether it is the whole picture. Render those flags —
 * a top-N presented as a complete matrix is a lie about the data.
 */
export function getMatrix(p: MatrixParams = {}): Promise<TrafficMatrix> {
  const q = new URLSearchParams()
  if (p.limit != null) q.set('limit', String(p.limit))
  if (p.sort) q.set('sort', p.sort)
  if (p.class) q.set('class', p.class)
  if (p.model) q.set('model', p.model)
  if (p.min_confidence != null && p.min_confidence > 0) {
    q.set('min_confidence', String(p.min_confidence))
  }
  if (p.disagreement) q.set('disagreement', 'true')
  if (p.from) q.set('from', p.from)
  if (p.to) q.set('to', p.to)
  scopeInto(q, p)
  const s = q.toString()
  return getJSON<TrafficMatrix>('/api/v1/matrix' + (s ? '?' + s : ''))
}

/** GET /api/v1/sensors — the flat sensor list. */
export function getSensors(): Promise<SensorStatus[]> {
  return getJSON<SensorStatus[]>('/api/v1/sensors')
}

/**
 * GET /api/v1/sensors/topology — sensors grouped by the location each reported.
 *
 * Never 503s: with no collector wired it returns an empty grouping with
 * `collector: false`, which is deliberately distinguishable from a collector
 * that simply has nobody connected.
 */
export function getSensorTopology(): Promise<SensorTopology> {
  return getJSON<SensorTopology>('/api/v1/sensors/topology')
}

/** GET /api/v1/flows scoped to a sensor or location. */
export function getScopedFlows(p: SensorScopeParams & { limit?: number }): Promise<FlowRecord[]> {
  const q = new URLSearchParams()
  if (p.limit != null) q.set('limit', String(p.limit))
  scopeInto(q, p)
  const s = q.toString()
  return getJSON<FlowRecord[]>('/api/v1/flows' + (s ? '?' + s : ''))
}


// ---- detections / alerts (§19.1, §19.4; issue #117) ------------------------
// Self-contained block at the end of the file.
//
// These are the only two calls in this client that treat a 404 as a *state*
// rather than a failure. The route landed in #117; a daemon predating it — an
// older binary the SPA has no other way to detect — answers 404, and the honest
// render for that is "not available in this build", not a spinner and not a red
// error. Both of those read as "SynapseIDS is broken" instead of "this daemon
// does not have that yet" (PROJECT.md §16).
//
// On a current daemon the list route always answers 200: with no alert store
// configured it returns an empty page, because "no detections" is the honest
// answer there. So `unavailable` and `ok`-with-zero-rows are different facts and
// are rendered differently.
//
// Nothing here invents a detection: `unavailable` carries no rows at all.

/** Serialise the fixed /api/v1/detections query, dropping unset values. */
export function detectionQuery(q: DetectionQuery = {}): string {
  const p = new URLSearchParams()
  if (q.limit != null) p.set('limit', String(q.limit))
  if (q.class) p.set('class', q.class)
  if (q.severity) p.set('severity', q.severity)
  if (q.min_confidence != null && q.min_confidence > 0) {
    p.set('min_confidence', String(q.min_confidence))
  }
  if (q.since) p.set('since', q.since)
  const s = p.toString()
  return s ? '?' + s : ''
}

const DETECTIONS_ABSENT =
  'this daemon has no GET /api/v1/detections route — the detections resource arrived in issue #117, so the binary predates it.'

/** The empty-but-valid list a well-formed response degrades to. */
function normalizeList(body: unknown): DetectionList {
  const b = (body ?? {}) as Partial<DetectionList>
  const rows = Array.isArray(b.detections) ? b.detections : []
  return {
    detections: rows,
    total: Number(b.total ?? rows.length),
    returned: Number(b.returned ?? rows.length),
    evicted: Number(b.evicted ?? 0),
  }
}

/**
 * GET /api/v1/detections. Never rejects: the three outcomes an operator can
 * act on are returned as data.
 */
export async function getDetections(q: DetectionQuery = {}): Promise<DetectionsResult> {
  const url = '/api/v1/detections' + detectionQuery(q)
  let res: Response
  try {
    res = await fetch(url, { headers: { accept: 'application/json' } })
  } catch (e: unknown) {
    return { state: 'error', message: e instanceof Error ? e.message : String(e) }
  }
  if (res.status === 404) return { state: 'unavailable', message: DETECTIONS_ABSENT }
  if (!res.ok) {
    const body = (await res.text().catch(() => '')).trim()
    return {
      state: 'error',
      message: `${url} → ${res.status} ${res.statusText}${body ? `: ${body}` : ''}`,
    }
  }
  try {
    return { state: 'ok', list: normalizeList(await res.json()) }
  } catch (e: unknown) {
    return { state: 'error', message: e instanceof Error ? e.message : String(e) }
  }
}

/** GET /api/v1/detections/{id}. Same three states as the list. */
export async function getDetection(id: number): Promise<DetectionResult> {
  const url = `/api/v1/detections/${id}`
  let res: Response
  try {
    res = await fetch(url, { headers: { accept: 'application/json' } })
  } catch (e: unknown) {
    return { state: 'error', message: e instanceof Error ? e.message : String(e) }
  }
  // A 404 here is ambiguous — no resource, or no such detection — so the
  // message says both rather than picking one.
  if (res.status === 404) {
    return {
      state: 'unavailable',
      message: `no detection ${id}, or ${DETECTIONS_ABSENT}`,
    }
  }
  if (!res.ok) {
    const body = (await res.text().catch(() => '')).trim()
    return {
      state: 'error',
      message: `${url} → ${res.status} ${res.statusText}${body ? `: ${body}` : ''}`,
    }
  }
  try {
    return { state: 'ok', detection: (await res.json()) as Detection }
  } catch (e: unknown) {
    return { state: 'error', message: e instanceof Error ? e.message : String(e) }
  }
}
