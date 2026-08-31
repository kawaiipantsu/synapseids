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
  FeatureSchema,
  FlowRecord,
  HostProfile,
  ModelInfo,
  TimelineSeries,
  TrainingList,
  TrainingRun,
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

export function getModels(): Promise<ModelInfo[]> {
  return getJSON<ModelInfo[]>('/api/v1/models')
}

export function getFlows(limit = 100): Promise<FlowRecord[]> {
  return getJSON<FlowRecord[]>(`/api/v1/flows?limit=${limit}`)
}

export function getFlow(id: number): Promise<FlowRecord> {
  return getJSON<FlowRecord>(`/api/v1/flows/${id}`)
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
