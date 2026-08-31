// Thin REST client for /api/v1. Same-origin in production (synapsed serves the
// SPA); the Vite dev server proxies /api to 127.0.0.1:8080. No API contract is
// changed here — these are exactly the endpoints present on origin/develop.

import type {
  CaptureSourceInput,
  CaptureSourceStatus,
  Classification,
  ClassSchema,
  DaemonStatus,
  FeatureSchema,
  FlowRecord,
  ModelInfo,
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
