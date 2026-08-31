// TypeScript mirrors of the Go DTOs served by /api/v1. These follow the JSON
// tags in internal/storage, internal/inference and internal/events on
// origin/develop. Only fields this SPA actually reads are typed exhaustively;
// unknown extra keys from concurrently-evolving endpoints are tolerated.

/** inference.ModelOutput — one model's verdict for one flow. */
export interface ModelOutput {
  model_id: string
  role: string
  class: string
  class_id: number
  score: number
  scores: number[] // length 7, traffic-classes-v1 order
}

/** inference.Result — the ensemble verdict for one flow. */
export interface Result {
  flow_id: number
  class: string
  class_id: number
  score: number
  disagreement: boolean
  models: ModelOutput[]
}

/** storage.Classification — a denormalized rolling-log row. */
export interface Classification {
  flow_id: number
  ts: string
  sensor: string
  proto: string
  initiator_ip: string
  initiator_port: number
  responder_ip: string
  responder_port: number
  result: Result
}

/** features.Vector — one flow-features-v1 sample. */
export interface FeatureVector {
  flow_id: number
  schema: string
  values: number[] // length 48, flow-features-v1 order
}

/** storage.FlowRecord — a stored flow plus its raw feature vector. */
export interface FlowRecord {
  id: number
  proto: string
  initiator_ip: string
  initiator_port: number
  responder_ip: string
  responder_port: number
  first_seen: string
  last_seen: string
  duration_sec: number
  fwd_packets: number
  bwd_packets: number
  fwd_bytes: number
  bwd_bytes: number
  close_reason: string
  snapshot_index: number
  features: FeatureVector
}

export interface ModelInfo {
  id: string
  family: string
  role: string
}

/** api.ReplayStatus */
export interface ReplayStatus {
  running: boolean
  id?: string
  source?: string
  speed?: string
  started?: string
  packets: number
  flows: number
  last_error?: string
}

/**
 * The subset of GET /api/v1/status this SPA depends on. Sibling branches are
 * concurrently reshaping handleStatus, so every access is defensive.
 */
export interface DaemonStatus {
  storage?: { flows?: number; classifications?: number; driver?: string }
  live?: { clients?: number }
  events?: { published?: number; dropped?: number; subscribers?: number }
  replay?: ReplayStatus
  models?: ModelInfo[]
  version?: string
  commit?: string
  uptime_sec?: number
  listen?: string
  loopback?: boolean
  // anything else the daemon adds later
  [k: string]: unknown
}

export interface FeatureSchemaEntry {
  index: number
  name: string
  type: string
  unit: string
  calc: string
  missing: string
  norm: string
}

export interface FeatureSchema {
  schema: string
  version: number
  frozen: boolean
  description: string
  input_size: number
  default_missing: number
  features: FeatureSchemaEntry[]
}

export interface ClassSchemaEntry {
  index: number
  name: string
  description: string
}

export interface ClassSchema {
  schema: string
  version: number
  frozen: boolean
  description: string
  output_size: number
  classes: ClassSchemaEntry[]
}

/** events.Event — the envelope every WebSocket batch element uses. */
export interface WsEvent<T = unknown> {
  type: string
  ts: string
  seq: number
  data: T
}
