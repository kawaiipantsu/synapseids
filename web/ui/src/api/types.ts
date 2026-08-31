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

/** capture.SourceStatus — one row of GET /api/v1/captures (PROJECT.md §19.14). */
export interface CaptureSourceStatus {
  name: string
  kind: string
  /** running | error | stopped */
  state: string
  packets: number
  decoded: number
  decode_errors: number
  bytes: number
  drops: number
  pps: number
  bps: number
  last_packet: string
  filter: string
  error: string
  connection_latency_ms: number
  /** "config" (opened at startup) | "api" (added at runtime) | "" */
  origin: string
}

export type CaptureKind = 'nic' | 'tcpdump' | 'ssh' | 'pcap-over-ip'

/**
 * config.CaptureSource — the POST /api/v1/captures body. Only the fields the
 * add-source form sends are listed; everything is optional on the wire and the
 * server runs the same per-kind validation the config file gets. An inline
 * `token` is deliberately absent: the UI offers `token_file` only (§23).
 */
export interface CaptureSourceInput {
  name: string
  kind: CaptureKind
  interface?: string
  promiscuous?: boolean
  snaplen?: number
  filter?: string
  binary?: string
  destination?: string
  port?: number
  identity_file?: string
  remote_binary?: string
  known_hosts?: string
  addr?: string
  token_file?: string
  server_name?: string
  ca_file?: string
  client_cert_file?: string
  client_key_file?: string
  insecure_tls?: boolean
  authorized?: boolean
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

// ---- investigation: host profiles and the classification timeline -----------
// insight.Profile / insight.Series (PROJECT.md §19.4-6, issues #39/#40/#41).
//
// Every address here is a packet-derived string decoded from the wire. Render it
// as text; never feed it to dangerouslySetInnerHTML or build markup from it.

export interface ProtoCount {
  proto: string
  flows: number
}

export interface PortCount {
  port: number
  flows: number
}

export interface PeerCount {
  ip: string
  flows: number
}

export interface ClassCount {
  class: string
  class_id: number
  count: number
}

/** A pointer back into the flow store; resolve the record with getFlow(). */
export interface HostFlowRef {
  flow_id: number
  ts: string
  proto: string
  peer: string
  port: number
  bytes: number
  class?: string
}

export interface HostProfile {
  ip: string
  first_seen: string
  last_seen: string
  flows: number
  flows_initiated: number
  flows_responded: number
  packets_in: number
  packets_out: number
  bytes_in: number
  bytes_out: number
  protocols: ProtoCount[]
  top_ports: PortCount[]
  /** Detail view only. */
  top_peers?: PeerCount[]
  classifications: number
  classes: ClassCount[]
  disagreements: number
  /** Detail view only. */
  recent_flows?: HostFlowRef[]
  /** Always false in Phase 5 — behavioural baselines are Phase 7. */
  baseline_available: boolean
  /** Always false in Phase 5 — anomaly scoring is Phase 7. */
  anomaly_available: boolean
}

export interface TimelineBucket {
  ts: string
  total: number
  by_class: Record<string, number>
  disagreements: number
}

export interface TimelineSeries {
  bucket_sec: number
  buckets: TimelineBucket[]
  /** Always false in Phase 5 — there is no anomaly series to plot yet. */
  anomaly_available: boolean
}

/** Filters shared by /api/v1/classifications and the per-host collections. */
export interface ClassFilterParams {
  class?: string
  model?: string
  min_confidence?: number
  disagreement?: boolean
  from?: string
  to?: string
  limit?: number
}

// ---- datasets (PROJECT.md §14, §19.10; issue #33) ------------------------

/** dataset.TimeRange — RFC3339 UTC, "" when the dataset is empty of times. */
export interface DatasetTimeRange {
  from: string
  to: string
}

/** dataset.Selection — the predicates that picked a dataset's rows. The four
 *  that also exist on GET /api/v1/classifications (class, model,
 *  min_confidence, disagreement) mean exactly the same thing there. */
export interface DatasetSelection {
  from?: string
  to?: string
  class?: string
  model?: string
  proto?: string
  initiator_ip?: string
  responder_ip?: string
  min_confidence?: number
  disagreement?: boolean
  limit?: number
  scan?: number
}

/** dataset.Dataset — the §14 manifest plus where it lives on disk. */
export interface Dataset {
  id: string
  version: string
  name: string
  description: string
  location: string
  tags: string[]
  created_at: string
  source_capture_ids: string[]
  time_range: DatasetTimeRange
  feature_schema: string
  output_schema: string
  flow_count: number
  label_counts: Record<string, number>
  /** "model_prediction:<model ids>" today. "human_review" becomes possible
   *  when the review loop (issue #42) lands — see the banner on the page. */
  labeling_source: string
  parent_datasets: string[]
  /** "sha256:<lowercase hex>" over the schema identity + the CSV bytes. */
  content_hash: string
  selection: DatasetSelection
  warnings?: string[]
  csv_file: string
  csv_bytes: number
  feature_count: number
  columns: string[]
  dir: string
}

/** GET /api/v1/datasets */
export interface DatasetList {
  datasets: Dataset[]
  /** the 48 feature column names + "label", in frozen schema order */
  columns: string[]
  label_column: string
  min_rows: number
}

/** POST /api/v1/datasets body. */
export interface DatasetCreateInput {
  id: string
  version?: string
  name?: string
  description?: string
  location?: string
  tags?: string[]
  source_capture_ids?: string[]
  /** "<id>@<version>" — records that dataset in parent_datasets. */
  derive_from?: string
  selection: DatasetSelection
}

// =======================================================================
// Dataset Explorer (PROJECT.md §19.11; issues #37, #67) — feature/dataset-explorer
// -----------------------------------------------------------------------
// Mirrors internal/dataset/stats.go, served by GET /api/v1/datasets/{ref}/stats.
// This block is owned by the dataset-explorer branch; keep sibling additions to
// their own clearly-marked blocks so the merges stay clean.
// =======================================================================

/** One feature's distribution over a materialised dataset's rows. */
export interface DatasetFeatureStats {
  index: number
  name: string
  unit: string
  norm: string
  min: number
  max: number
  mean: number
  stddev: number
  p25: number
  p50: number
  p75: number
  /** every row holds the same value (min === max); the histogram is empty */
  degenerate: boolean
  /** histogram edges are log1p-spaced (norm hint "log1p", all values >= 0) */
  log_scale: boolean
  /** length 25, or null when degenerate */
  bin_edges: number[] | null
  /** length 24, or null when degenerate */
  bin_counts: number[] | null
}

/** Row counts per traffic-classes-v1 class, in frozen schema order. */
export interface DatasetLabelDistribution {
  classes: string[]
  counts: number[]
  fractions: number[]
  total: number
  /** labels in the CSV that are not traffic-classes-v1 classes */
  unknown?: Record<string, number>
  /** the CSV's per-class counts disagree with the manifest's label_counts */
  manifest_mismatch: boolean
}

/** The 48×48 Pearson matrix, row-major: matrix[i*size + j] = corr(i, j). */
export interface DatasetCorrelation {
  names: string[]
  size: number
  matrix: number[]
}

export interface DatasetPortCount {
  port: number
  count: number
}

export interface DatasetPortStats {
  top_destination: DatasetPortCount[]
  top_source: DatasetPortCount[]
  distinct_destination: number
  distinct_source: number
}

export interface DatasetProtocolStats {
  tcp: number
  udp: number
  icmp: number
  other: number
}

export interface DatasetOutlierFeature {
  index: number
  name: string
  value: number
  z: number
}

/** A flagged row. `row` is its 0-based index into dataset.csv (no flow-id
 *  column exists), which is ordered by flow id. */
export interface DatasetOutlier {
  row: number
  label: string
  max_z: number
  features: DatasetOutlierFeature[]
}

export interface DatasetOutlierReport {
  rule: string
  threshold: number
  count: number
  cap: number
  rows: DatasetOutlier[]
}

export interface DatasetPCAPoint {
  pc1: number
  pc2: number
  pc3: number
  label: string
  row: number
}

export interface DatasetPCA {
  components: number
  /** loadings[k] is the k-th eigenvector in standardised space, length 48 */
  loadings: number[][]
  /** eigenvalue_k / trace, the variance share on component k */
  explained_variance: number[]
  eigenvalues_total: number
  jacobi_sweeps: number
  projection: DatasetPCAPoint[]
  projection_sampled: boolean
  projection_cap: number
}

/** GET /api/v1/datasets/{ref}/stats */
export interface DatasetStats {
  ref: string
  content_hash: string
  feature_schema: string
  output_schema: string
  row_count: number
  feature_count: number
  feature_stats: DatasetFeatureStats[]
  label_distribution: DatasetLabelDistribution
  correlation: DatasetCorrelation
  ports: DatasetPortStats
  protocols: DatasetProtocolStats
  outliers: DatasetOutlierReport
  pca: DatasetPCA
}


// ============================================================================
// Training dashboard (§19.8, issue #35, ADR 0019)
// -------------------------------------------------
// A training run is an external synapse-trainer process that reports progress
// to the daemon over HTTP. The SPA polls GET /api/v1/training/{id}. This block
// is self-contained — a sibling branch also edits this file; keep additions here.
// ============================================================================

export type TrainingStatus = 'running' | 'completed' | 'failed' | 'stale'

/** One per-epoch progress dict, stored and served verbatim by the daemon.
 *  Every field is optional: the trainer owns this shape and may add to it. */
export interface TrainingEpoch {
  event?: string
  status?: string
  epoch?: number
  epochs?: number
  batches?: number
  batches_total?: number
  train_loss?: number
  val_loss?: number
  accuracy?: number
  val_accuracy?: number
  val_macro_precision?: number
  val_macro_recall?: number
  val_macro_f1?: number
  lr?: number
  elapsed_s?: number
  device?: string
  [k: string]: unknown
}

export interface TrainingPerClass {
  class: string
  precision: number
  recall: number
  f1: number
  support: number
}

/** The terminal "done" metrics block (pass-through). */
export interface TrainingFinal {
  accuracy?: number
  macro_precision?: number
  macro_recall?: number
  macro_f1?: number
  train_loss?: number
  val_loss?: number
  test_loss?: number
  epochs_run?: number
  parameter_count?: number
  elapsed_s?: number
  device?: string
  per_class?: TrainingPerClass[]
  confusion?: number[][]
  test?: {
    accuracy?: number
    macro_precision?: number
    macro_recall?: number
    macro_f1?: number
    loss?: number
    per_class?: TrainingPerClass[]
    confusion?: number[][]
  }
  [k: string]: unknown
}

/** training.Run — GET /api/v1/training/{id}. */
export interface TrainingRun {
  id: string
  name: string
  status: TrainingStatus
  recipe?: unknown
  started_at: string
  updated_at: string
  finished_at?: string
  trainer_version?: string
  epochs_total: number
  epoch: number
  history: TrainingEpoch[]
  final?: TrainingFinal
  fail_reason?: string
}

/** GET /api/v1/training */
export interface TrainingList {
  runs: TrainingRun[]
  history_cap: number
  stale_after_seconds: number
}

// ---------------------------------------------------------------------------
// Downloadable investigation reports (issue #66, ADR 0023).
//
// Self-contained block, appended at the end of the file on purpose: several
// sibling branches also edit types.ts, and keeping this addition isolated makes
// a merge a concatenation rather than a conflict.
//
// The SPA never renders a report itself — rendering is server-side, and the
// download is a plain browser navigation to the attachment URL. These types
// exist so the query builder in api/client.ts is typed, and so a future view
// that wants to preview a report's coverage block has something to read.
// ---------------------------------------------------------------------------

/** report.ScopeKind — what a report is about. */
export type ReportScopeKind = 'host' | 'range'

/** The two rendering formats GET /api/v1/reports/* accepts. */
export type ReportFormat = 'json' | 'html'

/** report.Scope — exactly what was asked for. */
export interface ReportScope {
  kind: ReportScopeKind
  host?: string
  from?: string
  to?: string
  unbounded: boolean
  filter?: string
}

/** report.Note — one explicit statement about what the report does not know. */
export interface ReportNote {
  code: string
  level: 'info' | 'warning'
  text: string
}

/**
 * report.Coverage — every limit that applied and every discard the daemon had
 * already made. `partial` is the single flag a consumer can branch on.
 */
export interface ReportCoverage {
  partial: boolean
  store_driver: string
  flows_retained: number
  flows_evicted: number
  classifications_retained: number
  classifications_evicted: number
  scan_limit: number
  scan_scanned: number
  scan_exhausted: boolean
  oldest_retained?: string
  range_starts_before_retention: boolean
  hosts_tracked: number
  host_cap: number
  hosts_evicted: number
  key_cap: number
  keys_pruned: number
  observations_dropped: number
  timeline_late: number
  notable_flow_cap: number
  notable_candidates: number
  notable_flows_truncated: boolean
  flow_records_missing: number
  /** Always false in this build — behavioural baselines are Phase 7. */
  baseline_available: boolean
  /** Always false in this build — anomaly scoring is Phase 7. */
  anomaly_available: boolean
}

/** report.Report — the JSON artefact, for reference by any future consumer. */
export interface InvestigationReport {
  schema: string
  generated_at: string
  generator: {
    product: string
    version: string
    commit: string
    built_at: string
    dirty: boolean
    feature_schema: string
    output_schema: string
  }
  scope: ReportScope
  coverage: ReportCoverage
  notes: ReportNote[]
  summary: {
    classifications: number
    disagreements: number
    non_normal: number
    distinct_flows: number
    distinct_hosts: number
    first_verdict?: string
    last_verdict?: string
  }
  [k: string]: unknown
}
