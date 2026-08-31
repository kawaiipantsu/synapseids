import type { ReactNode } from 'react'

import { Placeholder } from '../components/Placeholder'
import { Architecture } from './Architecture'
import { CaptureSources } from './CaptureSources'
import { Dashboard } from './Dashboard'
import { Datasets } from './Datasets'
import { FlowLog } from './FlowLog'
import { ReplayPage } from './ReplayPage'

export type NavGroup = 'LIVE' | 'CAPTURE' | 'ML' | 'SYSTEM'

export interface RouteDef {
  path: string
  label: string
  group: NavGroup
  element: ReactNode
  /** Short sidebar tag: "live" for wired views, "P{n}" for a stubbed phase. */
  tag: string
  live: boolean
}

const P = (phase: number, title: string, epic: string, note?: string) => (
  <Placeholder title={title} phase={phase} epic={epic} note={note} />
)

// Navigation tree from PROJECT.md §19. Order here is the sidebar order.
export const ROUTES: RouteDef[] = [
  // ---- LIVE -------------------------------------------------------------
  { group: 'LIVE', path: '/dashboard', label: 'Dashboard', tag: 'live', live: true, element: <Dashboard /> },
  { group: 'LIVE', path: '/flow-log', label: 'Flow Log', tag: 'live', live: true, element: <FlowLog /> },
  {
    group: 'LIVE',
    path: '/investigate',
    label: 'Investigate',
    tag: 'P5',
    live: false,
    element: P(5, 'Investigate', 'EPIC: Phase 5 — Investigation', 'Host-pivot view (§19.4): live flows, classification history, baselines and related detections for a selected entity.'),
  },
  {
    group: 'LIVE',
    path: '/hosts',
    label: 'Hosts',
    tag: 'P5',
    live: false,
    element: P(5, 'Hosts', 'EPIC: Phase 5 — Investigation', 'Observed host profiles (§19.5): first/last seen, traffic volume, common peers/ports, baseline behaviour and anomaly trend.'),
  },
  {
    group: 'LIVE',
    path: '/detections',
    label: 'Detections',
    tag: 'P5',
    live: false,
    element: P(5, 'Detections', 'EPIC: Phase 5 — Investigation', 'Alert/detection feed. Needs an /api/v1/detections resource group — nothing emits AlertCreated events yet.'),
  },

  // ---- CAPTURE --------------------------------------------------------
  {
    group: 'CAPTURE',
    path: '/sources',
    label: 'Sources',
    tag: 'live',
    live: true,
    element: <CaptureSources />,
  },
  {
    group: 'CAPTURE',
    path: '/sensors',
    label: 'Sensors',
    tag: 'P6',
    live: false,
    element: P(6, 'Sensor Topology', 'EPIC: Phase 6 — Distributed Sensors', 'Sensors grouped by location/environment (§19.15); clicking a location scopes the other views.'),
  },
  { group: 'CAPTURE', path: '/replay', label: 'Replay', tag: 'live', live: true, element: <ReplayPage /> },

  // ---- ML ------------------------------------------------------------
  {
    group: 'ML',
    path: '/models',
    label: 'Models',
    tag: 'P2',
    live: false,
    element: P(2, 'Model Registry', 'EPIC: Phase 2 — Real Inference', 'Loaded models are listed on the Dashboard today. The registry (§19.12) — schema, architecture, datasets, lineage, metrics, confusion matrices — arrives with trained ONNX models.'),
  },
  {
    group: 'ML',
    path: '/training',
    label: 'Training',
    tag: 'P4',
    live: false,
    element: P(4, 'Training', 'EPIC: Phase 4 — Dataset/Training Workflow', 'Live training dashboard (§19.8): epoch/loss/accuracy/F1, per-class metrics and confusion matrix, updated over the event bus.'),
  },
  // The Dataset Manager (§19.10) is live. The Dataset Explorer (§19.11 —
  // feature distributions, correlations, PCA) is issue #37 and is not here.
  { group: 'ML', path: '/datasets', label: 'Datasets', tag: 'live', live: true, element: <Datasets /> },
  {
    group: 'ML',
    path: '/architecture',
    label: 'Architecture',
    tag: 'live',
    live: true,
    element: <Architecture />,
  },
  {
    group: 'ML',
    path: '/model-compare',
    label: 'Model Compare',
    tag: 'P7',
    live: false,
    element: P(7, 'Model Comparison', 'EPIC: Phase 7 — Advanced ML', 'Side-by-side evaluation of compatible models (§19.7): predictions, confidence, disagreement, latency and confusion matrices.'),
  },
  {
    group: 'ML',
    path: '/drift',
    label: 'Drift',
    tag: 'P7',
    live: false,
    element: P(7, 'Drift', 'EPIC: Phase 7 — Advanced ML', 'Per-feature comparison of current traffic against a model’s training distribution (§19.13). Informational only.'),
  },

  // ---- SYSTEM ------------------------------------------------------
  {
    group: 'SYSTEM',
    path: '/performance',
    label: 'Performance',
    tag: 'P7',
    live: false,
    element: P(7, 'System Performance', 'EPIC: Phase 7 — Advanced ML', 'Full §19.16 board: CPU/memory/goroutines, decode and inference latency percentiles, queue depth, DB latency. A few counters (WS clients, event queue) are already on /api/v1/status; the rest needs a performance API.'),
  },
  {
    group: 'SYSTEM',
    path: '/storage',
    label: 'Storage',
    tag: 'P2',
    live: false,
    element: P(2, 'Storage', 'EPIC: Phase 2 — Real Inference', 'SQLite metadata store with a retention policy (§20). Phase 1 uses a bounded in-memory ring; its counters are on /api/v1/status under "storage".'),
  },
  {
    group: 'SYSTEM',
    path: '/settings',
    label: 'Settings',
    tag: 'P2',
    live: false,
    element: P(2, 'Settings', 'EPIC: Phase 2 — Real Inference', 'Runtime settings surface (§19, §23). Configuration today is one JSON file plus SYNAPSE_* env overrides, loaded at start.'),
  },
]

export const GROUP_ORDER: NavGroup[] = ['LIVE', 'CAPTURE', 'ML', 'SYSTEM']

export function resolveRoute(path: string): RouteDef | null {
  return ROUTES.find((r) => r.path === path) ?? null
}
