import type { ReactNode } from 'react'

import { Placeholder } from '../components/Placeholder'
import { Architecture } from './Architecture'
import { CaptureSources } from './CaptureSources'
import { Dashboard } from './Dashboard'
import { DatasetExplorer } from './DatasetExplorer'
import { Datasets } from './Datasets'
import { Detections } from './Detections'
import { FlowLog } from './FlowLog'
import { Hosts } from './Hosts'
import { Investigate } from './Investigate'
import { Matrix } from './Matrix'
import { Models } from './Models'
import { ReplayPage } from './ReplayPage'
import { ReviewQueue } from './Review'
import { Sensors } from './Sensors'
import { Timeline } from './Timeline'
import { Training } from './Training'

export type NavGroup = 'LIVE' | 'CAPTURE' | 'ML' | 'SYSTEM'

export interface RouteDef {
  path: string
  label: string
  group: NavGroup
  element: ReactNode
  /**
   * Short sidebar tag: "live" for a wired view, "#{n}" — the *open* tracking
   * issue — for a stub. It used to be "P{n}" for a phase, but a phase number
   * goes stale the moment the epic closes, and several did (issue #118); an
   * issue number stays checkable.
   */
  tag: string
  live: boolean
}

/**
 * A stub route. `issues` must list open GitHub issues; `epic` is optional and
 * only passed when that epic is still open — EPIC: Phase 7 is, EPIC: Phase 2 and
 * Phase 5 are not, so the two views that used to cite them cite their leaf
 * issues alone.
 */
const P = (title: string, issues: number[], note: string, epic?: string) => (
  <Placeholder title={title} issues={issues} epic={epic} note={note} />
)

// Navigation tree from PROJECT.md §19. Order here is the sidebar order.
export const ROUTES: RouteDef[] = [
  // ---- LIVE -------------------------------------------------------------
  { group: 'LIVE', path: '/dashboard', label: 'Dashboard', tag: 'live', live: true, element: <Dashboard /> },
  { group: 'LIVE', path: '/flow-log', label: 'Flow Log', tag: 'live', live: true, element: <FlowLog /> },
  { group: 'LIVE', path: '/investigate', label: 'Investigate', tag: 'live', live: true, element: <Investigate /> },
  { group: 'LIVE', path: '/hosts', label: 'Hosts', tag: 'live', live: true, element: <Hosts /> },
  // The traffic matrix (issue #68): who talks to whom, over the same bounded read
  // model that backs Hosts. A top-N of the heaviest conversations, not a full
  // hosts × hosts grid — see ADR 0026.
  { group: 'LIVE', path: '/matrix', label: 'Matrix', tag: 'live', live: true, element: <Matrix /> },
  { group: 'LIVE', path: '/timeline', label: 'Timeline', tag: 'live', live: true, element: <Timeline /> },
  // The human review loop (§16; issues #42 and #64): the ranked queue, the five
  // review states, and the curated-dataset hand-off. Distinct from Detections
  // below — a review is about one classification, a detection is a deduplicated
  // alert standing for many.
  { group: 'LIVE', path: '/review', label: 'Review', tag: 'live', live: true, element: <ReviewQueue /> },
  // Detections (§19.1/§19.4, issue #117): the deduplicated alert feed over
  // GET /api/v1/detections. Against a daemon older than #117 the route 404s and
  // the view renders "not available in this build" rather than a spinner or an
  // error — it stays `live: true` either way, because the *view* is real and that
  // unavailability is a fact it reports about the daemon, not a stub.
  {
    group: 'LIVE',
    path: '/detections',
    label: 'Detections',
    tag: 'live',
    live: true,
    element: <Detections />,
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
  // Sensor topology (§19.15, issue #46): sensors grouped by the location each one
  // reported, with per-location aggregates, and click-to-scope. The view states
  // per sensor whether its flows can actually be attributed to it — flow/feature
  // mode yes, raw mode no (ADR 0026).
  {
    group: 'CAPTURE',
    path: '/sensors',
    label: 'Sensors',
    tag: 'live',
    live: true,
    element: <Sensors />,
  },
  { group: 'CAPTURE', path: '/replay', label: 'Replay', tag: 'live', live: true, element: <ReplayPage /> },

  // ---- ML ------------------------------------------------------------
  {
    group: 'ML',
    path: '/models',
    label: 'Models',
    tag: 'live',
    live: true,
    element: <Models />,
  },
  {
    group: 'ML',
    path: '/training',
    label: 'Training',
    tag: 'live',
    live: true,
    element: <Training />,
  },
  // The Dataset Manager (§19.10) and the Dataset Explorer (§19.11 — feature
  // distributions, correlations, outliers, protocol/port splits, PCA
  // projection; closes issues #37 and #67) are both live. The Explorer opens
  // per dataset via #/dataset-explorer?ref=<id>@<version>.
  { group: 'ML', path: '/datasets', label: 'Datasets', tag: 'live', live: true, element: <Datasets /> },
  {
    group: 'ML',
    path: '/dataset-explorer',
    label: 'Dataset Explorer',
    tag: 'live',
    live: true,
    element: <DatasetExplorer />,
  },
  {
    group: 'ML',
    path: '/architecture',
    label: 'Architecture',
    tag: 'live',
    live: true,
    element: <Architecture />,
  },
  // EPIC: Phase 7 — Advanced ML (#7) is still open, so the phase framing here is
  // accurate; each view names its own leaf issue as well.
  {
    group: 'ML',
    path: '/model-compare',
    label: 'Model Compare',
    tag: '#48',
    live: false,
    element: P(
      'Model Comparison',
      [48],
      'Side-by-side evaluation of compatible models (§19.7): predictions, confidence, disagreement, latency and confusion matrices. Needs two comparable models, which needs the trainer.',
      'EPIC: Phase 7 — Advanced ML (#7)',
    ),
  },
  {
    group: 'ML',
    path: '/drift',
    label: 'Drift',
    tag: '#49',
    live: false,
    element: P(
      'Drift',
      [49],
      'Per-feature comparison of current traffic against a model’s training distribution (§19.13). Informational only — drift is never an automatic retrain.',
      'EPIC: Phase 7 — Advanced ML (#7)',
    ),
  },

  // ---- SYSTEM ------------------------------------------------------
  // System Performance is §19.16 work tracked by #55 (structured logging +
  // /metrics), not by the Advanced-ML epic it used to cite.
  {
    group: 'SYSTEM',
    path: '/performance',
    label: 'Performance',
    tag: '#55',
    live: false,
    element: P(
      'System Performance',
      [55],
      'Full §19.16 board: CPU/memory/goroutines, decode and inference latency percentiles, queue depth, DB latency. A few counters (WebSocket clients, event queue, flow table) are already on /api/v1/status and shown on the Dashboard; the percentiles need the latency histograms from #55.',
    ),
  },
  {
    group: 'SYSTEM',
    path: '/storage',
    label: 'Storage',
    tag: '#53',
    live: false,
    element: P(
      'Storage',
      [53],
      'SQLite metadata store with a retention policy (§20). This build uses a bounded in-memory ring; its live counters are on /api/v1/status under "storage" and on the Dashboard.',
    ),
  },
  {
    group: 'SYSTEM',
    path: '/settings',
    label: 'Settings',
    tag: '#54',
    live: false,
    element: P(
      'Settings',
      [54, 59],
      'Runtime settings surface (§19, §23). Configuration today is one JSON file plus SYNAPSE_* env overrides, read once at start: #54 adds native YAML, #59 adds hot-reload, and an editable surface needs both.',
    ),
  },
]

export const GROUP_ORDER: NavGroup[] = ['LIVE', 'CAPTURE', 'ML', 'SYSTEM']

export function resolveRoute(path: string): RouteDef | null {
  return ROUTES.find((r) => r.path === path) ?? null
}
