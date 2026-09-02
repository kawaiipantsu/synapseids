import { useEffect, useMemo, useRef } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'
import type { TimelineBucket } from '../api/types'
import { CLASS_NAMES, classColor } from '../lib/classes'

// Classification timeline (PROJECT.md §19.6, issue #41): stacked per-class
// volume over time with a disagreement overlay. Dragging across the plot selects
// a time range, which the parent turns into from=/to= filters on the flow and
// classification lists — that interaction is the point of the view, not
// decoration.
//
// uPlot draws to canvas and cannot read CSS custom properties, so every colour
// is resolved to a concrete value first (same approach as Sparkline).

function resolveColor(c: string): string {
  const m = /^var\((--[\w-]+)\)$/.exec(c.trim())
  if (!m) return c
  const v = getComputedStyle(document.documentElement).getPropertyValue(m[1]!).trim()
  return v || c
}

/** rgba() form of a resolved #rrggbb, for the stacked fills. */
function withAlpha(hex: string, a: number): string {
  const m = /^#([0-9a-f]{6})$/i.exec(hex)
  if (!m) return hex
  const n = parseInt(m[1]!, 16)
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`
}

const DISAGREE_COLOR = '#ffffff'

export interface Range {
  from: string
  to: string
}

interface Props {
  buckets: TimelineBucket[]
  bucketSec: number
  height?: number
  /** Called with the dragged range, or null when the selection is cleared. */
  onBrush?: (r: Range | null) => void
  selection?: Range | null
  ariaLabel?: string
}

interface Prepared {
  /** class names actually present, in traffic-classes-v1 order */
  classes: string[]
  /** uPlot data: [xs, ...cumulative per class (top-most first), disagreements] */
  data: number[][]
  key: string
}

/**
 * Build uPlot's data. Stacking is done by cumulative sums, and the series are
 * emitted highest-cumulative-first so each filled area is drawn before the
 * shorter ones that sit on top of it.
 */
function prepare(buckets: TimelineBucket[]): Prepared {
  const present = new Set<string>()
  for (const b of buckets) {
    for (const [name, n] of Object.entries(b.by_class)) {
      if (n > 0) present.add(name)
    }
  }
  const classes = CLASS_NAMES.filter((c) => present.has(c))
  const xs = buckets.map((b) => Date.parse(b.ts) / 1000)

  const accum = new Array<number>(buckets.length).fill(0)
  const cumulative: number[][] = []
  for (const c of classes) {
    const row = new Array<number>(buckets.length)
    for (let i = 0; i < buckets.length; i++) {
      accum[i] = accum[i]! + (buckets[i]!.by_class[c] ?? 0)
      row[i] = accum[i]!
    }
    cumulative.push(row)
  }
  const disagree = buckets.map((b) => b.disagreements)

  return {
    classes,
    data: [xs, ...cumulative.slice().reverse(), disagree],
    key: classes.join(',') + '|' + buckets.length,
  }
}

export function TimelineChart({
  buckets,
  bucketSec,
  height = 150,
  onBrush,
  selection,
  ariaLabel,
}: Props) {
  const host = useRef<HTMLDivElement>(null)
  const plot = useRef<uPlot | null>(null)
  const brushRef = useRef<Props['onBrush']>(onBrush)
  brushRef.current = onBrush

  const prep = useMemo(() => prepare(buckets), [buckets])
  // The build effect keys on prep.key, which encodes the series set, so it reads
  // the rest of prep through a ref rather than re-running on every new object.
  const prepRef = useRef(prep)
  prepRef.current = prep

  // Rebuild the plot when the series set changes; otherwise just push data.
  useEffect(() => {
    const el = host.current
    if (!el) return

    // Reverse order: the tallest cumulative area is drawn first, shorter ones
    // over it. classes[] is bottom-to-top, so reverse for the series array.
    const stackedSeries: uPlot.Series[] = prepRef.current.classes
      .slice()
      .reverse()
      .map((name) => {
        const stroke = resolveColor(classColor(name))
        return {
          label: name,
          stroke,
          width: 1,
          fill: withAlpha(stroke, 0.45),
          points: { show: false },
        }
      })

    const opts: uPlot.Options = {
      width: el.clientWidth || 480,
      height,
      padding: [8, 8, 0, 0],
      legend: { show: false },
      cursor: {
        // Horizontal drag selects a range but must not rescale: the parent
        // re-queries the API with from=/to= instead of zooming the canvas.
        drag: { x: true, y: false, setScale: false },
      },
      scales: {
        x: { time: true },
        y: { range: (_u, _min, max) => [0, Math.max(1, max)] },
      },
      axes: [
        { stroke: resolveColor('var(--dim)'), grid: { show: false }, ticks: { show: false } },
        {
          stroke: resolveColor('var(--dim)'),
          grid: { stroke: resolveColor('var(--edge)'), width: 1 },
          ticks: { show: false },
          size: 40,
        },
      ],
      series: [
        {},
        ...stackedSeries,
        {
          label: 'disagreements',
          stroke: DISAGREE_COLOR,
          width: 1,
          dash: [3, 3],
          points: { show: false },
        },
      ],
      hooks: {
        setSelect: [
          (u) => {
            const cb = brushRef.current
            if (!cb) return
            if (u.select.width <= 2) {
              cb(null)
              return
            }
            const a = u.posToVal(u.select.left, 'x')
            const b = u.posToVal(u.select.left + u.select.width, 'x')
            cb({
              from: new Date(Math.min(a, b) * 1000).toISOString(),
              to: new Date(Math.max(a, b) * 1000).toISOString(),
            })
          },
        ],
      },
    }

    plot.current = new uPlot(opts, prepRef.current.data as uPlot.AlignedData, el)

    const ro = new ResizeObserver(() => {
      if (plot.current && el.clientWidth) {
        plot.current.setSize({ width: el.clientWidth, height })
      }
    })
    ro.observe(el)

    return () => {
      ro.disconnect()
      plot.current?.destroy()
      plot.current = null
    }
  }, [prep.key, height])

  useEffect(() => {
    plot.current?.setData(prep.data as uPlot.AlignedData)
  }, [prep.data])

  return (
    <div className="tl">
      <div ref={host} className="tl-plot" role="img" aria-label={ariaLabel ?? 'classification timeline'} />
      <div className="tl-legend">
        <span className="dim">{bucketSec}s buckets</span>
        {prep.classes.map((c) => (
          <span key={c} className="tl-key">
            <i style={{ background: classColor(c) }} />
            {c}
          </span>
        ))}
        <span className="tl-key">
          <i className="tl-dash" />
          disagreements
        </span>
        <span className="spacer" />
        {selection ? (
          <span className="tl-sel">
            filtered {new Date(selection.from).toLocaleTimeString()} –{' '}
            {new Date(selection.to).toLocaleTimeString()}
            <button className="tl-clear" onClick={() => onBrush?.(null)}>
              clear
            </button>
          </span>
        ) : (
          <span className="dim">drag to filter by time range</span>
        )}
      </div>
      <AnomalyCaption buckets={buckets} />
    </div>
  )
}

/**
 * A one-line summary of the anomaly-score series folded into the timeline
 * buckets (ADR 0037). Not drawn on the uPlot canvas — a caption of the real
 * numbers when a flow-anomaly-v1 model scored the window, a labelled gap
 * otherwise.
 */
function AnomalyCaption({ buckets }: { buckets: TimelineBucket[] }) {
  let n = 0
  let weighted = 0
  let max = 0
  let exceeded = 0
  for (const b of buckets) {
    n += b.anomaly_n
    weighted += b.anomaly_mean * b.anomaly_n
    if (b.anomaly_max > max) max = b.anomaly_max
    exceeded += b.anomaly_exceeds
  }
  if (n === 0) {
    return (
      <div className="tl-stub">
        no anomaly-score series — activate a <code>flow-anomaly-v1</code> model to score flows for
        novelty
      </div>
    )
  }
  return (
    <div className="tl-stub">
      anomaly score — {n.toLocaleString()} flows scored, mean {(weighted / n).toFixed(2)}, peak{' '}
      {max.toFixed(2)}
      {exceeded > 0 ? `, ${exceeded.toLocaleString()} over threshold` : ''}
    </div>
  )
}
