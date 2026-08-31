import { useEffect, useMemo, useRef } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'

// Multi-series line chart for the training dashboard (§19.8, issue #35): loss
// curves, the accuracy curve, the learning-rate curve. uPlot draws to canvas
// and cannot read CSS custom properties, so colours are resolved to concrete
// values first — the same approach as Sparkline / TimelineChart.

function resolveColor(c: string): string {
  const m = /^var\((--[\w-]+)\)$/.exec(c.trim())
  if (!m) return c
  const v = getComputedStyle(document.documentElement).getPropertyValue(m[1]!).trim()
  return v || c
}

export interface Series {
  label: string
  /** one value per x point; null for a gap */
  values: (number | null)[]
  color: string
}

interface Props {
  /** x axis, typically epoch numbers */
  xs: number[]
  series: Series[]
  height?: number
  yLabel?: string
  /** log-scale y (learning rate) */
  logY?: boolean
  ariaLabel?: string
}

export function TrainingChart({ xs, series, height = 170, yLabel, logY, ariaLabel }: Props) {
  const host = useRef<HTMLDivElement>(null)
  const plot = useRef<uPlot | null>(null)

  const key = useMemo(
    () => series.map((s) => s.label).join('|') + '|' + (logY ? 'log' : 'lin') + '|' + (yLabel ?? ''),
    [series, logY, yLabel],
  )

  const dataRef = useRef<uPlot.AlignedData>([])
  dataRef.current = [xs, ...series.map((s) => s.values)] as unknown as uPlot.AlignedData
  const seriesRef = useRef(series)
  seriesRef.current = series

  useEffect(() => {
    const el = host.current
    if (!el) return

    const opts: uPlot.Options = {
      width: el.clientWidth || 480,
      height,
      padding: [10, 12, 4, 4],
      legend: { show: true, live: true },
      cursor: { drag: { x: false, y: false }, points: { size: 5 } },
      scales: {
        x: { time: false },
        y: logY ? { distr: 3 } : { range: (_u, min, max) => [Math.min(0, min), Math.max(max, min + 1e-9)] },
      },
      axes: [
        {
          stroke: resolveColor('var(--dim)'),
          grid: { stroke: resolveColor('var(--edge)'), width: 1 },
          ticks: { show: false },
          values: (_u, splits) => splits.map((v) => String(Math.round(v))),
        },
        {
          stroke: resolveColor('var(--dim)'),
          grid: { stroke: resolveColor('var(--edge)'), width: 1 },
          ticks: { show: false },
          size: 52,
          label: yLabel,
          labelSize: yLabel ? 18 : 0,
        },
      ],
      series: [
        { label: 'epoch' },
        ...seriesRef.current.map((s) => ({
          label: s.label,
          stroke: resolveColor(s.color),
          width: 1.75,
          points: { show: false },
        })),
      ],
    }

    plot.current = new uPlot(opts, dataRef.current, el)
    const ro = new ResizeObserver(() => {
      if (plot.current && el.clientWidth) plot.current.setSize({ width: el.clientWidth, height })
    })
    ro.observe(el)
    return () => {
      ro.disconnect()
      plot.current?.destroy()
      plot.current = null
    }
  }, [key, height, logY, yLabel])

  useEffect(() => {
    plot.current?.setData(dataRef.current)
  }, [xs, series])

  return <div ref={host} className="tr-chart" role="img" aria-label={ariaLabel ?? yLabel ?? 'training metric'} />
}
