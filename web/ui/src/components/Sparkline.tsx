import { useEffect, useRef } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'

// Tiny streaming sparkline. uPlot is the charting library chosen for streaming
// performance (PROJECT.md §27); it is ~15 KB gzipped and draws to canvas, so
// CSS custom properties must be resolved to concrete colours first.

interface Props {
  values: number[]
  height?: number
  stroke?: string
  fill?: string
  ariaLabel?: string
}

function resolveColor(c: string): string {
  const m = /^var\((--[\w-]+)\)$/.exec(c.trim())
  if (!m) return c
  const v = getComputedStyle(document.documentElement).getPropertyValue(m[1]!).trim()
  return v || c
}

export function Sparkline({
  values,
  height = 44,
  stroke = '#35c1d6',
  fill = 'rgba(53,193,214,0.16)',
  ariaLabel,
}: Props) {
  const host = useRef<HTMLDivElement>(null)
  const plot = useRef<uPlot | null>(null)
  const dataRef = useRef<number[]>(values)
  dataRef.current = values

  useEffect(() => {
    const el = host.current
    if (!el) return

    const opts: uPlot.Options = {
      width: el.clientWidth || 240,
      height,
      padding: [4, 0, 2, 0],
      cursor: { show: false },
      legend: { show: false },
      scales: {
        x: { time: false },
        y: { range: (_u, _min, max) => [0, Math.max(1, max)] },
      },
      axes: [
        { show: false },
        { show: false },
      ],
      series: [
        {},
        {
          stroke: resolveColor(stroke),
          width: 1.5,
          fill: resolveColor(fill),
          points: { show: false },
        },
      ],
    }

    const xs = dataRef.current.map((_, i) => i)
    plot.current = new uPlot(opts, [xs, dataRef.current.slice()], el)

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
  }, [height, stroke, fill])

  useEffect(() => {
    if (!plot.current) return
    const xs = values.map((_, i) => i)
    plot.current.setData([xs, values.slice()])
  }, [values])

  return <div ref={host} className="spark" role="img" aria-label={ariaLabel} />
}
