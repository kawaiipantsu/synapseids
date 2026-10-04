import { useEffect, useState } from 'react'
import type { NeuralTrace } from '../api/types'

const number = (v: number) => Math.abs(v) > 10000 || (Math.abs(v) > 0 && Math.abs(v) < .001) ? v.toExponential(3) : v.toFixed(4)
export function ActivationGraph({ trace, flowID, playing, outputNames = [] }: { trace: NeuralTrace; flowID: number; playing: boolean; outputNames?: string[] }) {
  const [phase, setPhase] = useState(0)
  const [selected, setSelected] = useState({ node: 0, unit: 0 })
  const [animate, setAnimate] = useState(true)
  const [page, setPage] = useState(0)
  const count = trace.nodes.length
  useEffect(() => {
    setPhase(0)
    if (!animate) { setPhase(count - 1); return }
    const timer = setInterval(() => setPhase(p => Math.min(p + 1, count - 1)), 160)
    return () => clearInterval(timer)
  }, [flowID, trace, count, animate, playing])
  const start = Math.min(page * 24, Math.max(0, count - 1))
  const nodes = trace.nodes.slice(start, start + 24)
  const width = Math.max(780, nodes.length * 155)
  const point = (column: number, index: number) => {
    const sample = nodes[column]!.sample
    const row = sample.indexOf(index)
    return row < 0 ? null : { x: 66 + column * ((width - 130) / Math.max(nodes.length - 1, 1)), y: 70 + (row + .5) * 330 / sample.length }
  }
  const selectedNode = trace.nodes[selected.node] ?? trace.nodes[0]!
  const selectedValue = selectedNode.values[selected.unit] ?? 0
  return <div className="activation-graph">
    <div className="activation-controls"><span className="live-chip">MEASURED FORWARD PASS</span><span className="dim">Flow #{flowID} · operation {phase + 1}/{count}</span><label><input type="checkbox" checked={animate} onChange={e => setAnimate(e.target.checked)} />Animate propagation</label><button onClick={() => setPhase(0)}>Replay</button></div>
    <div className="activation-scroll"><svg viewBox={'0 0 ' + width + ' 450'} style={{ minWidth: Math.min(width, 780) }} role="img" aria-label="Actual neural activations and sampled weighted connections">
      {nodes.flatMap((node, column) => node.inputs.flatMap(input => {
        const source = nodes.findIndex(n => n.name === input)
        if (source < 0) return []
        const edges = node.connections?.length ? node.connections : node.sample.map(i => ({ from: i, to: i, weight: 1, contribution: nodes[source]!.values[i] ?? 0 }))
        const scale = Math.max(.001, ...edges.map(e => Math.abs(e.contribution)))
        return edges.map((edge, i) => {
          const a = point(source, edge.from), b = point(column, edge.to)
          if (!a || !b) return null
          const visible = column + start <= phase
          return <path key={node.name + input + i} d={'M' + a.x + ',' + a.y + ' C' + (a.x + 55) + ',' + a.y + ' ' + (b.x - 55) + ',' + b.y + ' ' + b.x + ',' + b.y} fill="none" stroke={edge.contribution < 0 ? '#ed987e' : '#48d5c1'} strokeWidth={.4 + 2 * Math.abs(edge.contribution) / scale} opacity={visible ? .12 + .48 * Math.abs(edge.contribution) / scale : .045} className={column + start === phase ? 'activation-edge-current' : ''}>
            <title>{node.connections?.length ? 'Weight ' + number(edge.weight) + ' · input × weight ' + number(edge.contribution) : 'Tensor dependency; not a learned weight'} · units {edge.from} → {edge.to}</title>
          </path>
        })
      }))}
      {nodes.map((node, column) => {
        const scale = Math.max(.001, ...node.values.map(Math.abs))
        const x = point(column, node.sample[0] ?? 0)?.x ?? 0
        return <g key={node.name} opacity={column + start <= phase ? 1 : .3}>
          <text x={x} y="25" textAnchor="middle" fill="var(--ink)" fontSize="12">{node.op === 'Input' ? 'INPUT' : node.op === 'Softmax' ? 'OUTPUT' : node.op.toUpperCase()}</text>
          <text x={x} y="43" textAnchor="middle" fill="var(--dim)" fontSize="10">{node.values.length} units</text>
          {node.sample.map(unit => {
            const p = point(column, unit)!, value = node.values[unit]!, strength = Math.abs(value) / scale
            const active = selected.node === column + start && selected.unit === unit
            const label = node.op === 'Softmax' ? (outputNames[unit]?.replace(/_/g,' ') ?? String(unit)) : String(unit)
            return <g key={unit} className="activation-neuron" tabIndex={0} role="button" aria-label={node.op + ' ' + label + ' activation ' + number(value)} onClick={() => setSelected({ node: column + start, unit })} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') setSelected({ node: column + start, unit }) }}>
              <circle cx={p.x} cy={p.y} r={active ? 12 : 9} fill={value < 0 ? '#b56c62' : '#269e8c'} fillOpacity={.15 + strength * .85} stroke={active ? '#fff' : '#4bcdbd'} strokeWidth={active ? 2 : 1} />
              <text x={node.op === 'Softmax' ? p.x - 15 : p.x + 15} textAnchor={node.op === 'Softmax' ? 'end' : 'start'} y={p.y + 3} fill="var(--dim)" fontSize="9">{label.length > 15 ? label.slice(0,14)+'…' : label}</text><title>{label} · {node.name} · unit {unit} · {number(value)}</title>
            </g>
          })}
          <text x={x} y="431" textAnchor="middle" fill="var(--dim)" fontSize="10">{node.sample.length}/{node.values.length} shown</text>
        </g>
      })}
    </svg></div>
    {count > 24 && <div className="activation-controls"><button disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous operations</button><button disabled={start + 24 >= count} onClick={() => setPage(p => p + 1)}>Next operations</button></div>}
    <div className="activation-readout"><strong>{selectedNode.op} · unit {selected.unit}</strong><b>{number(selectedValue)}</b><span className="dim">Actual activation · color scaled within this operation</span></div>
    <details className="activation-values"><summary>Inspect every unit in this operation</summary><div>{selectedNode.values.map((value, unit) => <button key={unit} onClick={() => setSelected({ node: selected.node, unit })}><span>#{unit}</span> {number(value)}</button>)}</div></details>
  </div>
}
