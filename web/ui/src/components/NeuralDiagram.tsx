/** A topology diagram. Unit samples never pretend to be measured activations. */
export function NeuralDiagram({
  widths,
  labels,
  active = false,
}: {
  widths: number[]
  labels?: string[]
  active?: boolean
}) {
  const layers = widths.map((width, i) => {
    const count = Math.min(8, Math.max(1, width))
    return Array.from({ length: count }, (_, j) => ({
      x: 55 + (i / Math.max(1, widths.length - 1)) * 590,
      y: 65 + ((j + 0.5) / count) * 185,
    }))
  })
  return (
    <svg
      className={`neural-diagram ${active ? 'is-active' : ''}`}
      viewBox="0 0 700 300"
      role="img"
      aria-label={`Network topology schematic: ${widths.join(' to ')} units. Hidden activations are not measured.`}
    >
      {layers.slice(0, -1).map((layer, i) => (
        <g key={i} className="neural-wires">
          {layer.flatMap((a, j) =>
            layers[i + 1]!.map((b, k) => (
              <path
                key={`${j}-${k}`}
                d={`M${a.x} ${a.y}L${b.x} ${b.y}`}
                stroke="currentColor"
                strokeWidth=".8"
                opacity={0.1 + ((j + k) % 3) * 0.035}
              />
            )),
          )}
        </g>
      ))}
      {layers.map((layer, i) => (
        <g
          key={i}
          className={
            i === 0
              ? 'neural-input'
              : i === layers.length - 1
                ? 'neural-output'
                : 'neural-hidden'
          }
        >
          <text
            x={layer[0]!.x}
            y="24"
            textAnchor="middle"
            fill="var(--dim)"
            fontSize="11"
          >
            {labels?.[i] ??
              (i === 0
                ? 'INPUT'
                : i === layers.length - 1
                  ? 'OUTPUT'
                  : `HIDDEN ${i}`)}
          </text>
          {layer.map((p, j) => (
            <g key={j}>
              <circle
                cx={p.x}
                cy={p.y}
                r="9"
                fill="var(--bg)"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <circle cx={p.x} cy={p.y} r="3" fill="currentColor" />
            </g>
          ))}
          <text
            x={layer[0]!.x}
            y="283"
            textAnchor="middle"
            fill="var(--ink)"
            fontSize="12"
          >
            {widths[i]} units
          </text>
        </g>
      ))}
    </svg>
  )
}
