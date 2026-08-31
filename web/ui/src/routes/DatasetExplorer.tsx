import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { getDatasetStats, getDatasets } from '../api/client'
import type {
  Dataset,
  DatasetFeatureStats,
  DatasetPCA,
  DatasetStats,
} from '../api/types'
import { classColor } from '../lib/classes'
import { fmtInt, fmtNum, fmtPct } from '../lib/format'
import { navigate } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'

// ML ▸ Dataset Explorer (PROJECT.md §19.11; closes issues #37 and #67).
//
// Opened as #/dataset-explorer?ref=<id>@<version>. Everything shown is derived
// server-side from the immutable dataset.csv (GET /api/v1/datasets/{ref}/stats)
// and cached there by content hash — this view only draws it. The PCA maths is
// in internal/dataset/stats.go (stdlib-only cyclic Jacobi); UMAP is deferred
// (ADR 0020).

// ---- ref plumbing -----------------------------------------------------------

function readRef(): string {
  const raw = window.location.hash.replace(/^#/, '')
  const i = raw.indexOf('?')
  if (i === -1) return ''
  return new URLSearchParams(raw.slice(i + 1)).get('ref') ?? ''
}

function splitRef(ref: string): { id: string; version: string } | null {
  const at = ref.lastIndexOf('@')
  if (at <= 0 || at === ref.length - 1) return null
  return { id: ref.slice(0, at), version: ref.slice(at + 1) }
}

function explorerHref(id: string, version: string): string {
  return `#/dataset-explorer?ref=${encodeURIComponent(`${id}@${version}`)}`
}

// ---- tiny SVG helpers -----------------------------------------------------

/** A sparkline-style vertical-bar mini histogram. */
function MiniBars({ counts, color, height = 34 }: { counts: number[]; color: string; height?: number }) {
  const max = counts.reduce((a, b) => Math.max(a, b), 0) || 1
  const w = 3
  const gap = 1
  const width = counts.length * (w + gap)
  return (
    <svg className="dx-mini" width={width} height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
      {counts.map((c, i) => {
        const h = Math.max(c > 0 ? 1 : 0, (c / max) * height)
        return <rect key={i} x={i * (w + gap)} y={height - h} width={w} height={h} fill={color} />
      })}
    </svg>
  )
}

// ---- correlation heatmap (the §19.11 centrepiece) -----------------------

function corrRGBA(v: number): string {
  const a = Math.min(1, Math.abs(v))
  // diverging: negative → accent blue, positive → dos red
  const [r, g, b] = v >= 0 ? [255, 92, 108] : [53, 193, 214]
  return `rgba(${r},${g},${b},${a.toFixed(3)})`
}

function CorrelationHeatmap({ names, size, matrix }: { names: string[]; size: number; matrix: number[] }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const [hover, setHover] = useState<{ i: number; j: number; x: number; y: number } | null>(null)
  const cell = 12
  const px = size * cell

  useEffect(() => {
    const cv = canvasRef.current
    if (!cv) return
    const ctx = cv.getContext('2d')
    if (!ctx) return
    ctx.clearRect(0, 0, px, px)
    for (let i = 0; i < size; i++) {
      for (let j = 0; j < size; j++) {
        ctx.fillStyle = corrRGBA(matrix[i * size + j] ?? 0)
        ctx.fillRect(j * cell, i * cell, cell, cell)
      }
    }
  }, [matrix, size, px])

  const onMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const j = Math.floor((e.clientX - rect.left) / cell)
    const i = Math.floor((e.clientY - rect.top) / cell)
    if (i < 0 || j < 0 || i >= size || j >= size) return setHover(null)
    setHover({ i, j, x: e.clientX - rect.left, y: e.clientY - rect.top })
  }

  const val = hover ? matrix[hover.i * size + hover.j] ?? 0 : 0

  return (
    <div className="card wide">
      <h3>Feature correlation ({size}×{size} Pearson)</h3>
      <div className="foot">
        Blue = negative, red = positive, intensity = |r|. Zero-variance features read 0. Hover a cell for the pair.
      </div>
      <div className="dx-heatwrap" style={{ position: 'relative', width: px, maxWidth: '100%', overflow: 'auto' }}>
        <canvas
          ref={canvasRef}
          width={px}
          height={px}
          className="dx-heat"
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
        />
        {hover ? (
          <div
            className="dx-heat-tip"
            style={{ left: Math.min(hover.x + 12, px - 220), top: hover.y + 12 }}
          >
            <b>{names[hover.i]}</b> × <b>{names[hover.j]}</b>
            <div className="mono">r = {fmtNum(val, 3)}</div>
          </div>
        ) : null}
      </div>
    </div>
  )
}

// ---- feature distribution grid -----------------------------------------

function FeatureCard({ f, onOpen }: { f: DatasetFeatureStats; onOpen: () => void }) {
  return (
    <button className="dx-fcard" onClick={onOpen} title={`${f.name} — click to enlarge`}>
      <div className="dx-fname">
        {f.index}. {f.name}
        {f.log_scale ? <span className="dx-tag">log</span> : null}
      </div>
      {f.degenerate || !f.bin_counts ? (
        <div className="dx-degenerate">constant {fmtNum(f.min)}</div>
      ) : (
        <MiniBars counts={f.bin_counts} color="var(--accent)" />
      )}
      <div className="dx-fmeta">
        μ {fmtNum(f.mean)} · σ {fmtNum(f.stddev)}
      </div>
    </button>
  )
}

function FeatureDetail({ f, onClose }: { f: DatasetFeatureStats; onClose: () => void }) {
  const width = 520
  const height = 160
  const counts = f.bin_counts ?? []
  const edges = f.bin_edges ?? []
  const max = counts.reduce((a, b) => Math.max(a, b), 0) || 1
  const span = f.max - f.min || 1
  const markerX = (v: number) => ((v - f.min) / span) * width
  const bw = width / (counts.length || 1)

  return (
    <div className="dx-detail card wide">
      <div className="dx-detail-h">
        <h3>
          {f.index}. {f.name} <span className="dim">({f.unit || 'unitless'} · norm {f.norm})</span>
        </h3>
        <button onClick={onClose}>close</button>
      </div>
      <div className="dx-stat-row">
        <span>min {fmtNum(f.min)}</span>
        <span>p25 {fmtNum(f.p25)}</span>
        <span>p50 {fmtNum(f.p50)}</span>
        <span>p75 {fmtNum(f.p75)}</span>
        <span>max {fmtNum(f.max)}</span>
        <span>mean {fmtNum(f.mean)}</span>
        <span>stddev {fmtNum(f.stddev)}</span>
      </div>
      {counts.length === 0 ? (
        <div className="foot">This feature is constant across every row — nothing to plot.</div>
      ) : (
        <svg className="dx-detail-svg" width={width} height={height + 22} role="img" aria-label={`${f.name} histogram`}>
          {counts.map((c, i) => {
            const h = c > 0 ? Math.max(1, (c / max) * height) : 0
            return <rect key={i} x={i * bw} y={height - h} width={Math.max(1, bw - 1)} height={h} fill="var(--accent)" />
          })}
          {[
            { v: f.p25, label: 'p25' },
            { v: f.p50, label: 'p50' },
            { v: f.p75, label: 'p75' },
          ].map((m) => (
            <g key={m.label}>
              <line x1={markerX(m.v)} x2={markerX(m.v)} y1={0} y2={height} stroke="var(--suspicious)" strokeDasharray="3 2" />
              <text x={markerX(m.v)} y={height + 14} fontSize={10} fill="var(--suspicious)" textAnchor="middle">
                {m.label}
              </text>
            </g>
          ))}
          <text x={0} y={height + 14} fontSize={10} fill="var(--dim)">
            {fmtNum(edges[0] ?? f.min)}
          </text>
          <text x={width} y={height + 14} fontSize={10} fill="var(--dim)" textAnchor="end">
            {fmtNum(edges[edges.length - 1] ?? f.max)}
          </text>
        </svg>
      )}
      {f.log_scale ? <div className="foot">Histogram edges are log1p-spaced (schema norm hint).</div> : null}
    </div>
  )
}

// ---- PCA scatter -------------------------------------------------------

const AXES = [1, 2, 3] as const
type Axis = (typeof AXES)[number]

function pcOf(p: DatasetPCA['projection'][number], axis: Axis): number {
  return axis === 1 ? p.pc1 : axis === 2 ? p.pc2 : p.pc3
}

function PCAScatter({ pca }: { pca: DatasetPCA }) {
  const [xa, setXa] = usePersistedState<Axis>('dx.pca.x', 1)
  const [ya, setYa] = usePersistedState<Axis>('dx.pca.y', 2)
  const width = 460
  const height = 360
  const pad = 28

  const pts = pca.projection
  const bounds = useMemo(() => {
    let x0 = Infinity
    let x1 = -Infinity
    let y0 = Infinity
    let y1 = -Infinity
    for (const p of pts) {
      const x = pcOf(p, xa)
      const y = pcOf(p, ya)
      if (x < x0) x0 = x
      if (x > x1) x1 = x
      if (y < y0) y0 = y
      if (y > y1) y1 = y
    }
    if (!Number.isFinite(x0)) return { x0: -1, x1: 1, y0: -1, y1: 1 }
    return { x0, x1, y0, y1 }
  }, [pts, xa, ya])

  const sx = (x: number) =>
    pad + ((x - bounds.x0) / (bounds.x1 - bounds.x0 || 1)) * (width - 2 * pad)
  const sy = (y: number) =>
    height - pad - ((y - bounds.y0) / (bounds.y1 - bounds.y0 || 1)) * (height - 2 * pad)

  const legend = useMemo(() => {
    const seen = new Set<string>()
    for (const p of pts) seen.add(p.label)
    return [...seen]
  }, [pts])

  return (
    <div className="card wide">
      <h3>PCA projection</h3>
      <div className="foot">
        Top {pca.components} components of the standardised 48-feature matrix (cyclic Jacobi, {pca.jacobi_sweeps} sweeps).
        Explained variance: {pca.explained_variance.map((v) => fmtPct(v)).join(' · ')} of {fmtNum(pca.eigenvalues_total, 1)} total.
        {pca.projection_sampled ? ` Showing a ${fmtInt(pts.length)}-row sample (cap ${fmtInt(pca.projection_cap)}).` : ''}
      </div>
      <div className="dx-pca-ctl">
        <label>
          X
          <select value={xa} onChange={(e) => setXa(Number(e.target.value) as Axis)}>
            {AXES.map((a) => (
              <option key={a} value={a}>
                PC{a} ({fmtPct(pca.explained_variance[a - 1] ?? 0)})
              </option>
            ))}
          </select>
        </label>
        <label>
          Y
          <select value={ya} onChange={(e) => setYa(Number(e.target.value) as Axis)}>
            {AXES.map((a) => (
              <option key={a} value={a}>
                PC{a} ({fmtPct(pca.explained_variance[a - 1] ?? 0)})
              </option>
            ))}
          </select>
        </label>
        <span className="dx-legend">
          {legend.map((l) => (
            <span key={l} className="dx-chip">
              <i style={{ background: classColor(l) }} />
              {l}
            </span>
          ))}
        </span>
      </div>
      <div className="dx-pca-wrap">
        <svg width={width} height={height} className="dx-pca" role="img" aria-label="PCA scatter plot">
          <line x1={pad} y1={height - pad} x2={width - pad} y2={height - pad} stroke="var(--edge)" />
          <line x1={pad} y1={pad} x2={pad} y2={height - pad} stroke="var(--edge)" />
          <text x={width - pad} y={height - pad + 16} fontSize={10} fill="var(--dim)" textAnchor="end">
            PC{xa}
          </text>
          <text x={pad - 6} y={pad} fontSize={10} fill="var(--dim)" textAnchor="end">
            PC{ya}
          </text>
          {pts.map((p) => (
            <circle
              key={p.row}
              cx={sx(pcOf(p, xa))}
              cy={sy(pcOf(p, ya))}
              r={2.2}
              fill={classColor(p.label)}
              fillOpacity={0.75}
            >
              <title>
                row {p.row} · {p.label} · PC{xa} {fmtNum(pcOf(p, xa), 2)} / PC{ya} {fmtNum(pcOf(p, ya), 2)}
              </title>
            </circle>
          ))}
        </svg>
      </div>
    </div>
  )
}

// ---- small bars ------------------------------------------------------

function BarRow({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total > 0 ? (value / total) * 100 : 0
  return (
    <div className="dx-bar-row">
      <span className="dx-bar-label">{label}</span>
      <span className="dx-bar-track">
        <span className="dx-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </span>
      <span className="dx-bar-val">{fmtInt(value)}</span>
    </div>
  )
}

// ---- the page --------------------------------------------------------

export function DatasetExplorer() {
  const [ref, setRef] = useState(() => readRef())
  const [stats, setStats] = useState<DatasetStats | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [openFeature, setOpenFeature] = useState<number | null>(null)
  const [pickList, setPickList] = useState<Dataset[]>([])

  useEffect(() => {
    const onHash = () => setRef(readRef())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const parsed = useMemo(() => splitRef(ref), [ref])

  const load = useCallback(() => {
    if (!parsed) return
    setLoading(true)
    setErr(null)
    getDatasetStats(parsed.id, parsed.version)
      .then((s) => {
        setStats(s)
        setOpenFeature(null)
      })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }, [parsed])

  useEffect(() => {
    setStats(null)
    load()
  }, [load])

  useEffect(() => {
    if (parsed) return
    getDatasets()
      .then((r) => setPickList(r.datasets ?? []))
      .catch(() => setPickList([]))
  }, [parsed])

  if (!parsed) {
    return (
      <div>
        <div className="page-h">
          <h1>Dataset Explorer</h1>
          <span className="sub">
            feature distributions, correlations, protocol/port splits, outliers and a PCA projection
            for one materialised dataset (§19.11, issues #37/#67). Pick a version:
          </span>
        </div>
        <div className="card wide">
          {pickList.length === 0 ? (
            <div className="foot">
              no datasets yet — cut one on <a href="#/datasets">ML ▸ Datasets</a> first.
            </div>
          ) : (
            <ul className="dx-picklist">
              {pickList.map((d) => (
                <li key={`${d.id}@${d.version}`}>
                  <a href={explorerHref(d.id, d.version)}>
                    {d.id} <span className="src-badge">{d.version}</span>
                  </a>
                  <span className="dim"> · {fmtInt(d.flow_count)} flows</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="page-h">
        <h1>Dataset Explorer</h1>
        <span className="sub">
          <a href="#/datasets">← Datasets</a> · <code>{ref}</code>
          {stats ? (
            <>
              {' '}
              · {fmtInt(stats.row_count)} rows · {stats.feature_count} features ·{' '}
              <span className="mono" title={stats.content_hash}>
                {stats.content_hash.replace('sha256:', '').slice(0, 12)}
              </span>
            </>
          ) : null}
        </span>
      </div>

      {err ? (
        <div className="src-msg err">
          stats unavailable — {err}{' '}
          <button onClick={() => navigate('/dataset-explorer')}>pick another</button>
        </div>
      ) : null}
      {loading && !stats ? <div className="foot">computing…</div> : null}

      {stats ? (
        <>
          <div className="card wide">
            <h3>Label distribution</h3>
            <div className="dx-bars">
              {stats.label_distribution.classes.map((c, i) => (
                <BarRow
                  key={c}
                  label={c}
                  value={stats.label_distribution.counts[i] ?? 0}
                  total={stats.label_distribution.total}
                  color={classColor(c)}
                />
              ))}
            </div>
            {stats.label_distribution.manifest_mismatch ? (
              <div className="foot dx-warn">
                the CSV&rsquo;s per-class counts disagree with the manifest&rsquo;s <code>label_counts</code>.
              </div>
            ) : null}
            {stats.label_distribution.unknown
              ? Object.entries(stats.label_distribution.unknown).map(([k, v]) => (
                  <div key={k} className="foot dx-warn">
                    {fmtInt(v)} row(s) carry a non-schema label <code>{k}</code>.
                  </div>
                ))
              : null}
          </div>

          <div className="cards dx-sidebyside">
            <div className="card">
              <h3>Protocol split</h3>
              <div className="dx-bars">
                {(
                  [
                    ['TCP', stats.protocols.tcp, 'var(--accent)'],
                    ['UDP', stats.protocols.udp, 'var(--c2)'],
                    ['ICMP', stats.protocols.icmp, 'var(--scan)'],
                    ['other', stats.protocols.other, 'var(--dim)'],
                  ] as const
                ).map(([l, v, col]) => (
                  <BarRow key={l} label={l} value={v} total={stats.row_count} color={col} />
                ))}
              </div>
            </div>
            <div className="card">
              <h3>Top destination ports</h3>
              <div className="foot">{fmtInt(stats.ports.distinct_destination)} distinct</div>
              <div className="dx-bars">
                {stats.ports.top_destination.slice(0, 10).map((p) => (
                  <BarRow
                    key={p.port}
                    label={String(p.port)}
                    value={p.count}
                    total={stats.ports.top_destination[0]?.count ?? 1}
                    color="var(--suspicious)"
                  />
                ))}
              </div>
            </div>
          </div>

          <CorrelationHeatmap
            names={stats.correlation.names}
            size={stats.correlation.size}
            matrix={stats.correlation.matrix}
          />

          <PCAScatter pca={stats.pca} />

          <div className="card wide">
            <h3>Feature distributions ({stats.feature_stats.length})</h3>
            <div className="foot">click a feature to enlarge it with quartile markers.</div>
            <div className="dx-fgrid">
              {stats.feature_stats.map((f) => (
                <FeatureCard key={f.index} f={f} onOpen={() => setOpenFeature(f.index)} />
              ))}
            </div>
          </div>

          {openFeature != null && stats.feature_stats[openFeature] ? (
            <FeatureDetail f={stats.feature_stats[openFeature]} onClose={() => setOpenFeature(null)} />
          ) : null}

          <div className="card wide">
            <h3>Outliers ({fmtInt(stats.outliers.count)})</h3>
            <div className="foot">{stats.outliers.rule} · threshold |z| &gt; {stats.outliers.threshold}.</div>
            {stats.outliers.rows.length === 0 ? (
              <div className="foot">no row exceeds the threshold.</div>
            ) : (
              <div className="src-scroll">
                <table className="mini src-table">
                  <thead>
                    <tr>
                      <th className="num">row</th>
                      <th>label</th>
                      <th className="num">max |z|</th>
                      <th>top deviating features</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.outliers.rows.map((o) => (
                      <tr key={o.row}>
                        <td className="num mono">{o.row}</td>
                        <td>
                          <span className="dx-chip">
                            <i style={{ background: classColor(o.label) }} />
                            {o.label}
                          </span>
                        </td>
                        <td className="num">{fmtNum(o.max_z, 1)}</td>
                        <td className="mono">
                          {o.features.map((ff) => `${ff.name} (z ${fmtNum(ff.z, 1)})`).join(', ')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {stats.outliers.count > stats.outliers.rows.length ? (
              <div className="foot">list capped at {fmtInt(stats.outliers.cap)}.</div>
            ) : null}
          </div>
        </>
      ) : null}
    </div>
  )
}
