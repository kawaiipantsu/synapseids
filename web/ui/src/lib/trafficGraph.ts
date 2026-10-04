import type { FlowRecord, MatrixPair } from '../api/types'

export type AddressScope = 'private' | 'public' | 'special'
export interface AssetNode {
  id: string
  scope: AddressScope
  flows: number
  bytes: number
  threats: number
  ports: number[]
}
export interface TrafficGraph {
  nodes: AssetNode[]
  edges: MatrixPair[]
  omitted: number
}
export interface Point {
  x: number
  y: number
}

/** Address scope is a hint, never a claim that an asset belongs to this site. */
export function addressScope(value: string): AddressScope {
  const ip = value.toLowerCase()
  if (ip.startsWith('::ffff:')) return addressScope(ip.slice(7))
  if (ip.includes(':')) {
    if (/^f[cd][\da-f]{2}:/.test(ip)) return 'private'
    if (
      /^fe[89ab][\da-f]:/.test(ip) ||
      ip === '::1' ||
      ip === '::' ||
      ip.startsWith('ff')
    )
      return 'special'
    // Global unicast 2000::/3; documentation addresses are deliberately special.
    return /^[23][\da-f]{3}:/.test(ip) && !ip.startsWith('2001:db8:')
      ? 'public'
      : 'special'
  }
  const parts = ip.split('.').map(Number)
  if (
    parts.length !== 4 ||
    !parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255)
  )
    return 'special'
  const [a, b, c] = parts as [number, number, number, number]
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168))
    return 'private'
  if (
    a === 0 ||
    a === 127 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  )
    return 'special'
  return 'public'
}

export function buildTrafficGraph(
  pairs: MatrixPair[],
  records: FlowRecord[],
  cap = 60,
): TrafficGraph {
  const assets = new Map<string, AssetNode>()
  for (const pair of pairs) {
    // A loopback conversation is one asset, not two copies of its counters.
    for (const ip of new Set([pair.initiator, pair.responder])) {
      const asset = assets.get(ip) ?? {
        id: ip,
        scope: addressScope(ip),
        flows: 0,
        bytes: 0,
        threats: 0,
        ports: [],
      }
      asset.flows += pair.flows
      asset.bytes += pair.bytes
      asset.threats += pair.threat_count ?? 0
      assets.set(ip, asset)
    }
  }
  for (const flow of records) {
    for (const [ip, port] of [
      [flow.initiator_ip, flow.initiator_port],
      [flow.responder_ip, flow.responder_port],
    ] as const) {
      const node = assets.get(ip)
      if (node && port > 0 && !node.ports.includes(port)) node.ports.push(port)
    }
  }
  const nodes = [...assets.values()]
    .sort((a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id))
    .slice(0, Math.max(0, cap))
  nodes.forEach((node) => node.ports.sort((a, b) => a - b))
  const visible = new Set(nodes.map((n) => n.id))
  const edges = pairs.filter(
    (p) => visible.has(p.initiator) && visible.has(p.responder),
  )
  return { nodes, edges, omitted: pairs.length - edges.length }
}

/** Bounded deterministic layout. Counts never influence position, so polling stays stable. */
export function layoutGraph(
  graph: TrafficGraph,
  mode: 'force' | 'ring' | 'grouped',
): Map<string, Point> {
  const nodes = [...graph.nodes].sort((a, b) => a.id.localeCompare(b.id))
  const points = nodes.map((_, i) => {
    const angle = (i / Math.max(1, nodes.length)) * Math.PI * 2 - Math.PI / 2
    return { x: 450 + Math.cos(angle) * 310, y: 250 + Math.sin(angle) * 175 }
  })
  if (nodes.length === 1) points[0] = { x: 450, y: 250 }
  if (mode === 'grouped') {
    for (const [col, scope] of ['private', 'public', 'special'].entries()) {
      const group = nodes
        .map((n, i) => ({ n, i }))
        .filter(({ n }) => n.scope === scope)
      group.forEach(({ i }, row) => {
        points[i] = {
          x: 170 + col * 280,
          y: 75 + ((row + 1) / (group.length + 1)) * 350,
        }
      })
    }
  } else if (mode === 'force') {
    const index = new Map(nodes.map((n, i) => [n.id, i]))
    for (let iteration = 0; iteration < 160; iteration++) {
      const force = points.map((p) => ({
        x: (450 - p.x) * 0.004,
        y: (250 - p.y) * 0.004,
      }))
      for (let i = 0; i < points.length; i++) {
        for (let j = i + 1; j < points.length; j++) {
          const dx = points[i]!.x - points[j]!.x,
            dy = points[i]!.y - points[j]!.y
          const d2 = Math.max(100, dx * dx + dy * dy),
            d = Math.sqrt(d2)
          const f = 22000 / d2
          force[i]!.x += (dx / d) * f
          force[i]!.y += (dy / d) * f
          force[j]!.x -= (dx / d) * f
          force[j]!.y -= (dy / d) * f
        }
      }
      for (const edge of graph.edges) {
        const a = index.get(edge.initiator)!,
          b = index.get(edge.responder)!
        if (a === b) continue
        const dx = points[b]!.x - points[a]!.x,
          dy = points[b]!.y - points[a]!.y
        const distance = Math.max(1, Math.hypot(dx, dy)),
          f = (distance - 175) * 0.012
        force[a]!.x += (dx / distance) * f
        force[a]!.y += (dy / distance) * f
        force[b]!.x -= (dx / distance) * f
        force[b]!.y -= (dy / distance) * f
      }
      points.forEach((p, i) => {
        p.x = Math.max(
          95,
          Math.min(805, p.x + Math.max(-8, Math.min(8, force[i]!.x))),
        )
        p.y = Math.max(
          65,
          Math.min(425, p.y + Math.max(-8, Math.min(8, force[i]!.y))),
        )
      })
    }
  }
  return new Map(nodes.map((n, i) => [n.id, points[i]!]))
}
