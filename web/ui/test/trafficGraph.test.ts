import assert from 'node:assert/strict'
import test from 'node:test'
import { addressScope, buildTrafficGraph, layoutGraph } from '../src/lib/trafficGraph.js'
import type { MatrixPair } from '../src/api/types.js'
const pair = (initiator: string, responder: string, bytes = 10): MatrixPair => ({ initiator, responder, bytes, bytes_fwd: bytes, bytes_bwd: 0, packets: 1, flows: 1, first_seen: '', last_seen: '', classifications: 1, classes: [], disagreements: 0 })
test('address scopes include IPv6, mapped IPv4 and special ranges without implying site ownership', () => {
  for (const ip of ['10.0.0.1', '172.16.0.1', '192.168.1.1', 'fd00::1', '::ffff:10.1.1.1']) assert.equal(addressScope(ip), 'private')
  for (const ip of ['127.0.0.1', '169.254.1.2', '100.64.0.1', '192.0.2.1', '2001:db8::1', '::1', 'fe80::1', 'ff02::1']) assert.equal(addressScope(ip), 'special')
  assert.equal(addressScope('8.8.8.8'), 'public')
  assert.equal(addressScope('2606:4700::1111'), 'public')
  assert.equal(addressScope('untrusted<input>'), 'special')
})
test('graph preserves directional edges and accounts for omitted connections at its node cap', () => {
  const graph = buildTrafficGraph([pair('a','b',100),pair('b','a',80),pair('b','c',1)], [], 2)
  assert.equal(graph.nodes.length, 2)
  assert.equal(graph.edges.length, 2)
  assert.equal(graph.omitted, 1)
  assert.equal(graph.nodes.find((n) => n.id === 'b')!.bytes, 181)
})
test('self connections count each asset once and layouts are finite, bounded and deterministic', () => {
  const graph = buildTrafficGraph([pair('a', 'a'), pair('a','b')], [])
  assert.equal(graph.nodes.find((n) => n.id === 'a')!.flows, 2)
  for (const mode of ['force','ring','grouped'] as const) {
    const positions = layoutGraph(graph, mode)
    assert.deepEqual(positions, layoutGraph(graph, mode))
    for (const point of positions.values()) { assert.ok(Number.isFinite(point.x)); assert.ok(point.x >= 0 && point.x <= 900); assert.ok(point.y >= 0 && point.y <= 500) }
  }
  assert.equal(layoutGraph(buildTrafficGraph([],[]), 'force').size, 0)
})
