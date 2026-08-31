// GET /api/v1/detections — client contract tests (issue #117, issue #118).
//
// The endpoint itself is landing on a sibling branch, so this suite exists to
// make the SPA's half verifiable *without* it: `fetch` is stubbed and answered
// from test/fixtures/detections.json, which is a byte-for-byte instance of the
// agreed response contract. If the daemon ever answers something else, this
// fixture is the thing to update — and the diff will say exactly what changed.
//
// The behaviour under test is mostly about honesty:
//
//   * a 404 is "not available in this build", not an error and not an empty
//     list. The three are rendered differently, so they must be distinguishable
//     here (PROJECT.md §16).
//   * nothing is ever invented. `count`, `total` and `evicted` come through
//     verbatim; a malformed body degrades to an empty list rather than to
//     plausible-looking rows.

import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { after, beforeEach, test } from 'node:test'

import { detectionQuery, getDetection, getDetections } from '../src/api/client.js'
import { SEVERITIES } from '../src/api/types.js'
import type { DetectionList } from '../src/api/types.js'

/**
 * The fixture lives next to the source, not next to the emitted JS — tsc copies
 * no assets — so it is resolved relative to this module first (running the
 * TypeScript directly) and then relative to .test-build/test/ (the normal
 * `npm test` path). Reading a real file rather than importing the JSON keeps the
 * fixture a plain contract sample with no module semantics attached.
 */
function fixturePath(): string {
  for (const rel of ['./fixtures/detections.json', '../../test/fixtures/detections.json']) {
    const p = fileURLToPath(new URL(rel, import.meta.url))
    if (existsSync(p)) return p
  }
  throw new Error('test/fixtures/detections.json not found')
}

const FIXTURE = JSON.parse(readFileSync(fixturePath(), 'utf8')) as DetectionList

type Stub = (url: string) => { status: number; body?: unknown; text?: string }

const realFetch = globalThis.fetch
const calls: string[] = []

/** Answer every fetch from `fn`, recording the URL it was asked for. */
function stubFetch(fn: Stub): void {
  globalThis.fetch = ((input: RequestInfo | URL) => {
    const url = String(input)
    calls.push(url)
    const r = fn(url)
    const body = r.text ?? (r.body === undefined ? '' : JSON.stringify(r.body))
    return Promise.resolve(
      new Response(body, {
        status: r.status,
        headers: { 'content-type': 'application/json' },
      }),
    )
  }) as typeof fetch
}

beforeEach(() => {
  calls.length = 0
})

after(() => {
  globalThis.fetch = realFetch
})

// ---- query serialisation --------------------------------------------------

test('detectionQuery serialises only the parameters that are set', () => {
  assert.equal(detectionQuery(), '')
  assert.equal(detectionQuery({ limit: 100 }), '?limit=100')
  assert.equal(
    detectionQuery({
      limit: 50,
      class: 'brute_force',
      severity: 'high',
      min_confidence: 0.9,
      since: '2026-08-31T17:00:00Z',
    }),
    '?limit=50&class=brute_force&severity=high&min_confidence=0.9&since=2026-08-31T17%3A00%3A00Z',
  )
})

test('detectionQuery drops a zero min_confidence rather than sending a no-op filter', () => {
  assert.equal(detectionQuery({ min_confidence: 0 }), '')
})

// ---- the happy path, against the fixed contract ---------------------------

test('a contract-shaped response is returned verbatim', async () => {
  stubFetch(() => ({ status: 200, body: FIXTURE }))

  const r = await getDetections({ limit: 100, severity: 'high' })
  assert.equal(r.state, 'ok')
  if (r.state !== 'ok') return

  assert.equal(calls[0], '/api/v1/detections?limit=100&severity=high')
  assert.equal(r.list.total, 12)
  assert.equal(r.list.returned, 3)
  assert.equal(r.list.evicted, 2)
  assert.equal(r.list.detections.length, 3)

  const brute = r.list.detections[0]!
  assert.equal(brute.id, 12)
  assert.equal(brute.class, 'brute_force')
  assert.equal(brute.severity, 'high')
  assert.equal(brute.count, 7)
  assert.equal(brute.confidence, 0.983)
  assert.equal(brute.flow_id, 4231)
  assert.deepEqual(brute.flow_ids, [4231, 4232])
  assert.equal(brute.src_port, 51234)
  assert.equal(brute.dst_port, 3306)
  assert.equal(brute.models?.[0]?.role, 'primary')
})

test('a deduplicated detection keeps its count and its first/last span', async () => {
  stubFetch(() => ({ status: 200, body: FIXTURE }))
  const r = await getDetections()
  assert.equal(r.state, 'ok')
  if (r.state !== 'ok') return

  const scan = r.list.detections.find((d) => d.class === 'scan')!
  // 412 probes behind one row is the whole reason `count` is on the contract.
  assert.equal(scan.count, 412)
  assert.notEqual(scan.ts, scan.last_ts)
  assert.ok(new Date(scan.last_ts) > new Date(scan.ts))

  const single = r.list.detections.find((d) => d.id === 9)!
  assert.equal(single.count, 1)
  assert.equal(single.ts, single.last_ts)
})

test('every fixture severity is one of the four the contract allows', () => {
  for (const d of FIXTURE.detections) {
    assert.ok(SEVERITIES.includes(d.severity), `unexpected severity ${d.severity}`)
  }
})

// ---- honest degradation ---------------------------------------------------

test('a 404 is "unavailable", not an error and not an empty list', async () => {
  stubFetch(() => ({ status: 404, text: '404 page not found' }))

  const r = await getDetections()
  assert.equal(r.state, 'unavailable')
  if (r.state !== 'unavailable') return
  assert.match(r.message, /not available in this build/)
  assert.match(r.message, /#117/)
})

test('an empty feed is "ok" with zero rows — distinct from unavailable', async () => {
  stubFetch(() => ({
    status: 200,
    body: { detections: [], total: 0, returned: 0, evicted: 0 },
  }))

  const r = await getDetections()
  assert.equal(r.state, 'ok')
  if (r.state !== 'ok') return
  assert.equal(r.list.detections.length, 0)
  assert.equal(r.list.total, 0)
})

test('a 500 is an error, and carries the daemon\'s text', async () => {
  stubFetch(() => ({ status: 500, text: 'detection store unavailable' }))

  const r = await getDetections()
  assert.equal(r.state, 'error')
  if (r.state !== 'error') return
  assert.match(r.message, /500/)
  assert.match(r.message, /detection store unavailable/)
})

test('a transport failure is an error, never a rejected promise', async () => {
  globalThis.fetch = (() => Promise.reject(new Error('network down'))) as typeof fetch

  const r = await getDetections()
  assert.equal(r.state, 'error')
  if (r.state !== 'error') return
  assert.match(r.message, /network down/)
})

test('a body that is not the contract degrades to an empty list, not to guesses', async () => {
  stubFetch(() => ({ status: 200, body: { unexpected: true } }))

  const r = await getDetections()
  assert.equal(r.state, 'ok')
  if (r.state !== 'ok') return
  assert.deepEqual(r.list.detections, [])
  assert.equal(r.list.total, 0)
  assert.equal(r.list.returned, 0)
})

// ---- the single-detection route ------------------------------------------

test('getDetection returns the object on 200', async () => {
  const one = FIXTURE.detections[0]!
  stubFetch(() => ({ status: 200, body: one }))

  const r = await getDetection(12)
  assert.equal(calls[0], '/api/v1/detections/12')
  assert.equal(r.state, 'ok')
  if (r.state !== 'ok') return
  assert.equal(r.detection.id, 12)
  assert.equal(r.detection.count, 7)
})

test('getDetection says a 404 could be either missing route or missing detection', async () => {
  stubFetch(() => ({ status: 404, text: '404 page not found' }))

  const r = await getDetection(999)
  assert.equal(r.state, 'unavailable')
  if (r.state !== 'unavailable') return
  assert.match(r.message, /no detection 999/)
  assert.match(r.message, /#117/)
})
