// Turning the cumulative ingest counters into per-second rates (issue #118).
//
// The Dashboard's Packets/sec and Throughput cards exist because the data was
// already on /api/v1/captures and /api/v1/sensors/topology — as *totals*. These
// tests pin the two rules that keep the derived rate from stating something the
// counters do not support (PROJECT.md §16): one reading is not a rate, and a
// counter going backwards is a reset rather than negative traffic.

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { addCounters, latest, newRateSampler, pushSample } from '../src/lib/rates.js'

const WINDOW = 5

test('the first reading only seeds the baseline — one sample is not a rate', () => {
  const s = newRateSampler()
  pushSample(s, { packets: 1000, bytes: 500_000, drops: 0 }, 1_000, WINDOW)

  assert.equal(s.samples, 1)
  assert.deepEqual(s.pktPerSec, [])
  assert.deepEqual(s.bytesPerSec, [])
  assert.equal(latest(s.pktPerSec), 0)
})

test('the second reading yields delta / real elapsed time', () => {
  const s = newRateSampler()
  pushSample(s, { packets: 1000, bytes: 500_000, drops: 0 }, 1_000, WINDOW)
  // 2.5 s later, +5000 packets and +1 MB.
  pushSample(s, { packets: 6000, bytes: 1_548_576, drops: 3 }, 3_500, WINDOW)

  assert.equal(s.samples, 2)
  assert.equal(latest(s.pktPerSec), 2000) // 5000 / 2.5
  assert.equal(latest(s.bytesPerSec), (1_548_576 - 500_000) / 2.5)
})

test('a nominal interval is never assumed — a late poll divides by the real gap', () => {
  const s = newRateSampler()
  pushSample(s, { packets: 0, bytes: 0, drops: 0 }, 0, WINDOW)
  // The browser tab was throttled: 10 s of wall clock, 1000 packets.
  pushSample(s, { packets: 1000, bytes: 0, drops: 0 }, 10_000, WINDOW)

  assert.equal(latest(s.pktPerSec), 100)
})

test('a counter moving backwards is a reset, not a negative rate', () => {
  const s = newRateSampler()
  pushSample(s, { packets: 9000, bytes: 900, drops: 0 }, 0, WINDOW)
  // A replay restarted, or the only capture source was removed.
  pushSample(s, { packets: 12, bytes: 4, drops: 0 }, 1_000, WINDOW)

  assert.equal(s.resets, 1)
  assert.deepEqual(s.pktPerSec, [], 'no sample is contributed by a reset')

  // The reading that caused the reset is the new baseline, so the next one is
  // measured against it and is a real rate again.
  pushSample(s, { packets: 112, bytes: 104, drops: 0 }, 2_000, WINDOW)
  assert.equal(latest(s.pktPerSec), 100)
  assert.equal(latest(s.bytesPerSec), 100)
})

test('a zero or backwards clock contributes nothing', () => {
  const s = newRateSampler()
  pushSample(s, { packets: 0, bytes: 0, drops: 0 }, 5_000, WINDOW)
  pushSample(s, { packets: 100, bytes: 100, drops: 0 }, 5_000, WINDOW)
  pushSample(s, { packets: 200, bytes: 200, drops: 0 }, 4_000, WINDOW)

  assert.deepEqual(s.pktPerSec, [])
})

test('the series is bounded to the sparkline window', () => {
  const s = newRateSampler()
  for (let i = 0; i <= WINDOW + 4; i++) {
    pushSample(s, { packets: i * 10, bytes: i * 100, drops: 0 }, i * 1_000, WINDOW)
  }
  assert.equal(s.pktPerSec.length, WINDOW)
  assert.equal(s.bytesPerSec.length, WINDOW)
  // Every entry is the same 10 packets/s, oldest→newest.
  assert.deepEqual(s.pktPerSec, new Array(WINDOW).fill(10))
})

test('addCounters folds several ingest paths into one total', () => {
  const total = addCounters(
    addCounters({ packets: 10, bytes: 100, drops: 1 }, { packets: 5, bytes: 50, drops: 0 }),
    { packets: 1, bytes: 2, drops: 3 },
  )
  assert.deepEqual(total, { packets: 16, bytes: 152, drops: 4 })
})
