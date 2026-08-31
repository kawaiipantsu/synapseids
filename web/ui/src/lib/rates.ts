// Turning cumulative counters into per-second rates.
//
// /api/v1/captures, /api/v1/sensors/topology and /api/v1/status all report
// *totals* since a source started. A "packets / sec" card therefore has to
// differentiate them client-side, and the honest way to do that is the same way
// the daemon's own capture sampler does (internal/capture manager.sample):
// remember the previous reading and its timestamp, and divide the delta by the
// real elapsed time — never by the nominal poll interval.
//
// Two rules keep this from inventing numbers (PROJECT.md §16):
//
//   * a single reading is not a rate. The first sample only seeds the baseline;
//     `samples` stays at 1 and the caller renders "measuring…", not 0/s.
//   * a counter that moves backwards is a reset, not negative traffic. A replay
//     restarting, or a capture source being removed, drops the total; that
//     re-seeds the baseline and contributes no sample rather than a spike or a
//     negative rate.

/** One reading of the cumulative ingest counters. */
export interface Counters {
  packets: number
  bytes: number
  drops: number
}

export const ZERO_COUNTERS: Counters = { packets: 0, bytes: 0, drops: 0 }

/** Rolling per-second history derived from successive `Counters` readings. */
export interface RateSampler {
  /** the previous reading, or null before the first one */
  last: Counters | null
  /** Date.now() of `last` */
  lastAt: number
  /** per-second packet rates, oldest→newest, at most `window` entries */
  pktPerSec: number[]
  /** per-second byte rates, oldest→newest */
  bytesPerSec: number[]
  /** readings folded in so far; a rate needs at least 2 */
  samples: number
  /** resets observed (a counter moving backwards) */
  resets: number
}

export function newRateSampler(): RateSampler {
  return { last: null, lastAt: 0, pktPerSec: [], bytesPerSec: [], samples: 0, resets: 0 }
}

function trim(a: number[], window: number): void {
  if (a.length > window) a.splice(0, a.length - window)
}

/**
 * Fold one cumulative reading in, mutating `s`.
 *
 * `now` is the reading's wall-clock time in ms and `window` the number of
 * per-second entries to retain.
 */
export function pushSample(s: RateSampler, cur: Counters, now: number, window: number): void {
  const prev = s.last
  s.samples++
  s.last = cur
  const at = s.lastAt
  s.lastAt = now
  if (!prev) return // first reading: baseline only

  const dt = (now - at) / 1000
  if (!(dt > 0)) return

  if (cur.packets < prev.packets || cur.bytes < prev.bytes) {
    s.resets++
    return // a reset is not traffic
  }

  s.pktPerSec.push((cur.packets - prev.packets) / dt)
  s.bytesPerSec.push((cur.bytes - prev.bytes) / dt)
  trim(s.pktPerSec, window)
  trim(s.bytesPerSec, window)
}

/** The most recent entry of a rate series, or 0 when there is none yet. */
export function latest(series: number[]): number {
  return series.length ? series[series.length - 1]! : 0
}

/** Sum of `Counters`, used to fold several ingest paths into one total. */
export function addCounters(a: Counters, b: Counters): Counters {
  return {
    packets: a.packets + b.packets,
    bytes: a.bytes + b.bytes,
    drops: a.drops + b.drops,
  }
}
