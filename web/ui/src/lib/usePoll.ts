import { useEffect, useState } from 'react'

/** One request at a time, stop on unmount, retain and label the last good result. */
export function usePoll<T>(
  load: () => Promise<T>,
  interval = 5000,
  paused = false,
) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [updated, setUpdated] = useState<Date | null>(null)
  useEffect(() => {
    if (paused) return
    let alive = true
    let timer: ReturnType<typeof setTimeout>
    const tick = async () => {
      try {
        const result = await load()
        if (alive) {
          setData(result)
          setError(null)
          setUpdated(new Date())
        }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e))
      } finally {
        if (alive) timer = setTimeout(tick, interval)
      }
    }
    void tick()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [load, interval, paused])
  return { data, error, updated }
}
