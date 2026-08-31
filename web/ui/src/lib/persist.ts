import { useCallback, useState } from 'react'

const PREFIX = 'synapseids.'

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(PREFIX + key)
    if (raw == null) return fallback
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

function write<T>(key: string, value: T): void {
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value))
  } catch {
    // storage disabled / full / private mode — a lost preference is harmless.
  }
}

/**
 * useState backed by localStorage. Reads are best-effort and always tolerate a
 * missing or unreadable store (returns the fallback).
 */
export function usePersistedState<T>(key: string, fallback: T): [T, (v: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => read(key, fallback))
  const set = useCallback(
    (v: T | ((prev: T) => T)) => {
      setValue((prev) => {
        const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v
        write(key, next)
        return next
      })
    },
    [key],
  )
  return [value, set]
}
