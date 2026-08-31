import { useCallback, useState } from 'react'

import { startReplay, stopReplay } from '../api/client'
import { useStream } from '../api/stream'
import { fmtInt } from '../lib/format'
import { usePersistedState } from '../lib/persist'

const SPEEDS = ['1', '0.5', '2', '10', 'max']

function useReplay() {
  const { status, refreshStatus } = useStream()
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const start = useCallback(
    async (path: string, speed: string) => {
      setBusy(true)
      const r = await startReplay(path, speed)
      setMsg(r.ok ? 'start accepted' : `start failed: ${r.message}`)
      setBusy(false)
      refreshStatus()
    },
    [refreshStatus],
  )

  const stop = useCallback(async () => {
    setBusy(true)
    const r = await stopReplay()
    setMsg(r.ok ? 'stop sent' : `stop failed: ${r.message}`)
    setBusy(false)
    refreshStatus()
  }, [refreshStatus])

  return { replay: status.replay, busy, msg, start, stop }
}

function statusLine(
  replay: ReturnType<typeof useReplay>['replay'],
  msg: string,
): string {
  if (replay.running) {
    return `running ${replay.source ?? '?'} @${replay.speed ?? '?'} — ${fmtInt(replay.packets)} pkts, ${fmtInt(replay.flows)} flows`
  }
  if (replay.last_error) return `error: ${replay.last_error}`
  return msg || 'idle'
}

/** Compact footer control — same path / speed / start / stop / status as the old shell. */
export function ReplayBar() {
  const { replay, busy, msg, start, stop } = useReplay()
  const [path, setPath] = usePersistedState('replay.path', 'testdata/pcap/portscan.pcap')
  const [speed, setSpeed] = usePersistedState('replay.speed', 'max')

  return (
    <>
      <span className="dim">replay:</span>
      <input
        className="rpath"
        aria-label="replay pcap path"
        placeholder="/path/to/capture.pcap"
        value={path}
        onChange={(e) => setPath(e.target.value)}
      />
      <select aria-label="replay speed" value={speed} onChange={(e) => setSpeed(e.target.value)}>
        {SPEEDS.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>
      <button disabled={busy || replay.running || !path.trim()} onClick={() => start(path.trim(), speed)}>
        Start
      </button>
      <button disabled={busy || !replay.running} onClick={() => stop()}>
        Stop
      </button>
      <span className="dim" style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
        {statusLine(replay, msg)}
      </span>
      <span className="thugs">&#10214;THUGS&#10215; &#183; (c) 2026</span>
    </>
  )
}

/** Fuller page control used by the CAPTURE ▸ Replay route. */
export function ReplayPanel() {
  const { replay, busy, msg, start, stop } = useReplay()
  const [path, setPath] = usePersistedState('replay.path', 'testdata/pcap/portscan.pcap')
  const [speed, setSpeed] = usePersistedState('replay.speed', 'max')

  return (
    <div className="card span2">
      <h3>Replay control</h3>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', margin: '4px 0 10px' }}>
        <input
          className="rpath"
          aria-label="replay pcap path"
          placeholder="/path/to/capture.pcap"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          style={{ flex: 1, minWidth: 220 }}
        />
        <select aria-label="replay speed" value={speed} onChange={(e) => setSpeed(e.target.value)}>
          {SPEEDS.map((s) => (
            <option key={s} value={s}>
              {s === 'max' ? 'max' : `${s}×`}
            </option>
          ))}
        </select>
        <button
          className="on"
          disabled={busy || replay.running || !path.trim()}
          onClick={() => start(path.trim(), speed)}
        >
          Start
        </button>
        <button disabled={busy || !replay.running} onClick={() => stop()}>
          Stop
        </button>
      </div>
      <dl className="kv">
        <dt>state</dt>
        <dd>{replay.running ? 'running' : 'idle'}</dd>
        <dt>source</dt>
        <dd className="mono">{replay.source ?? '—'}</dd>
        <dt>speed</dt>
        <dd>{replay.speed ?? '—'}</dd>
        <dt>packets</dt>
        <dd className="mono">{fmtInt(replay.packets)}</dd>
        <dt>flows</dt>
        <dd className="mono">{fmtInt(replay.flows)}</dd>
        {replay.last_error ? (
          <>
            <dt>last error</dt>
            <dd className="err">{replay.last_error}</dd>
          </>
        ) : null}
        {msg ? (
          <>
            <dt>action</dt>
            <dd className="dim">{msg}</dd>
          </>
        ) : null}
      </dl>
    </div>
  )
}
