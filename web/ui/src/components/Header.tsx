import { useStream } from '../api/stream'
import { fmtInt } from '../lib/format'

// Ported from the old shell header: the SynapseIDS mark plus live
// flows / classified / clients counters and the WebSocket connection state.
export function Header() {
  const { status, connected } = useStream()
  return (
    <header className="appbar">
      <span className="mark">
        Synapse<b>&#9642;</b>IDS
      </span>
      <span className="stat">
        flows <b>{fmtInt(status.flows)}</b>
      </span>
      <span className="stat">
        classified <b>{fmtInt(status.classifications)}</b>
      </span>
      <span className="stat">
        clients <b>{fmtInt(status.clients)}</b>
      </span>
      <span className={`conn${connected ? ' live' : ''}`}>
        <span className="dot" />
        {connected ? 'live' : 'reconnecting…'}
      </span>
      {status.error ? (
        <span className="stat err" title={status.error}>
          status api unreachable
        </span>
      ) : null}
      <span className="spacer" />
      <span className="stat dim">
        {status.raw?.version ? String(status.raw.version) : 'synapsed'}
      </span>
    </header>
  )
}
