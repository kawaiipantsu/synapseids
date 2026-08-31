import { useStream } from '../api/stream'
import { ReplayPanel } from '../components/ReplayControl'
import { fmtClock } from '../lib/format'

export function ReplayPage() {
  const { replayEvents } = useStream()

  return (
    <div>
      <div className="page-h">
        <h1>Replay</h1>
        <span className="sub">
          drives <code>POST /api/v1/replay</code> — replayed packets run the exact live pipeline, so
          the Flow Log and Dashboard react identically
        </span>
      </div>

      <div className="cards">
        <ReplayPanel />

        <div className="card span2">
          <h3>Replay events</h3>
          {replayEvents.length === 0 ? (
            <div className="foot">no replay activity this session</div>
          ) : (
            <table className="mini">
              <thead>
                <tr>
                  <th>time</th>
                  <th>event</th>
                  <th>detail</th>
                </tr>
              </thead>
              <tbody>
                {replayEvents.map((e) => (
                  <tr key={e.seq}>
                    <td className="dim mono">{fmtClock(e.ts)}</td>
                    <td>{e.type}</td>
                    <td className="dim">{e.text}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="foot">from ReplayStarted / ReplayProgress / ReplayFinished on the live stream</div>
        </div>
      </div>
    </div>
  )
}
