import { TrafficNetwork } from '../components/TrafficNetwork'

export function Network() {
  return (
    <div className="visual-page">
      <div className="page-h">
        <div>
          <div className="eyebrow">LIVE / NETWORK</div>
          <h1>See how your network connects.</h1>
          <p className="sub">
            Explore assets, follow conversations, and trace a classification
            back to its traffic.
          </p>
        </div>
      </div>
      <TrafficNetwork />
    </div>
  )
}
