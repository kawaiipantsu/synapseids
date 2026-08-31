interface Props {
  title: string
  phase: number
  epic: string
  note?: string
}

/**
 * Every §19 view that is not in the Phase-1 slice renders one of these: a tidy
 * "Planned" panel that names the tracking epic so an operator knows where the
 * feature lives on the roadmap.
 */
export function Placeholder({ title, phase, epic, note }: Props) {
  return (
    <div className="placeholder">
      <h1>{title}</h1>
      <div className="phase">Planned — Phase {phase}</div>
      <p>
        Tracked under <b>{epic}</b>.
      </p>
      {note ? <p>{note}</p> : null}
      <p className="dim">
        The Phase-1 vertical slice ships the live Dashboard, Flow Log, Flow Inspector and
        Replay control only.
      </p>
    </div>
  )
}
