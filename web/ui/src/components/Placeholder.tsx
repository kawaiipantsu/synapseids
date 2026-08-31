import { IssueLinks } from './IssueLink'

interface Props {
  title: string
  /** Open tracking issues. At least one — never a bare phase number. */
  issues: number[]
  /**
   * The epic this sits under, e.g. "EPIC: Phase 7 — Advanced ML". Only pass one
   * that is still open; a closed epic turns a correct "not built yet" notice
   * into a broken promise (issue #118).
   */
  epic?: string
  note?: string
}

/**
 * Every §19 view that is not built yet renders one of these: a "Planned" panel
 * naming the **open** issues that track the work.
 *
 * The rule this component exists to enforce is that a labelled gap must be
 * checkable. Citing "Phase 2" after Phase 2 closed tells an operator the notice
 * is stale, not that the feature is missing; citing an issue number they can
 * open tells them exactly where the work is. PROJECT.md §16 makes the gap itself
 * legitimate — inventing a number to fill the panel would not be.
 */
export function Placeholder({ title, issues, epic, note }: Props) {
  return (
    <div className="placeholder">
      <h1>{title}</h1>
      <div className="phase">Not built yet</div>
      <p>
        Tracked by <IssueLinks issues={issues} />
        {epic ? (
          <>
            {' '}
            under <b>{epic}</b>
          </>
        ) : null}
        .
      </p>
      {note ? <p>{note}</p> : null}
      <p className="dim">
        This view shows no numbers rather than placeholder ones — see PROJECT.md §16.
      </p>
    </div>
  )
}
