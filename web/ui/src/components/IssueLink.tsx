/** The repository every issue reference points at. */
const REPO = 'https://github.com/kawaiipantsu/synapseids'

/**
 * A citation for an unbuilt feature: "#53", linked to the tracking issue.
 *
 * Every "not built yet" notice in the SPA names an **open** issue this way.
 * Issue #118 was the alternative: notices that cited a development phase, which
 * went stale the moment the epic closed, so a correct "this is missing" message
 * read as a broken promise instead. An issue number stays checkable — and it
 * keeps the labelled gap PROJECT.md §16 requires from decaying into noise.
 *
 * The number is plain text inside the anchor, so it still says something useful
 * on an air-gapped install where the link cannot be followed.
 */
export function IssueLink({ n }: { n: number }) {
  return (
    <a href={`${REPO}/issues/${n}`} target="_blank" rel="noreferrer noopener">
      #{n}
    </a>
  )
}

/** A comma-separated run of IssueLinks. */
export function IssueLinks({ issues }: { issues: number[] }) {
  return (
    <>
      {issues.map((n, i) => (
        <span key={n}>
          {i > 0 ? ', ' : ''}
          <IssueLink n={n} />
        </span>
      ))}
    </>
  )
}
