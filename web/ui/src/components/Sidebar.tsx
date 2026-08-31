import { Link } from '../lib/hashRouter'
import { GROUP_ORDER, ROUTES } from '../routes/routes'

export function Sidebar({ active }: { active: string }) {
  return (
    <nav className="sidebar" aria-label="Primary">
      {GROUP_ORDER.map((group) => (
        <div key={group}>
          <div className="navgroup">{group}</div>
          {ROUTES.filter((r) => r.group === group).map((r) => (
            <Link
              key={r.path}
              to={r.path}
              className={`navlink${r.path === active ? ' active' : ''}`}
              aria-current={r.path === active ? 'page' : undefined}
            >
              <span>{r.label}</span>
              <span className="tag">{r.tag}</span>
            </Link>
          ))}
        </div>
      ))}
    </nav>
  )
}
