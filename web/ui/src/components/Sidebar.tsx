import { Icon } from './Icon'
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
              <span className="nav-label">
                <Icon
                  name={
                    r.path === '/network' || r.path === '/sensors'
                      ? 'network'
                      : r.path === '/dashboard'
                        ? 'dashboard'
                        : r.path === '/inference' || r.path === '/training'
                          ? 'brain'
                          : r.path === '/flow-log'
                            ? 'flow'
                            : r.path === '/timeline'
                              ? 'chart'
                              : r.path === '/detections' || r.path === '/review'
                                ? 'shield'
                                : r.path === '/investigate'
                                  ? 'search'
                                  : r.path === '/hosts'
                                    ? 'host'
                                    : r.path === '/replay'
                                      ? 'play'
                                      : 'layers'
                  }
                />
                {r.label}
              </span>
              {!r.live && <span className="tag">planned</span>}
            </Link>
          ))}
        </div>
      ))}
    </nav>
  )
}
