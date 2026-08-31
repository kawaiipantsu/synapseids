import { useHashRoute } from '../lib/hashRouter'
import { DEFAULT_ROUTE } from '../lib/hashRouter'
import { resolveRoute } from '../routes/routes'
import { Header } from './Header'
import { ReplayBar } from './ReplayControl'
import { Sidebar } from './Sidebar'

function NotFound({ path }: { path: string }) {
  return (
    <div className="placeholder">
      <h1>Unknown view</h1>
      <p className="dim">
        No route matches <code>#{path}</code>.
      </p>
      <p>
        <a href={`#${DEFAULT_ROUTE}`}>Go to the Flow Log</a>
      </p>
    </div>
  )
}

export function Shell() {
  const path = useHashRoute()
  const route = resolveRoute(path)

  return (
    <div className="app">
      <Header />
      <div className="app-body">
        <Sidebar active={path} />
        <main className="content">{route ? route.element : <NotFound path={path} />}</main>
      </div>
      <footer className="appfoot">
        <ReplayBar />
      </footer>
    </div>
  )
}
