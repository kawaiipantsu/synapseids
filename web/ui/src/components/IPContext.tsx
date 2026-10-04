import { countryName, useIPContext } from '../lib/ipContext'
import { fmtDateTime } from '../lib/format'

export function CountryFlag({ code }: { code?: string }) {
  return code && /^[A-Z]{2}$/.test(code) ? <img className="country-flag" src={'/flags/' + code.toLowerCase() + '.svg'} alt={countryName(code)} width="18" height="14" loading="lazy" onError={(event) => { event.currentTarget.hidden = true }} /> : null
}

export function IPLabel({ ip, port }: { ip: string; port?: number }) {
  const info = useIPContext(ip)
  const name = info?.dns.names?.[0]
  const country = info?.geo.country
  const address = port === undefined ? ip : `${ip.includes(':') ? `[${ip}]` : ip}:${port}`
  return <span className="ip-label" title={[name, countryName(country), info?.geo.organization, info?.stale ? 'Cached context is being refreshed' : ''].filter(Boolean).join(' · ')}>
    <span className="ip-address"><CountryFlag code={country} />{address}</span>
    {name && <small className="ip-rdns">{name}</small>}
  </span>
}

/** SVG labels cannot contain HTML; the graph uses this small SVG counterpart. */
export function IPNodeLabel({ ip, y = 44 }: { ip: string; y?: number }) {
  const info = useIPContext(ip)
  const name = info?.dns.names?.[0]
  return <g>{info?.geo.country && /^[A-Z]{2}$/.test(info.geo.country) && <image x="18" y="14" width="18" height="14" href={'/flags/' + info.geo.country.toLowerCase() + '.svg'} aria-label={countryName(info.geo.country)} />}
  <text y={y} textAnchor="middle" fill="var(--ink)" fontSize="11">
    <title>{[ip, name, countryName(info?.geo.country)].filter(Boolean).join(' · ')}</title>
    {name ? (name.length > 24 ? name.slice(0, 22) + '…' : name) : ip}
  </text></g>
}

const statusLabel = (status?: string) => ({ ok: 'Available', pending: 'Looking up…', refreshing: 'Refreshing cached data…', busy: 'Lookup queue busy; retrying', not_found: 'No record found', not_applicable: 'Private or special-use address', disabled: 'Disabled in configuration', unobserved: 'Waiting for an observed host', error: 'Lookup unavailable; cached retry scheduled', rate_limited: 'Provider rate limit; cached retry scheduled' }[status ?? ''] ?? 'Loading context…')
const date = (value?: string) => value && !value.startsWith('0001-') ? fmtDateTime(value) : '—'

export function HostContext({ ip }: { ip: string }) {
  const info = useIPContext(ip)
  return <section className="viz-panel host-context" aria-label="Host identity and location">
    <div className="panel-heading"><div><div className="eyebrow">IP CONTEXT</div><h2>Identity & location</h2></div><span className="context-cache">{info?.stale ? 'Refreshing cached context' : info?.status === 'ready' ? 'Cached lookup' : statusLabel(info?.status)}</span></div>
    <div className="context-columns">
      <div><h3>Reverse DNS</h3><p className="context-status">{statusLabel(info?.dns.status)}</p>
        {info?.dns.names?.map((name) => <div className="mono context-name" key={name}>{name}</div>)}
        <p className="foot">PTR records from the configured DNS resolver. A name is advisory and does not establish ownership.</p>
      </div>
      <div><h3><CountryFlag code={info?.geo.country} /> Geolocation</h3><p className="context-status">{statusLabel(info?.geo.status)}</p>
        {info?.geo.status === 'ok' && <dl className="context-facts">
          <dt>Country</dt><dd>{countryName(info.geo.country)} ({info.geo.country})</dd>
          <dt>Region / city</dt><dd>{[info.geo.subdivision, info.geo.city].filter(Boolean).join(' / ') || 'Not supplied'}</dd>
          <dt>Coordinates</dt><dd>{info.geo.latitude != null && info.geo.longitude != null ? `${info.geo.latitude.toFixed(3)}, ${info.geo.longitude.toFixed(3)}` : 'Not supplied'}</dd>
          <dt>Accuracy radius</dt><dd>{info.geo.accuracy_km != null ? `${info.geo.accuracy_km} km` : 'Not supplied'}</dd>
          <dt>Timezone</dt><dd>{info.geo.timezone || 'Not supplied'}</dd>
          <dt>Network</dt><dd>{[info.geo.asn ? `AS${info.geo.asn}` : '', info.geo.organization].filter(Boolean).join(' · ') || 'Not supplied'}</dd>
          <dt>Source</dt><dd>{info.geo.source}</dd>
        </dl>}
        <p className="foot">Approximate network location; VPNs, mobile networks and anycast can differ from a device's physical location.</p>
      </div>
      <div><h3>WHOIS / RDAP registration</h3><p className="context-status">{statusLabel(info?.whois.status)}</p>
        {info?.whois.status === 'ok' && <dl className="context-facts">
          <dt>Network name</dt><dd>{info.whois.name || 'Not supplied'}</dd>
          <dt>Handle</dt><dd>{info.whois.handle || 'Not supplied'}</dd>
          <dt>Allocation</dt><dd>{info.whois.start} – {info.whois.end}</dd>
          <dt>Type</dt><dd>{info.whois.type || 'Not supplied'}</dd>
          <dt>Registration country</dt><dd>{countryName(info.whois.country) || 'Not supplied'}</dd>
          <dt>Registry updated</dt><dd>{date(info.whois.updated)}</dd>
          <dt>Registry</dt><dd>{info.whois.source}</dd>
        </dl>}
        <p className="foot">Regional registry allocation via RDAP. Registration country is separate from geolocation.</p>
      </div>
    </div>
    <div className="context-footer foot">Updated {date(info?.updated_at)} · Expires {date(info?.expires_at)} · Cached on the daemon; refresh does not force provider queries.</div>
  </section>
}
