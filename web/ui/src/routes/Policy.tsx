import { useEffect, useState } from 'react'
import { CLASS_NAMES } from '../lib/classes'
import { fmtDateTime } from '../lib/format'

type Rule = { cidr: string; label: string; mode: 'owned' | 'exclude'; suppress_classes: string[] }
type PolicyDoc = { revision: number; rules: Rule[]; spamhaus: boolean; cins_army: boolean; abuseipdb: boolean; dnsbl: boolean }
type Provider = { id: string; status: string; entries: number; updated_at: string; copyright?: string }
export function Policy() {
  const [doc, setDoc] = useState<PolicyDoc | null>(null)
  const [providers, setProviders] = useState<Provider[]>([])
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [dirty, setDirty] = useState(false)
  const load = async () => {
    try { const r = await fetch('/api/v1/policy'); if (!r.ok) throw new Error(await r.text()); const v = await r.json() as { policy: PolicyDoc; providers: Provider[] }; setDoc(v.policy); setProviders(v.providers); setDirty(false); setError('') }
    catch (e) { setError(String(e)) }
  }
  useEffect(() => { void load() }, [])
  const edit = (value: PolicyDoc) => { setDoc(value); setDirty(true); setMessage('') }
  const rule = (index: number, patch: Partial<Rule>) => { if (doc) edit({ ...doc, rules: doc.rules.map((r, i) => i === index ? { ...r, ...patch } : r) }) }
  const save = async () => {
    setBusy(true); setError(''); setMessage('')
    try { const r = await fetch('/api/v1/policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(doc) }); if (!r.ok) throw new Error(await r.text()); setDoc(await r.json() as PolicyDoc); setDirty(false); setMessage('Saved. Policy applies immediately to new traffic. Feed changes are picked up within a minute.') }
    catch (e) { setError(String(e)) } finally { setBusy(false) }
  }
  return <div className="visual-page policy-page">
    <div className="page-h"><div><div className="eyebrow">NETWORK POLICY</div><h1>Assets, exclusions & reputation</h1><p className="dim">Manage trusted infrastructure and the evidence that accompanies each classification.</p></div><a className="btn" href="#/detections">View detections</a></div>
    {error && <p className="error" role="alert">{error}</p>}{message && <p className="policy-success" role="status">{message}</p>}
    {!doc ? <p>Loading policy…</p> : <>
      <section className="viz-panel"><div className="panel-heading"><div><div className="eyebrow">OWNERSHIP & SCOPE</div><h2>Address rules</h2></div><button onClick={() => edit({ ...doc, rules: [...doc.rules, { cidr: '', label: '', mode: 'owned', suppress_classes: [] }] })}>Add IP / CIDR</button></div>
        <p className="dim">Owned assets remain inspected. Selected classes suppress alerts only when this asset initiates the flow; the original classification stays visible. Excluded ranges bypass IDS for either endpoint.</p>
        {!doc.rules.length && <p className="empty">No rules yet. Add an address or range to identify your infrastructure.</p>}
        {doc.rules.map((r, i) => <div className="policy-rule" key={i}>
          <div className="policy-fields"><label>IP address / CIDR<input value={r.cidr} placeholder="192.0.2.10/32" onChange={e => rule(i, { cidr: e.target.value })} /></label><label>Asset label<input value={r.label} maxLength={80} placeholder="Cloud application server" onChange={e => rule(i, { label: e.target.value })} /></label><label>Inspection<select value={r.mode} onChange={e => rule(i, { mode: e.target.value as Rule['mode'], suppress_classes: [] })}><option value="owned">OWNED · inspect traffic</option><option value="exclude">EXCLUDED · bypass IDS</option></select></label><button onClick={() => edit({ ...doc, rules: doc.rules.filter((_, j) => i !== j) })}>Remove</button></div>
          {r.mode === 'owned' ? <fieldset className="policy-classes"><legend>Suppress alerts for selected classifications</legend>{CLASS_NAMES.filter(c => c !== 'normal').map(c => <label key={c}><input type="checkbox" checked={r.suppress_classes.includes(c)} onChange={e => rule(i, { suppress_classes: e.target.checked ? [...r.suppress_classes, c] : r.suppress_classes.filter(v => v !== c) })} />{c.toUpperCase().replace(/_/g, ' ')}</label>)}</fieldset> : <p className="policy-caution">Traffic to or from this range will have no new IDS flow records, classifications, or reputation lookups. Capture counters still measure received traffic.</p>}
        </div>)}
        <p className="foot">IPv4 and IPv6 supported. Any matching exclusion takes precedence. Rules persist across restarts; retained history is unchanged.</p>
      </section>
      <section className="viz-panel"><div className="panel-heading"><div><div className="eyebrow">ADVISORY INTELLIGENCE</div><h2>Reputation providers</h2></div><span className="dim">Cached · asynchronous</span></div>
        <div className="policy-providers">{([
          ['spamhaus', 'Spamhaus DROP', 'Public IPv4 / IPv6 ranges. BadRep tags. Refreshed every 6 hours.'],
          ['cins_army', 'CINS Army', 'Public threat intelligence IP list. BadRep tags. Refreshed every 6 hours.'],
          ['abuseipdb', 'AbuseIPDB', 'BadRep at confidence ≥75. Needs a local API key file; at most 100 unique checks/day.'],
          ['dnsbl', 'DNS RBL', 'Named DNS blocklists with explicit response-code meanings. Needs a local DNSBL configuration file.'],
        ] as const).map(([key, title, description]) => <label className="policy-provider" key={key}><input type="checkbox" checked={doc[key]} onChange={e => edit({ ...doc, [key]: e.target.checked })} /><div><strong>{title}</strong><p className="dim">{description}</p></div></label>)}</div>
        <p className="foot">Reputation is advisory evidence, separate from neural predictions. Only observed public addresses are queried. Exclusions bypass these lookups. Providers never receive private addresses or packet content.</p>
        <div className="table-wrap"><table><thead><tr><th>Provider</th><th>Status at last refresh</th><th>Cached entries</th><th>Last successful update</th></tr></thead><tbody>{providers.map(p => <tr key={p.id}><td>{p.id}</td><td>{p.status.replace(/_/g, ' ')}</td><td>{p.entries.toLocaleString()}</td><td>{p.updated_at.startsWith('0001') ? '—' : fmtDateTime(p.updated_at)}</td></tr>)}</tbody></table></div>
        {providers.filter(p => p.copyright).map(p => <p className="foot" key={p.id}>{p.copyright}</p>)}<p className="foot">Spamhaus Project DROP data · CINS Army / Sentinel IPS. Provider outages are shown as incomplete checks, never as a clean reputation.</p>
      </section>
      <div className="policy-actions"><button className="primary" disabled={busy || !dirty} onClick={() => void save()}>{busy ? 'Saving…' : 'Save policy'}</button><button disabled={busy} onClick={() => void load()}>Reload saved policy & provider status</button><span className="dim">{dirty ? 'Unsaved changes' : 'Saved policy'} · revision {doc.revision}</span></div>
    </>}
  </div>
}
