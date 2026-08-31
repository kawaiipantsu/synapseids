import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react'

import { createCapture, deleteCapture, getCaptures } from '../api/client'
import type { CaptureKind, CaptureSourceInput, CaptureSourceStatus } from '../api/types'
import { fmtAgo, fmtBytes, fmtDateTime, fmtInt, fmtNum } from '../lib/format'
import { usePersistedState } from '../lib/persist'

const POLL_MS = 1000
const KINDS: CaptureKind[] = ['nic', 'tcpdump', 'ssh', 'pcap-over-ip']
const NIC_FILTERS = ['', 'ip', 'ip6', 'ip-any', 'not-arp']

// ---- authorization mirror (server is the authority; this keeps the form honest)
function hostIsLoopback(addr: string): boolean {
  let host = addr.trim()
  const m = host.match(/^\[(.+)\]:\d+$/) // [::1]:4789
  if (m) host = m[1]!
  else if (host.includes(':')) host = host.slice(0, host.lastIndexOf(':'))
  host = host.replace(/^\[|\]$/g, '')
  return host === 'localhost' || host === '::1' || /^127\./.test(host)
}

function authReason(d: DraftState): string | null {
  if (d.kind === 'ssh') return 'remote SSH capture (PROJECT.md §28.18)'
  if (d.kind === 'pcap-over-ip') {
    if (d.insecure_tls) return 'insecure_tls disables certificate verification'
    if (d.addr.trim() && !hostIsLoopback(d.addr)) return 'a non-loopback sensor address'
    if (!d.token_file.trim()) return 'connecting without a bearer token'
  }
  return null
}

// ---- draft ---------------------------------------------------------------
interface DraftState {
  name: string
  kind: CaptureKind
  interface: string
  promiscuous: boolean
  snaplen: string
  filter: string
  binary: string
  destination: string
  port: string
  identity_file: string
  remote_binary: string
  known_hosts: string
  addr: string
  token_file: string
  server_name: string
  ca_file: string
  client_cert_file: string
  client_key_file: string
  insecure_tls: boolean
  authorized: boolean
}

const EMPTY_DRAFT: DraftState = {
  name: '',
  kind: 'nic',
  interface: '',
  promiscuous: false,
  snaplen: '',
  filter: '',
  binary: '',
  destination: '',
  port: '',
  identity_file: '',
  remote_binary: '',
  known_hosts: 'strict',
  addr: '',
  token_file: '',
  server_name: '',
  ca_file: '',
  client_cert_file: '',
  client_key_file: '',
  insecure_tls: false,
  authorized: false,
}

function toBody(d: DraftState): CaptureSourceInput {
  const b: CaptureSourceInput = { name: d.name.trim(), kind: d.kind }
  const s = (v: string) => v.trim() || undefined
  const n = (v: string) => {
    const x = Number(v)
    return v.trim() && Number.isFinite(x) ? x : undefined
  }
  if (d.kind === 'nic') {
    b.interface = s(d.interface)
    if (d.promiscuous) b.promiscuous = true
    b.snaplen = n(d.snaplen)
    b.filter = s(d.filter)
  } else if (d.kind === 'tcpdump') {
    b.interface = s(d.interface)
    b.filter = s(d.filter)
    b.snaplen = n(d.snaplen)
    b.binary = s(d.binary)
  } else if (d.kind === 'ssh') {
    b.destination = s(d.destination)
    b.interface = s(d.interface)
    b.filter = s(d.filter)
    b.snaplen = n(d.snaplen)
    b.binary = s(d.binary)
    b.port = n(d.port)
    b.identity_file = s(d.identity_file)
    b.remote_binary = s(d.remote_binary)
    b.known_hosts = s(d.known_hosts)
  } else {
    b.addr = s(d.addr)
    b.token_file = s(d.token_file)
    b.server_name = s(d.server_name)
    b.ca_file = s(d.ca_file)
    b.client_cert_file = s(d.client_cert_file)
    b.client_key_file = s(d.client_key_file)
    if (d.insecure_tls) b.insecure_tls = true
  }
  if (d.authorized) b.authorized = true
  return b
}

// ---- status table ------------------------------------------------------
function stateClass(state: string): string {
  if (state === 'running') return 'running'
  if (state === 'error') return 'error'
  return 'stopped'
}

function latencyCell(s: CaptureSourceStatus): string {
  if (s.kind !== 'pcap-over-ip') return 'n/a'
  return s.connection_latency_ms > 0 ? `${fmtInt(s.connection_latency_ms)} ms` : '—'
}

function SourceRow({
  s,
  now,
  busy,
  onRemove,
}: {
  s: CaptureSourceStatus
  now: number
  busy: boolean
  onRemove: (name: string) => void
}) {
  return (
    <>
      <tr>
        <td>
          <b>{s.name}</b>
          {s.origin === 'config' ? <span className="src-badge">from config</span> : null}
          {s.origin === 'api' ? <span className="src-badge api">runtime</span> : null}
        </td>
        <td className="mono">{s.kind}</td>
        <td>
          <span className={`src-state ${stateClass(s.state)}`}>{s.state}</span>
        </td>
        <td className="num">{fmtInt(s.packets)}</td>
        <td className="num">{fmtBytes(s.bytes)}</td>
        <td className="num">{fmtNum(s.pps, 1)}</td>
        <td className="num">{fmtBytes(s.bps)}/s</td>
        <td className="num">{fmtInt(s.drops)}</td>
        <td className="num">{fmtInt(s.decode_errors)}</td>
        <td title={fmtDateTime(s.last_packet)}>{fmtAgo(s.last_packet, now)}</td>
        <td className="mono">{s.filter || '(all)'}</td>
        <td className="num">{latencyCell(s)}</td>
        <td>
          <button
            className="src-rm"
            disabled={busy}
            onClick={() => onRemove(s.name)}
            title="stop and remove this source"
          >
            remove
          </button>
        </td>
      </tr>
      {s.state === 'error' && s.error ? (
        <tr className="src-errrow">
          <td colSpan={13}>
            <span className="err">error:</span> {s.error}
          </td>
        </tr>
      ) : null}
    </>
  )
}

// ---- form fields -----------------------------------------------------
function Field({
  label,
  children,
  hint,
}: {
  label: string
  children: ReactNode
  hint?: string
}) {
  return (
    <label className="src-field">
      <span>{label}</span>
      {children}
      {hint ? <span className="hint">{hint}</span> : null}
    </label>
  )
}

export function CaptureSources() {
  const [rows, setRows] = useState<CaptureSourceStatus[]>([])
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [now, setNow] = useState(() => Date.now())

  const [draft, setDraft] = usePersistedState<DraftState>('capture.draft', EMPTY_DRAFT)
  const set = <K extends keyof DraftState>(k: K, v: DraftState[K]) => setDraft({ ...draft, [k]: v })

  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // poll ----------------------------------------------------------------
  const load = useCallback(() => {
    getCaptures()
      .then((r) => {
        setRows(r)
        setLoadErr(null)
      })
      .catch((e: unknown) => setLoadErr(e instanceof Error ? e.message : String(e)))
  }, [])

  const loadRef = useRef(load)
  loadRef.current = load
  useEffect(() => {
    loadRef.current()
    const id = window.setInterval(() => {
      setNow(Date.now())
      loadRef.current()
    }, POLL_MS)
    return () => window.clearInterval(id)
  }, [])

  const reason = useMemo(() => authReason(draft), [draft])
  const needsAuth = reason != null
  const nameOk = draft.name.trim().length > 0
  const canSubmit = !busy && nameOk && (!needsAuth || draft.authorized)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return
    setBusy(true)
    setMsg(null)
    const r = await createCapture(toBody(draft))
    setBusy(false)
    if (r.ok) {
      setMsg({ ok: true, text: `added "${draft.name.trim()}" (${draft.kind})` })
      setDraft({ ...EMPTY_DRAFT, kind: draft.kind })
      load()
    } else {
      setMsg({ ok: false, text: `${r.status}: ${r.message}` })
    }
  }

  const remove = async (name: string) => {
    if (!window.confirm(`Remove capture source "${name}"?\nThis stops live capture / kills its subprocess / ends its SSH or TLS session.`)) {
      return
    }
    setBusy(true)
    setMsg(null)
    const r = await deleteCapture(name)
    setBusy(false)
    setMsg(r.ok ? { ok: true, text: `removed "${name}"` } : { ok: false, text: `${r.status}: ${r.message}` })
    load()
  }

  const k = draft.kind

  return (
    <div>
      <div className="page-h">
        <h1>Capture Sources</h1>
        <span className="sub">
          live <code>GET /api/v1/captures</code> (polled 1s); add / remove drive{' '}
          <code>POST</code> / <code>DELETE /api/v1/captures</code> — a runtime source runs the exact
          same pipeline as a config one (§19.14)
        </span>
      </div>

      {loadErr ? <div className="src-msg err">capture list unavailable — {loadErr}</div> : null}

      <div className="card wide">
        <h3>Sources ({rows.length})</h3>
        {rows.length === 0 ? (
          <div className="foot">no capture sources — add one below, or start the daemon with <code>capture.sources[]</code></div>
        ) : (
          <div className="src-scroll">
            <table className="mini src-table">
              <thead>
                <tr>
                  <th>name</th>
                  <th>kind</th>
                  <th>state</th>
                  <th className="num">packets</th>
                  <th className="num">bytes</th>
                  <th className="num">pps</th>
                  <th className="num">bps</th>
                  <th className="num">drops</th>
                  <th className="num">dec.err</th>
                  <th>last packet</th>
                  <th>filter</th>
                  <th className="num">conn.lat</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => (
                  <SourceRow key={s.name} s={s} now={now} busy={busy} onRemove={remove} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <form className="card wide src-form" onSubmit={submit}>
        <h3>Add a source</h3>

        <div className="src-grid">
          <Field label="name" hint="unique label shown above">
            <input value={draft.name} onChange={(e) => set('name', e.target.value)} placeholder="wan0" />
          </Field>
          <Field label="kind">
            <select value={k} onChange={(e) => set('kind', e.target.value as CaptureKind)}>
              {KINDS.map((x) => (
                <option key={x} value={x}>
                  {x}
                </option>
              ))}
            </select>
          </Field>

          {(k === 'nic' || k === 'tcpdump' || k === 'ssh') && (
            <Field label="interface" hint={k === 'ssh' ? 'the remote NIC' : 'local NIC'}>
              <input
                value={draft.interface}
                onChange={(e) => set('interface', e.target.value)}
                placeholder="eth0"
              />
            </Field>
          )}

          {k === 'nic' && (
            <>
              <Field label="filter" hint="built-in cBPF preset">
                <select value={draft.filter} onChange={(e) => set('filter', e.target.value)}>
                  {NIC_FILTERS.map((f) => (
                    <option key={f} value={f}>
                      {f || '(all)'}
                    </option>
                  ))}
                </select>
              </Field>
              <label className="src-field row">
                <input
                  type="checkbox"
                  checked={draft.promiscuous}
                  onChange={(e) => set('promiscuous', e.target.checked)}
                />
                <span>promiscuous</span>
              </label>
              <Field label="snaplen" hint="0 = default">
                <input
                  type="number"
                  value={draft.snaplen}
                  onChange={(e) => set('snaplen', e.target.value)}
                />
              </Field>
            </>
          )}

          {(k === 'tcpdump' || k === 'ssh') && (
            <Field label="filter" hint="raw tcpdump expression — argv, never a shell">
              <input
                value={draft.filter}
                onChange={(e) => set('filter', e.target.value)}
                placeholder="tcp port 80 or udp"
              />
            </Field>
          )}
          {(k === 'tcpdump' || k === 'ssh') && (
            <Field label={k === 'ssh' ? 'ssh binary' : 'tcpdump binary'} hint="blank = default on PATH">
              <input value={draft.binary} onChange={(e) => set('binary', e.target.value)} />
            </Field>
          )}
          {(k === 'tcpdump' || k === 'ssh') && (
            <Field label="snaplen" hint="0 = full packet">
              <input
                type="number"
                value={draft.snaplen}
                onChange={(e) => set('snaplen', e.target.value)}
              />
            </Field>
          )}

          {k === 'ssh' && (
            <>
              <Field label="destination" hint="user@host or ssh_config alias">
                <input
                  value={draft.destination}
                  onChange={(e) => set('destination', e.target.value)}
                  placeholder="sensor@10.0.0.9"
                />
              </Field>
              <Field label="port" hint="0 = ssh default">
                <input type="number" value={draft.port} onChange={(e) => set('port', e.target.value)} />
              </Field>
              <Field label="identity file" hint="ssh -i key path">
                <input
                  value={draft.identity_file}
                  onChange={(e) => set('identity_file', e.target.value)}
                />
              </Field>
              <Field label="remote binary" hint="blank = tcpdump">
                <input
                  value={draft.remote_binary}
                  onChange={(e) => set('remote_binary', e.target.value)}
                />
              </Field>
              <Field label="known hosts">
                <select
                  value={draft.known_hosts}
                  onChange={(e) => set('known_hosts', e.target.value)}
                >
                  <option value="strict">strict</option>
                  <option value="accept-new">accept-new</option>
                </select>
              </Field>
            </>
          )}

          {k === 'pcap-over-ip' && (
            <>
              <Field label="addr" hint="sensor host:port">
                <input
                  value={draft.addr}
                  onChange={(e) => set('addr', e.target.value)}
                  placeholder="127.0.0.1:4789"
                />
              </Field>
              <Field label="token file" hint="path to the bearer token — inline tokens are refused (§23)">
                <input
                  value={draft.token_file}
                  onChange={(e) => set('token_file', e.target.value)}
                  placeholder="/etc/synapse/poip.tok"
                />
              </Field>
              <Field label="server name" hint="TLS SNI / cert name (default: host of addr)">
                <input
                  value={draft.server_name}
                  onChange={(e) => set('server_name', e.target.value)}
                />
              </Field>
              <Field label="ca file" hint="PEM bundle; blank = system roots">
                <input value={draft.ca_file} onChange={(e) => set('ca_file', e.target.value)} />
              </Field>
              <Field label="client cert file" hint="optional mutual TLS">
                <input
                  value={draft.client_cert_file}
                  onChange={(e) => set('client_cert_file', e.target.value)}
                />
              </Field>
              <Field label="client key file" hint="optional mutual TLS">
                <input
                  value={draft.client_key_file}
                  onChange={(e) => set('client_key_file', e.target.value)}
                />
              </Field>
              <label className="src-field row">
                <input
                  type="checkbox"
                  checked={draft.insecure_tls}
                  onChange={(e) => set('insecure_tls', e.target.checked)}
                />
                <span>insecure_tls (skip cert verification)</span>
              </label>
            </>
          )}
        </div>

        <label className={`src-auth ${needsAuth && !draft.authorized ? 'required' : ''}`}>
          <input
            type="checkbox"
            checked={draft.authorized}
            onChange={(e) => set('authorized', e.target.checked)}
          />
          <span>
            I am authorised to monitor this target.
            {needsAuth ? (
              <b> Required for {reason}.</b>
            ) : (
              <span className="dim"> (asserted on the source as authorized:true)</span>
            )}
          </span>
        </label>

        <div className="src-actions">
          <button type="submit" className="on" disabled={!canSubmit}>
            {busy ? 'working…' : 'Add source'}
          </button>
          <button type="button" disabled={busy} onClick={() => setDraft({ ...EMPTY_DRAFT, kind: k })}>
            Reset
          </button>
          {msg ? <span className={`src-msg ${msg.ok ? 'ok' : 'err'}`}>{msg.text}</span> : null}
        </div>
        <div className="foot">
          the daemon validates every field exactly as it validates <code>capture.sources[]</code> in
          the config file; a rejection shows here verbatim. This endpoint is loopback-only and
          unauthenticated for now (issue&nbsp;#58).
        </div>
      </form>
    </div>
  )
}
