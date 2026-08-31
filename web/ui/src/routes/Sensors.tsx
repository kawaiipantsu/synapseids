import { useCallback, useEffect, useMemo, useState } from 'react'

import { getSensorTopology } from '../api/client'
import type { SensorTopology, TopologyLocation, TopologySensor } from '../api/types'
import { fmtAgo, fmtBytes, fmtDateTime, fmtInt, fmtNum } from '../lib/format'
import { navigateWith } from '../lib/hashRouter'
import { usePersistedState } from '../lib/persist'

// CAPTURE ▸ Sensors — the sensor topology view (PROJECT.md §19.15, issue #46).
//
// Sensors grouped by the location each one reported, with per-location
// aggregates, and clicking either a location or a sensor scopes the other views.
//
// The scoping is where this view has to be careful. §19.15 wants a click to pivot
// the application, but a flow can only be attributed to the sensor that produced
// it when that sensor ships pre-aggregated records (flow/feature mode). A
// raw-mode sensor's packets merge into the local flow table before a flow record
// exists, so its rows are labelled "local" and a sensor= filter would match
// nothing. The daemon tells us which is which in `flow_attribution`, and this
// view offers the scope only where it works — a disabled control with the reason
// beats a filter that silently returns an empty list. See ADR 0026.
//
// Every string here (sensor ids, locations, filters, agent versions) arrives from
// a remote peer and is therefore untrusted (§21, §28.11). All of it is rendered
// as text; nothing uses dangerouslySetInnerHTML, and values that reach a URL go
// through navigateWith, which encodes them.

const POLL_MS = 2000

function healthClass(h: string): string {
  if (h === 'ok') return 'ok'
  if (h === 'degraded') return 'degraded'
  return 'down'
}

function stateClass(state: string): string {
  if (state === 'running') return 'running'
  if (state === 'error') return 'error'
  return 'stopped'
}

/** A location's display label. The daemon never invents a location; the empty
 *  bucket arrives flagged, and only the label is ours. */
function locationLabel(g: TopologyLocation): string {
  return g.unassigned ? 'unassigned' : g.location
}

/**
 * The scope controls for one selection. `param` is the query parameter the
 * daemon named ("sensor" or "location") so the SPA is not hardcoding a dialect,
 * and `value` is the exact string the daemon spelled.
 */
function ScopeLinks({
  param,
  value,
  attributable,
  what,
}: {
  param: string
  value: string
  attributable: boolean
  what: string
}) {
  if (!attributable) {
    return (
      <span
        className="sn-scope-off"
        title={
          `${what} ships raw packets, which merge into the local flow table before a flow ` +
          `record exists. Its rows are labelled "local", so scoping the flow log to it ` +
          `would match nothing — its own counters above are the honest view. (ADR 0026)`
        }
      >
        counters only
      </span>
    )
  }
  return (
    <span className="sn-scope">
      <button
        onClick={(e) => {
          e.stopPropagation()
          navigateWith('/matrix', { [param]: value })
        }}
        title={`show the traffic matrix for ${value}`}
      >
        matrix
      </button>
      <button
        onClick={(e) => {
          e.stopPropagation()
          navigateWith('/flow-log', { [param]: value })
        }}
        title={`scope the rolling flow log to ${value}`}
      >
        flow log
      </button>
    </span>
  )
}

function SensorRow({ s, now }: { s: TopologySensor; now: number }) {
  const attributable = s.flow_attribution === 'records'
  // In flow/feature mode nothing is transferred as packets, so packet counters
  // are genuinely 0 rather than unmeasured — show the record counters instead.
  const recordMode = s.mode === 'flow' || s.mode === 'feature'
  return (
    <tr className={attributable ? undefined : 'sn-unattributed'}>
      <td>
        <b className="mono">{s.sensor_id || '(unnamed)'}</b>
        {s.remote_addr ? <span className="sn-addr mono">{s.remote_addr}</span> : null}
      </td>
      <td>
        <span className={`src-state ${stateClass(s.state)}`}>{s.state || 'unknown'}</span>
      </td>
      <td>
        <span className={`sn-mode ${s.mode || 'raw'}`}>{s.mode || 'raw'}</span>
      </td>
      <td className="num">{recordMode ? '—' : fmtNum(s.pps, 1)}</td>
      <td className="num">{recordMode ? '—' : `${fmtBytes(s.bps)}/s`}</td>
      <td className="num">{recordMode ? fmtInt(s.records) : fmtInt(s.packets)}</td>
      <td className="num">{recordMode ? fmtBytes(s.record_bytes) : fmtBytes(s.bytes)}</td>
      <td className={'num' + (s.drops > 0 ? ' sn-drops' : '')}>{fmtInt(s.drops)}</td>
      <td className="dim">{s.agent_version || '—'}</td>
      <td className="dim">{s.os_arch || '—'}</td>
      <td className="dim" title={s.last_packet ? fmtDateTime(s.last_packet) : 'nothing yet'}>
        {recordMode && !s.last_packet ? 'n/a' : fmtAgo(s.last_packet, now)}
      </td>
      <td>
        <ScopeLinks
          param="sensor"
          value={s.sensor_id}
          attributable={attributable}
          what={`Sensor ${s.sensor_id}`}
        />
      </td>
    </tr>
  )
}

function LocationCard({
  g,
  now,
  open,
  onToggle,
}: {
  g: TopologyLocation
  now: number
  open: boolean
  onToggle: () => void
}) {
  const scopeValue = g.unassigned ? 'unassigned' : g.location
  return (
    <div className={`sn-loc${g.unassigned ? ' unassigned' : ''}`}>
      <div className="sn-lochead" onClick={onToggle} role="button" tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            onToggle()
          }
        }}
      >
        <span className="sn-caret">{open ? '▾' : '▸'}</span>
        <h3>
          {locationLabel(g)}
          {g.unassigned ? (
            <span
              className="sn-hint"
              title="these sensors reported no location; the daemon groups them explicitly rather than guessing one"
            >
              no location reported
            </span>
          ) : null}
        </h3>
        <span className={`sn-health ${healthClass(g.health)}`}>{g.health}</span>
        <span className="sn-stat">
          <b>{fmtInt(g.sensor_count)}</b> sensor{g.sensor_count === 1 ? '' : 's'}
        </span>
        <span className="sn-stat">
          <b>{fmtInt(g.running)}</b> running
        </span>
        <span className="sn-stat">
          <b>{fmtNum(g.pps, 1)}</b> pps
        </span>
        <span className="sn-stat">
          <b>{fmtBytes(g.bps)}</b>/s
        </span>
        <span className={'sn-stat' + (g.drops > 0 ? ' sn-drops' : '')}>
          <b>{fmtInt(g.drops)}</b> drops
        </span>
        {g.records > 0 ? (
          <span className="sn-stat">
            <b>{fmtInt(g.records)}</b> records
          </span>
        ) : null}
        <span className="sn-modes">
          {g.modes.length === 0 ? (
            <span className="dim">no mode reported</span>
          ) : (
            g.modes.map((m) => (
              <span key={m} className={`sn-mode ${m}`}>
                {m}
              </span>
            ))
          )}
        </span>
        <span className="spacer" />
        <span
          className="sn-attr"
          title={`${g.attributable_sensors} of ${g.sensor_count} sensors here ship tagged records, so a location scope selects only their flows`}
        >
          {fmtInt(g.attributable_sensors)}/{fmtInt(g.sensor_count)} scopeable
        </span>
        <ScopeLinks
          param="location"
          value={scopeValue}
          attributable={g.attributable_sensors > 0}
          what={`Every sensor at ${locationLabel(g)}`}
        />
      </div>

      {open ? (
        <table className="flow compact sn-table">
          <thead>
            <tr>
              <th>sensor</th>
              <th>state</th>
              <th>mode</th>
              <th className="num">pps</th>
              <th className="num">bps</th>
              <th className="num">packets/records</th>
              <th className="num">volume</th>
              <th className="num">drops</th>
              <th>agent</th>
              <th>os/arch</th>
              <th>last packet</th>
              <th>scope</th>
            </tr>
          </thead>
          <tbody>
            {g.sensors.map((s) => (
              <SensorRow key={s.session_id || s.sensor_id} s={s} now={now} />
            ))}
          </tbody>
        </table>
      ) : null}
    </div>
  )
}

export function Sensors() {
  const [topo, setTopo] = useState<SensorTopology | null>(null)
  const [err, setErr] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [now, setNow] = useState(() => Date.now())
  const [live, setLive] = usePersistedState<boolean>('sensors.live', true)
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})

  const load = useCallback(() => {
    getSensorTopology()
      .then((t) => {
        setTopo(t)
        setErr('')
        setLoaded(true)
        setNow(Date.now())
      })
      .catch((e: unknown) => {
        setErr(e instanceof Error ? e.message : String(e))
        setLoaded(true)
      })
  }, [])

  useEffect(() => {
    load()
    if (!live) return
    const t = setInterval(load, POLL_MS)
    return () => clearInterval(t)
  }, [load, live])

  const locations = useMemo(() => topo?.locations ?? [], [topo])

  return (
    <div>
      <div className="page-h">
        <h1>Sensors</h1>
        <span className="sub">
          topology from <code>/api/v1/sensors/topology</code> (§19.15) — sensors grouped by the
          location each one reported; click a location or sensor to scope the other views
        </span>
      </div>

      <div className="flowbar">
        <label>
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          auto-refresh
        </label>
        <button onClick={load}>refresh</button>
        <span className="spacer" />
        {topo ? (
          <span className="dim">
            {fmtInt(topo.sensors)} sensor{topo.sensors === 1 ? '' : 's'} ·{' '}
            {fmtInt(topo.location_count)} location{topo.location_count === 1 ? '' : 's'} ·{' '}
            {fmtInt(topo.attributable_sensors)} scopeable · {fmtNum(topo.pps, 1)} pps ·{' '}
            {fmtBytes(topo.bps)}/s · {fmtInt(topo.drops)} drops
          </span>
        ) : null}
      </div>

      {err ? <p className="err">{err}</p> : null}

      {topo && !topo.collector ? (
        <div className="sect stub">
          <span className="tag">not configured</span> No SYNPOIP collector is wired, so no sensor
          can connect. Enable <code>capture.collector</code> in the daemon configuration (§5.3,
          §21: TLS and an authenticated sensor identity are required) and the sensors will appear
          here grouped by their <code>--location</code>.
        </div>
      ) : null}

      {topo && topo.collector && topo.sensors === 0 && loaded && !err ? (
        <div className="foot">
          The collector is listening, but no sensor has connected yet. Start one with{' '}
          <code>synapse-sensor --connect &lt;daemon&gt; --location &lt;name&gt;</code>.
        </div>
      ) : null}

      {locations.map((g) => {
        const key = g.unassigned ? ' unassigned' : g.location
        return (
          <LocationCard
            key={key}
            g={g}
            now={now}
            open={!collapsed[key]}
            onToggle={() => setCollapsed((c) => ({ ...c, [key]: !c[key] }))}
          />
        )
      })}

      {topo && topo.sensors > 0 ? (
        <div className="sect stub">
          <span className="tag">scope</span> {topo.scope_note} Locally captured traffic — a NIC, a
          PCAP replay, or any raw-mode sensor — is scopeable as{' '}
          <button
            className="sn-inline-link"
            onClick={() => navigateWith('/matrix', { sensor: topo.local_sensor_label })}
          >
            sensor={topo.local_sensor_label}
          </button>
          .
        </div>
      ) : null}
    </div>
  )
}
