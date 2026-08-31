package api

// Sensor topology (PROJECT.md §19.15, issue #46): the connected sensors grouped
// by the location each one reported, with per-location aggregates.
//
// # The honest part
//
// §19.15 asks that clicking a location or a sensor scope the other views, so the
// first question is whether a stored flow can be attributed to the sensor that
// produced it. Today, only partly:
//
//   - `flow`- and `feature`-mode SYNPOIP sensors send pre-aggregated records that
//     the collector tags with the sensor id, and the pipeline copies that id onto
//     storage.Classification.Sensor. Those rows are attributable, and sensor= /
//     location= really do scope them.
//   - `raw`-mode sensors are not attributable. Their packets are merged into the
//     capture.Manager's single output channel, and neither packet.Packet nor
//     flow.Record has a sensor field, so by the time a flow record exists the
//     origin is gone and the row is labelled "local" — the same label a local NIC
//     or a PCAP replay gets. Fixing that means putting sensor identity on the
//     packet path and in flow.Key (otherwise two sensors' identical 5-tuples
//     merge into one flow), which is a data-plane change, not an API one.
//
// Rather than ship a filter that quietly returns nothing, this response states
// per sensor whether its flows can be scoped, in FlowAttribution. A client is
// expected to read it and offer counter-scoped detail instead of a flow filter
// where it says "none". ADR 0026 has the full reasoning and what was deferred.

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
)

// UnassignedLocation is the bucket a sensor lands in when it reported no
// location. It is a sentinel for grouping and for the location= parameter — the
// response also sets Unassigned:true, so a client never has to infer intent from
// the string, and no location is invented for the sensor itself.
const UnassignedLocation = "unassigned"

// LocalSensorLabel is the value storage.Classification.Sensor carries for every
// row built locally from packets: local captures, PCAP replay, and raw-mode
// sensors alike. sensor=local is therefore a legitimate, working scope — it just
// does not mean "one sensor".
const LocalSensorLabel = "local"

// Flow-attribution verdicts for one sensor.
const (
	// AttributionRecords: this sensor ships tagged records, so sensor= and
	// location= scope its flows and classifications.
	AttributionRecords = "records"
	// AttributionNone: this sensor's packets merge into the local flow table
	// before a record exists. Its rows are indistinguishable from local capture,
	// and a sensor= scope would match nothing.
	AttributionNone = "none"
)

// Location health.
const (
	HealthOK       = "ok"
	HealthDegraded = "degraded"
	HealthDown     = "down"
)

// TopologySensor is one sensor row: everything GET /api/v1/sensors returns, plus
// whether its traffic can be scoped. SensorStatus is embedded rather than copied
// field by field so the two routes can never drift apart.
type TopologySensor struct {
	capture.SensorStatus
	// FlowAttribution is AttributionRecords or AttributionNone — see the package
	// comment. It is the field a UI must consult before offering "scope the flow
	// log to this sensor".
	FlowAttribution string `json:"flow_attribution"`
}

// TopologyLocation is one location group and its aggregates.
type TopologyLocation struct {
	// Location is exactly what the sensors reported, trimmed of surrounding
	// space, or UnassignedLocation for the empty bucket. It is the value to pass
	// back as location=, so a client never has to guess a spelling.
	Location string `json:"location"`
	// Unassigned marks the bucket holding sensors that reported no location.
	Unassigned bool `json:"unassigned"`

	SensorCount int    `json:"sensor_count"`
	Running     int    `json:"running"`
	Health      string `json:"health"`
	// Modes are the distinct sensor modes in use here, sorted.
	Modes []string `json:"modes"`

	Packets     uint64  `json:"packets"`
	Bytes       uint64  `json:"bytes"`
	Drops       uint64  `json:"drops"`
	Records     uint64  `json:"records"`
	RecordBytes uint64  `json:"record_bytes"`
	PPS         float64 `json:"pps"`
	BPS         float64 `json:"bps"`
	// LastPacket is the newest packet or record time across the group; zero when
	// nothing has arrived (every sensor here is in flow/feature mode, or none has
	// sent anything yet).
	LastPacket time.Time `json:"last_packet,omitempty"`

	// AttributableSensors is how many of these sensors' flows a sensor= or
	// location= scope can actually select. When it is 0, location= for this group
	// would match nothing, and a UI should scope to counters instead.
	AttributableSensors int `json:"attributable_sensors"`

	Sensors []TopologySensor `json:"sensors"`
}

// SensorTopology is the GET /api/v1/sensors/topology response.
type SensorTopology struct {
	// Locations holds named groups first, ordered by sensor count then name, with
	// the unassigned bucket last so it reads as an exception rather than a peer.
	Locations []TopologyLocation `json:"locations"`

	Sensors             int `json:"sensors"`
	LocationCount       int `json:"location_count"`
	UnassignedSensors   int `json:"unassigned_sensors"`
	AttributableSensors int `json:"attributable_sensors"`

	Packets     uint64  `json:"packets"`
	Bytes       uint64  `json:"bytes"`
	Drops       uint64  `json:"drops"`
	Records     uint64  `json:"records"`
	RecordBytes uint64  `json:"record_bytes"`
	PPS         float64 `json:"pps"`
	BPS         float64 `json:"bps"`

	// Collector is false when no SYNPOIP collector is wired at all, which is why
	// Locations is empty. Distinguishing that from "a collector with no sensors
	// connected" saves an operator from debugging the wrong thing.
	Collector bool `json:"collector"`

	// ScopeSensorParam and ScopeLocationParam name the query parameters that
	// scope the flow and classification lists to a selection here.
	ScopeSensorParam   string `json:"scope_sensor_param"`
	ScopeLocationParam string `json:"scope_location_param"`
	// LocalSensorLabel is the sensor value carried by locally-built rows, so a
	// client can offer "local capture" as a scope alongside real sensors.
	LocalSensorLabel string `json:"local_sensor_label"`
	// ScopeNote states the attribution limitation in one sentence, for a UI that
	// wants to show the caveat rather than restate it in its own words.
	ScopeNote string `json:"scope_note"`
}

const scopeNote = "sensor= and location= match the sensor id stored on a classification. " +
	"Only flow- and feature-mode sensors carry one; raw-mode sensors' packets merge " +
	"into the local flow table and their rows are labelled \"local\", so check each " +
	"sensor's flow_attribution before scoping."

// flowAttribution reports whether this sensor's mode tags the rows it produces.
// The record modes are authoritative here because the collector tags exactly the
// record frames and nothing else (see internal/capture/records.go).
func flowAttribution(mode string) string {
	switch mode {
	case pcapoverip.ModeFlow.String(), pcapoverip.ModeFeature.String():
		return AttributionRecords
	default:
		return AttributionNone
	}
}

// handleSensorTopology serves GET /api/v1/sensors/topology.
//
// It is a sibling of /sensors rather than a shape change to it: /sensors is a
// flat list several views already consume, and grouping is a different question
// asked of the same facts. With no collector wired it returns an empty grouping
// with collector:false — never a 503 — so the view always renders.
//
// Note on routing: this literal path is registered alongside GET
// /api/v1/sensors/{id}, and Go's ServeMux prefers the more specific pattern, so
// the literal wins. A sensor whose id were literally "topology" would be
// unreachable by that route and must be read from the list instead.
func (s *Server) handleSensorTopology(w http.ResponseWriter, _ *http.Request) {
	out := SensorTopology{
		Locations:          []TopologyLocation{},
		Collector:          s.sensors != nil,
		ScopeSensorParam:   "sensor",
		ScopeLocationParam: "location",
		LocalSensorLabel:   LocalSensorLabel,
		ScopeNote:          scopeNote,
	}
	var list []capture.SensorStatus
	if s.sensors != nil {
		list = s.sensors.Sensors()
	}

	// Group by the location the sensor reported, verbatim apart from trimming.
	// No normalisation beyond that: "WAN" and "wan" stay distinct groups because
	// merging them would mean choosing a spelling neither sensor sent, and the
	// location= parameter matches these same strings exactly.
	groups := map[string]*TopologyLocation{}
	order := []string{}
	for _, st := range list {
		key := strings.TrimSpace(st.Location)
		unassigned := key == ""
		if unassigned {
			key = UnassignedLocation
		}
		g, ok := groups[key]
		if !ok {
			g = &TopologyLocation{
				Location:   key,
				Unassigned: unassigned,
				Modes:      []string{},
				Sensors:    []TopologySensor{},
			}
			groups[key] = g
			order = append(order, key)
		}

		attr := flowAttribution(st.Mode)
		g.Sensors = append(g.Sensors, TopologySensor{SensorStatus: st, FlowAttribution: attr})
		g.SensorCount++
		if st.State == capture.StateRunning {
			g.Running++
		}
		if attr == AttributionRecords {
			g.AttributableSensors++
		}
		g.Packets += st.Packets
		g.Bytes += st.Bytes
		g.Drops += st.Drops
		g.Records += st.Records
		g.RecordBytes += st.RecordBytes
		g.PPS += st.PPS
		g.BPS += st.BPS
		if st.LastPacket.After(g.LastPacket) {
			g.LastPacket = st.LastPacket
		}
		if st.Mode != "" && !containsString(g.Modes, st.Mode) {
			g.Modes = append(g.Modes, st.Mode)
		}
	}

	for _, key := range order {
		g := groups[key]
		g.Health = locationHealth(g)
		sort.Strings(g.Modes)
		// Deterministic sensor order within a group.
		sort.Slice(g.Sensors, func(i, j int) bool {
			if g.Sensors[i].SensorID != g.Sensors[j].SensorID {
				return g.Sensors[i].SensorID < g.Sensors[j].SensorID
			}
			return g.Sensors[i].SessionID < g.Sensors[j].SessionID
		})
		out.Locations = append(out.Locations, *g)

		out.Sensors += g.SensorCount
		out.AttributableSensors += g.AttributableSensors
		out.Packets += g.Packets
		out.Bytes += g.Bytes
		out.Drops += g.Drops
		out.Records += g.Records
		out.RecordBytes += g.RecordBytes
		out.PPS += g.PPS
		out.BPS += g.BPS
		if g.Unassigned {
			out.UnassignedSensors = g.SensorCount
		}
	}

	// Busiest named location first; the unassigned bucket always last.
	sort.SliceStable(out.Locations, func(i, j int) bool {
		a, b := out.Locations[i], out.Locations[j]
		if a.Unassigned != b.Unassigned {
			return !a.Unassigned
		}
		if a.SensorCount != b.SensorCount {
			return a.SensorCount > b.SensorCount
		}
		return a.Location < b.Location
	})
	out.LocationCount = len(out.Locations)

	writeJSON(w, http.StatusOK, out)
}

// locationHealth summarises a group: down when nothing is running, degraded when
// some sensor is not running or any sensor is dropping, ok otherwise. Drops are
// part of the verdict because a running sensor that is shedding packets is not
// healthy — §19.14 lists drops as a first-class signal.
func locationHealth(g *TopologyLocation) string {
	if g.SensorCount == 0 || g.Running == 0 {
		return HealthDown
	}
	if g.Running < g.SensorCount || g.Drops > 0 {
		return HealthDegraded
	}
	return HealthOK
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
