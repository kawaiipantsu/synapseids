// Package api serves the versioned REST surface and the single live WebSocket
// channel (PROJECT.md §18). It never streams raw packets: the live channel
// carries batched, server-filtered event envelopes and applies backpressure via
// the wshub Hub (PROJECT.md §22).
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/dataset"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/obs"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
	"github.com/kawaiipantsu/synapseids/internal/training"
	"github.com/kawaiipantsu/synapseids/internal/version"
	"github.com/kawaiipantsu/synapseids/internal/wshub"
	"github.com/kawaiipantsu/synapseids/web"
)

// ReplayStatus is the state of the replay subsystem.
type ReplayStatus struct {
	Running   bool      `json:"running"`
	ID        string    `json:"id,omitempty"`
	Source    string    `json:"source,omitempty"`
	Speed     string    `json:"speed,omitempty"`
	Started   time.Time `json:"started,omitempty"`
	Packets   uint64    `json:"packets"`
	Flows     uint64    `json:"flows"`
	LastError string    `json:"last_error,omitempty"`
}

// ReplayController lets the API drive PCAP replay without owning the pipeline.
type ReplayController interface {
	Start(path string, speed capture.Speed) (string, error)
	Stop() error
	Status() ReplayStatus
}

// FlowStats is a snapshot of the live flow table: its lifetime counters plus the
// configured cap. It is surfaced on /api/v1/status so flow-table growth and
// oldest-idle eviction pressure are visible without the API touching the packet
// path (PROJECT.md §22, §24).
type FlowStats struct {
	Active    int    `json:"active"`
	Started   uint64 `json:"started"`
	Closed    uint64 `json:"closed"`
	Snapshots uint64 `json:"snapshots"`
	Evicted   uint64 `json:"evicted"`
	Max       int    `json:"max"`
}

// FlowStatsProvider exposes the running pipeline's flow-table counters. The
// daemon's replay controller implements it; it may be nil in embedded/test use,
// in which case /api/v1/status reports zeroes and the configured cap.
type FlowStatsProvider interface {
	FlowStats() FlowStats
}

// CaptureStatusProvider is the live capture manager as the API uses it: the
// per-source status for GET /api/v1/captures[/{name}] (PROJECT.md §19.14) plus
// runtime add/remove for POST/DELETE /api/v1/captures (issue #32).
// capture.Manager implements it. A nil provider means "no capture manager
// wired": the GETs return an empty list / 404 and the mutating routes return
// 503. The interface keeps the api package off a concrete *capture.Manager.
type CaptureStatusProvider interface {
	List() []capture.SourceStatus
	Get(name string) (capture.SourceStatus, bool)
	// Add registers and (if the manager is already running) starts a source.
	// It returns an error on a duplicate name or an empty name.
	Add(name string, src capture.Source, meta capture.SourceMeta) error
	// Remove stops, closes and deregisters a source; false if unknown.
	Remove(name string) bool
	// ShutdownDrops is the daemon-lifetime count of packets discarded on the
	// capture shutdown / terminal-error path (issue #138, PROJECT.md §22).
	ShutdownDrops() uint64
}

// Server bundles the HTTP handler, the live hub and the event pump.
type Server struct {
	cfg     config.Config
	bus     *events.Bus
	store   storage.Store
	rt      *inference.Runtime
	reg     *registry.Registry
	audit   *audit.Logger
	ds      *dataset.Manager
	rc      ReplayController
	fs      FlowStatsProvider
	cap     CaptureStatusProvider
	sensors SensorStatusProvider
	insight *insight.Index
	tr      *training.Store
	rv      *review.Store
	alerts  *alert.Store
	hub     *wshub.Hub
	start   time.Time

	// metrics is the daemon's obs.Metrics (issue #55), set by the daemon after
	// New via SetMetrics. nil in embedded/test use — GET /metrics then renders
	// every counter it can still reach and empty latency histograms.
	metrics *obs.Metrics

	// Resolved bundle normalizers for the Flow Inspector's normalized-inputs
	// view, keyed by "<model id>@<content hash>". model.Load reads and hashes
	// model.onnx, so it must not run per request; a registered bundle is
	// immutable, which makes the content hash a sound key. See flows.go.
	normMu    sync.Mutex
	normCache map[string]cachedNormalizer
}

// New builds a Server. reg may be nil (the /api/v1/models* routes then report an
// empty registry / 503 on the state-changing ones); aud may be nil (audit
// logging becomes a no-op); ds may be nil (/api/v1/datasets then returns an
// empty list and the other dataset routes 503); rc may be nil (replay endpoints
// then return 503); fs may be nil (/api/v1/status then reports a zeroed flow
// table with the configured cap); cp may be nil (/api/v1/captures then returns
// an empty list); ix may be nil (/api/v1/hosts then returns an empty list and
// /api/v1/timeline an empty series — *insight.Index is nil-safe on every read);
// tr may be nil (GET /api/v1/training then returns an empty list and the
// trainer-facing POST routes return 503); sp may be nil (/api/v1/sensors then
// returns an empty list and /{id} a 404); rv may be nil (every /api/v1/review*
// route then returns 503); al may be nil (/api/v1/detections then returns an
// empty page and /{id} a 404 — *alert.Store is nil-safe on every read).
//
// ix, tr, rv and al are concrete pointers rather than interfaces on purpose: a
// concrete nil pointer with nil-safe methods cannot reproduce the typed-nil
// crash of issue #116, where a nil *capture.Collector stored in an interface
// passed every `!= nil` guard and then panicked on first use.
func New(cfg config.Config, bus *events.Bus, store storage.Store, rt *inference.Runtime, reg *registry.Registry, aud *audit.Logger, ds *dataset.Manager, rc ReplayController, fs FlowStatsProvider, cp CaptureStatusProvider, ix *insight.Index, tr *training.Store, sp SensorStatusProvider, rv *review.Store, al *alert.Store) *Server {
	return &Server{
		cfg: cfg, bus: bus, store: store, rt: rt, reg: reg, audit: aud, ds: ds, rc: rc, fs: fs, cap: cp,
		sensors: sp,
		insight: ix,
		tr:      tr,
		rv:      rv,
		alerts:  al,
		hub:     wshub.NewHub(cfg.Live.ClientQueueSize),
		start:   time.Now(),
	}
}

// SetMetrics wires the process metric set for GET /metrics (issue #55). The
// daemon calls it once, after New; a Server without it still serves /metrics
// from the counters it already holds, with empty latency histograms.
func (s *Server) SetMetrics(m *obs.Metrics) { s.metrics = m }

// Handler returns the routed http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/flows", s.handleFlows)
	mux.HandleFunc("GET /api/v1/flows/{id}", s.handleFlow)
	mux.HandleFunc("GET /api/v1/flows/{id}/explain", s.handleFlowExplain)
	mux.HandleFunc("GET /api/v1/flows/{id}/snapshots", s.handleFlowSnapshots)
	mux.HandleFunc("GET /api/v1/classifications", s.handleClassifications)
	mux.HandleFunc("GET /api/v1/detections", s.handleDetections)
	mux.HandleFunc("GET /api/v1/detections/{id}", s.handleDetection)
	mux.HandleFunc("GET /api/v1/hosts", s.handleHosts)
	mux.HandleFunc("GET /api/v1/hosts/{ip}", s.handleHost)
	mux.HandleFunc("GET /api/v1/hosts/{ip}/flows", s.handleHostFlows)
	mux.HandleFunc("GET /api/v1/hosts/{ip}/classifications", s.handleHostClassifications)
	mux.HandleFunc("GET /api/v1/timeline", s.handleTimeline)
	mux.HandleFunc("GET /api/v1/reports/host/{ip}", s.handleHostReport)
	mux.HandleFunc("GET /api/v1/reports/range", s.handleRangeReport)
	mux.HandleFunc("GET /api/v1/models", s.handleModels)
	mux.HandleFunc("GET /api/v1/models/{id}", s.handleModel)
	mux.HandleFunc("GET /api/v1/models/{id}/lineage", s.handleModelLineage)
	mux.HandleFunc("POST /api/v1/models/{id}/activate", s.handleModelActivate)
	mux.HandleFunc("POST /api/v1/models/{id}/deactivate", s.handleModelDeactivate)
	mux.HandleFunc("GET /api/v1/datasets", s.handleDatasets)
	mux.HandleFunc("POST /api/v1/datasets", s.handleDatasetCreate)
	mux.HandleFunc("GET /api/v1/datasets/{ref}", s.handleDataset)
	mux.HandleFunc("DELETE /api/v1/datasets/{ref}", s.handleDatasetDelete)
	mux.HandleFunc("GET /api/v1/datasets/{ref}/download", s.handleDatasetDownload)
	mux.HandleFunc("GET /api/v1/datasets/{ref}/stats", s.handleDatasetStats)
	mux.HandleFunc("GET /api/v1/review/queue", s.handleReviewQueue)
	mux.HandleFunc("GET /api/v1/review/stats", s.handleReviewStats)
	mux.HandleFunc("GET /api/v1/review", s.handleReviews)
	mux.HandleFunc("GET /api/v1/review/{flow_id}", s.handleReview)
	mux.HandleFunc("PUT /api/v1/review/{flow_id}", s.handleReviewWrite)
	mux.HandleFunc("POST /api/v1/review/{flow_id}", s.handleReviewWrite)
	mux.HandleFunc("GET /api/v1/training", s.handleTrainings)
	mux.HandleFunc("POST /api/v1/training", s.handleTrainingCreate)
	mux.HandleFunc("GET /api/v1/training/{id}", s.handleTraining)
	mux.HandleFunc("POST /api/v1/training/{id}/progress", s.handleTrainingProgress)
	mux.HandleFunc("POST /api/v1/training/{id}/fail", s.handleTrainingFail)
	// Read-only by design: the audit log is append-only forever, so there is
	// no DELETE or PATCH counterpart to this route (PROJECT.md §21).
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	mux.HandleFunc("GET /api/v1/schemas/features", s.rawJSON(schema.FlowFeaturesV1JSON()))
	mux.HandleFunc("GET /api/v1/schemas/classes", s.rawJSON(schema.TrafficClassesV1JSON()))
	mux.HandleFunc("GET /api/v1/captures", s.handleCaptures)
	mux.HandleFunc("POST /api/v1/captures", s.handleCaptureCreate)
	mux.HandleFunc("GET /api/v1/captures/{name}", s.handleCapture)
	mux.HandleFunc("DELETE /api/v1/captures/{name}", s.handleCaptureDelete)
	mux.HandleFunc("GET /api/v1/sensors", s.handleSensors)
	// The literal path is registered before the wildcard for readability only —
	// Go's ServeMux picks the more specific pattern regardless of order.
	mux.HandleFunc("GET /api/v1/sensors/topology", s.handleSensorTopology)
	mux.HandleFunc("GET /api/v1/sensors/{id}", s.handleSensor)
	mux.HandleFunc("GET /api/v1/matrix", s.handleMatrix)
	mux.HandleFunc("POST /api/v1/architecture/estimate", s.handleArchitectureEstimate)
	mux.HandleFunc("GET /api/v1/replay", s.handleReplayStatus)
	mux.HandleFunc("POST /api/v1/replay", s.handleReplayStart)
	mux.HandleFunc("POST /api/v1/replay/stop", s.handleReplayStop)
	mux.HandleFunc("GET /api/v1/stream", s.handleStream)

	if root := s.cfg.Server.WebRoot; root != "" {
		mux.Handle("/", http.FileServer(http.Dir(root)))
	} else {
		mux.Handle("/", http.FileServerFS(web.FS()))
	}
	return logMiddleware(mux)
}

// Run starts the event pump and serves HTTP until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	go s.pump(ctx)

	srv := &http.Server{
		Addr:              s.cfg.Server.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// pump subscribes to the bus and pushes batched envelopes to WebSocket clients
// on the configured interval (PROJECT.md §18, §22).
func (s *Server) pump(ctx context.Context) {
	sub := s.bus.Subscribe(s.cfg.Live.ClientQueueSize)
	defer sub.Close()

	interval := s.cfg.Live.WebSocketBatch.D()
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	batch := make([]events.Event, 0, 256)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if b, err := json.Marshal(batch); err == nil {
			s.hub.Broadcast(b)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-sub.C:
			batch = append(batch, ev)
			if len(batch) >= 256 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	conn, err := wshub.Upgrade(w, r)
	if err != nil {
		http.Error(w, "expected a websocket upgrade", http.StatusBadRequest)
		return
	}
	s.hub.Add(conn) // blocks until the client disconnects
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	pub, drop, subs := s.bus.Stats()
	ws := s.hub.Stats()
	var rs ReplayStatus
	if s.rc != nil {
		rs = s.rc.Status()
	}
	fs := FlowStats{Max: s.cfg.Capture.MaxFlows}
	if s.fs != nil {
		fs = s.fs.FlowStats()
	}
	capStats := map[string]any{}
	if s.cap != nil {
		capStats["shutdown_drops"] = s.cap.ShutdownDrops()
	}
	ms := s.metrics.Snapshot()
	inf := map[string]any{
		"scored":         ms.InferenceLatency.Total,
		"failures":       ms.InferenceFailures,
		"latency_p50_ms": s.metrics.InferenceQuantile(0.50) * 1000,
		"latency_p95_ms": s.metrics.InferenceQuantile(0.95) * 1000,
		"latency_p99_ms": s.metrics.InferenceQuantile(0.99) * 1000,
		"by_class":       ms.Classified,
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    version.Short("synapsed"),
		"commit":     version.Commit,
		"uptime_sec": int64(time.Since(s.start).Seconds()),
		"listen":     s.cfg.Server.Listen,
		"loopback":   s.cfg.LoopbackOnly(),
		"storage":    s.store.Stats(),
		"events":     map[string]any{"published": pub, "dropped": drop, "subscribers": subs},
		"capture":    capStats,
		"live": map[string]any{
			// Canonical WebSocket-hub counters (issue #70).
			"ws_clients":        ws.Clients,
			"ws_client_drops":   ws.Drops,
			"ws_frames_batched": ws.FramesBatched,
			// Pre-existing keys, kept for back-compat (additive).
			"clients":      ws.Clients,
			"accepted":     ws.Accepted,
			"frames_out":   ws.FramesOut,
			"client_drops": ws.Drops,
		},
		"flow":           fs,
		"inference":      inf,
		"insight":        s.insight.Stats(),
		"alerts":         s.alerts.Stats(),
		"models":         s.modelList(),
		"replay":         rs,
		"feature_schema": schema.FlowFeaturesV1().Schema,
		"output_schema":  schema.TrafficClassesV1().Schema,
	})
}

// handleFlows serves GET /api/v1/flows. It accepts the sensor scope (sensor=,
// location=) so the topology view can pivot the flow list onto one sensor
// (PROJECT.md §19.15); without those params its behaviour is unchanged.
//
// A flow record carries its own observation point since issue #126, so the scope
// is answered from the row itself. A row stored before that — or written by an
// embedder that does not set it — falls back to the old join against the recent
// classification window, and drops out of a scoped list once its verdict ages
// out of that window.
func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	limit := limitParam(r, 2000)
	scope, ok := s.parseSensorScope(w, r.URL.Query())
	if !ok {
		return
	}
	if scope == nil {
		writeJSON(w, http.StatusOK, s.store.RecentFlows(limit))
		return
	}

	var verdict map[uint64]storage.Classification
	out := make([]storage.FlowRecord, 0, min(limit, 128))
	for _, fr := range s.store.RecentFlows(classFilterScan) {
		sensor := fr.Sensor
		if sensor == "" {
			// Build the fallback index lazily: a store whose rows all carry a
			// sensor never pays for it.
			if verdict == nil {
				verdict = make(map[uint64]storage.Classification, classFilterScan)
				for _, c := range s.store.RecentClassifications(classFilterScan) {
					if _, seen := verdict[c.FlowID]; !seen {
						verdict[c.FlowID] = c
					}
				}
			}
			c, found := verdict[fr.ID]
			if !found {
				continue
			}
			sensor = c.Sensor
		}
		if !scope[sensor] {
			continue
		}
		out = append(out, fr)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// parseSensorScope reads sensor= and location=, and nothing else, so a route that
// supports only the scope does not accidentally validate predicates it then
// ignores. A nil map with ok=true means "unscoped"; an empty non-nil map means
// "scoped to nothing", which is a legitimate outcome of intersecting a disjoint
// sensor= and location=.
//
// See parseClassFilters for what these two parameters honestly select.
func (s *Server) parseSensorScope(w http.ResponseWriter, q url.Values) (map[string]bool, bool) {
	var out map[string]bool

	// sensor= is matched verbatim and deliberately not validated against the
	// connected set: a sensor that has disconnected still owns its stored rows,
	// and "local" is a legitimate value that never appears in the collector.
	if v := strings.TrimSpace(q.Get("sensor")); v != "" {
		out = map[string]bool{v: true}
	}

	// location= resolves through the *currently connected* sensors, because a
	// location lives on the live session and is not stored on a row. A location
	// nothing reports is a 400: an empty 200 would be indistinguishable from "that
	// location produced no traffic".
	if v := strings.TrimSpace(q.Get("location")); v != "" {
		ids := s.sensorIDsAtLocation(v)
		if len(ids) == 0 {
			http.Error(w, "unknown location: no connected sensor reports it", http.StatusBadRequest)
			return nil, false
		}
		if out == nil {
			out = ids
		} else {
			// Both given: intersect, so sensor= narrows within location=.
			for id := range out {
				if !ids[id] {
					delete(out, id)
				}
			}
		}
	}
	return out, true
}

func (s *Server) handleFlow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad flow id", http.StatusBadRequest)
		return
	}
	fr, ok := s.store.Flow(id)
	if !ok {
		http.Error(w, "flow not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, fr)
}

// classFilterScan is how many recent verdicts a filtered query walks before it
// caps at the requested limit. The memory store has no indexes, so a filter is a
// linear scan of the newest window; a predicate-pushdown backend (SQLite) will
// replace this.
const classFilterScan = 5000

func (s *Server) handleClassifications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := limitParam(r, 5000)

	f, ok := s.parseClassFilters(w, q)
	if !ok {
		return // parseClassFilters already wrote a 400
	}
	if f.empty() {
		writeJSON(w, http.StatusOK, s.store.RecentClassifications(limit))
		return
	}

	rows := s.store.RecentClassifications(classFilterScan)
	out := make([]storage.Classification, 0, limit)
	for _, c := range rows {
		if f.match(c) {
			out = append(out, c)
			if len(out) >= limit {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// classFilters holds the optional GET /api/v1/classifications query predicates.
// Every field is additive: a request with none of them keeps the legacy
// behaviour (newest `limit`, max 5000).
type classFilters struct {
	disagreement bool    // disagreement=true  → only Result.Disagreement rows
	class        string  // class=<name>       → Result.Class == name (validated)
	model        string  // model=<id>         → any Result.Models[].ModelID == id
	minConf      float64 // min_confidence=... → Result.Score >= threshold (0..1)
	hasMinConf   bool

	// sensors is the sensor scope from sensor= / location= (PROJECT.md §19.15,
	// issue #46): the set of Classification.Sensor values a row may carry. A nil
	// map means "any sensor" — it is not the same as an empty map, which matches
	// nothing.
	//
	// Since issue #126 every stored row carries the id of the sensor that saw the
	// traffic, in all three sensor modes; "local" now means what it says — the
	// daemon's own capture — rather than "provenance was lost".
	sensors map[string]bool
}

func (f classFilters) empty() bool {
	return !f.disagreement && f.class == "" && f.model == "" && !f.hasMinConf && f.sensors == nil
}

func (f classFilters) match(c storage.Classification) bool {
	if f.disagreement && !c.Result.Disagreement {
		return false
	}
	if f.class != "" && c.Result.Class != f.class {
		return false
	}
	if f.hasMinConf && c.Result.Score < f.minConf {
		return false
	}
	if f.sensors != nil && !f.sensors[c.Sensor] {
		return false
	}
	if f.model != "" {
		found := false
		for _, m := range c.Result.Models {
			if m.ModelID == f.model {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// parseClassFilters reads the query params, validating as it goes. On a bad
// value it writes a 400 and returns ok=false.
//
// # The sensor scope, and what it honestly does
//
// sensor= and location= exist so clicking a sensor or a location in the topology
// view can scope the other views (PROJECT.md §19.15). Both resolve to a set of
// allowed Sensor values, which is the sensor provenance every stored row carries.
//
// All three sensor modes are scopeable since issue #126. `flow` and `feature`
// records arrive pre-aggregated and tagged; a `raw` sensor's packets are stamped
// with its id by capture.Manager and keyed by it in the flow table, so the flow
// the daemon builds knows which observation point it came from (ADR 0030). The
// literal "local" remains a legitimate scope and now means only what it says:
// traffic the daemon captured itself, or replayed.
//
// Two limits remain, stated rather than hidden. A sensor that reported no id at
// all is indistinguishable from local capture and lands in "local". And
// location= resolves through the *currently connected* sensors, because a
// location lives on the live session and is not stored on a row — so an
// unresolvable location= is a 400 rather than a silently empty 200.
func (s *Server) parseClassFilters(w http.ResponseWriter, q url.Values) (classFilters, bool) {
	var f classFilters

	f.disagreement = q.Get("disagreement") == "true"

	if v := q.Get("class"); v != "" {
		if !validClassName(v) {
			http.Error(w, "unknown class name", http.StatusBadRequest)
			return f, false
		}
		f.class = v
	}

	f.model = q.Get("model")

	if v := q.Get("min_confidence"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n < 0 {
			http.Error(w, "bad min_confidence", http.StatusBadRequest)
			return f, false
		}
		if n > 1 { // accept a 0..100 percentage, like the web UI's slider
			n /= 100
		}
		f.minConf, f.hasMinConf = n, true
	}

	// The sensor scope shares one implementation with the routes that accept it
	// alone, so `sensor=`/`location=` cannot come to mean two different things.
	scope, ok := s.parseSensorScope(w, q)
	if !ok {
		return f, false
	}
	f.sensors = scope

	return f, true
}

// sensorIDsAtLocation returns the ids of connected sensors whose reported
// location is exactly loc, after trimming. The match is exact — not
// case-insensitive — because GET /api/v1/sensors/topology groups by the same
// verbatim string and hands the client the value to send back, so there is
// nothing to guess. The empty-location bucket is addressed by the
// UnassignedLocation sentinel (see topology.go).
func (s *Server) sensorIDsAtLocation(loc string) map[string]bool {
	if s.sensors == nil {
		return nil
	}
	out := map[string]bool{}
	for _, st := range s.sensors.Sensors() {
		have := strings.TrimSpace(st.Location)
		if have == "" {
			have = UnassignedLocation
		}
		if have == loc {
			out[st.SensorID] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validClassName reports whether name is a traffic-classes-v1 class.
func validClassName(name string) bool {
	for _, c := range schema.TrafficClassesV1().Classes {
		if c.Name == name {
			return true
		}
	}
	return false
}

// modelList is the lightweight live-classifier list surfaced on /api/v1/status:
// just what is actually scoring flows right now (the heuristic, or an activated
// ONNX model). The full registry view is GET /api/v1/models (see models.go).
func (s *Server) modelList() []map[string]string {
	out := make([]map[string]string, 0, len(s.rt.Models()))
	for _, m := range s.rt.Models() {
		out = append(out, map[string]string{
			"id": m.ID(), "family": m.Family(), "role": string(m.Role()),
		})
	}
	return out
}

func (s *Server) handleReplayStatus(w http.ResponseWriter, _ *http.Request) {
	if s.rc == nil {
		http.Error(w, "replay not available", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, s.rc.Status())
}

func (s *Server) handleReplayStart(w http.ResponseWriter, r *http.Request) {
	if s.rc == nil {
		http.Error(w, "replay not available", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Path  string `json:"path"`
		Speed string `json:"speed"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	if fi, err := os.Stat(req.Path); err != nil || fi.IsDir() {
		http.Error(w, "path does not name a readable file", http.StatusBadRequest)
		return
	}
	sp, err := capture.ParseSpeed(req.Speed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := s.rc.Start(req.Path, sp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "speed": sp.String()})
}

func (s *Server) handleReplayStop(w http.ResponseWriter, _ *http.Request) {
	if s.rc == nil {
		http.Error(w, "replay not available", http.StatusServiceUnavailable)
		return
	}
	if err := s.rc.Stop(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"stopped": "ok"})
}

func (s *Server) rawJSON(doc []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// defaultLimit is the page size every collection route uses when the caller
// does not send limit=. Each route supplies its own upper bound.
const defaultLimit = 100

// limitParam reads limit=, clamping it to [1, max]. An absent, unparseable or
// non-positive value falls back to defaultLimit.
func limitParam(r *http.Request, max int) int {
	q := r.URL.Query().Get("limit")
	if q == "" {
		return defaultLimit
	}
	n, err := strconv.Atoi(q)
	if err != nil || n < 1 {
		return defaultLimit
	}
	if n > max {
		return max
	}
	return n
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}

// Hijack lets the WebSocket upgrade reach the underlying connection.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("api: underlying writer is not a Hijacker")
	}
	return h.Hijack()
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		// Structured access log (issue #55): one record per request with the
		// fields a log query needs. 4xx/5xx are warnings; the rest stay at info,
		// which is the level the plain-text line used before this change.
		lvl := slog.LevelInfo
		if rec.code >= 400 {
			lvl = slog.LevelWarn
		}
		slog.LogAttrs(r.Context(), lvl, "http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.code),
			slog.Int64("dur_ms", time.Since(start).Milliseconds()),
		)
	})
}
