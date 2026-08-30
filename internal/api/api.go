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
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
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

// Server bundles the HTTP handler, the live hub and the event pump.
type Server struct {
	cfg   config.Config
	bus   *events.Bus
	store storage.Store
	rt    *inference.Runtime
	rc    ReplayController
	hub   *wshub.Hub
	start time.Time
}

// New builds a Server. rc may be nil (replay endpoints then return 503).
func New(cfg config.Config, bus *events.Bus, store storage.Store, rt *inference.Runtime, rc ReplayController) *Server {
	return &Server{
		cfg: cfg, bus: bus, store: store, rt: rt, rc: rc,
		hub:   wshub.NewHub(cfg.Live.ClientQueueSize),
		start: time.Now(),
	}
}

// Handler returns the routed http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/flows", s.handleFlows)
	mux.HandleFunc("GET /api/v1/flows/{id}", s.handleFlow)
	mux.HandleFunc("GET /api/v1/classifications", s.handleClassifications)
	mux.HandleFunc("GET /api/v1/models", s.handleModels)
	mux.HandleFunc("GET /api/v1/schemas/features", s.rawJSON(schema.FlowFeaturesV1JSON()))
	mux.HandleFunc("GET /api/v1/schemas/classes", s.rawJSON(schema.TrafficClassesV1JSON()))
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
	clients, accepted, framesOut, wsDrops := s.hub.Stats()
	var rs ReplayStatus
	if s.rc != nil {
		rs = s.rc.Status()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        version.Short("synapsed"),
		"commit":         version.Commit,
		"uptime_sec":     int64(time.Since(s.start).Seconds()),
		"listen":         s.cfg.Server.Listen,
		"loopback":       s.cfg.LoopbackOnly(),
		"storage":        s.store.Stats(),
		"events":         map[string]any{"published": pub, "dropped": drop, "subscribers": subs},
		"live":           map[string]any{"clients": clients, "accepted": accepted, "frames_out": framesOut, "client_drops": wsDrops},
		"models":         s.modelList(),
		"replay":         rs,
		"feature_schema": schema.FlowFeaturesV1().Schema,
		"output_schema":  schema.TrafficClassesV1().Schema,
	})
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.RecentFlows(limitParam(r, 100, 2000)))
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

func (s *Server) handleClassifications(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.RecentClassifications(limitParam(r, 100, 5000)))
}

func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.modelList())
}

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

func limitParam(r *http.Request, def, max int) int {
	q := r.URL.Query().Get("limit")
	if q == "" {
		return def
	}
	n, err := strconv.Atoi(q)
	if err != nil || n < 1 {
		return def
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
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.code, time.Since(start).Round(time.Millisecond))
	})
}
