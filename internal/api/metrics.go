package api

import (
	"net/http"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/obs"
	"github.com/kawaiipantsu/synapseids/internal/version"
)

// handleMetrics serves GET /metrics in the Prometheus text exposition format
// (issue #55, PROJECT.md §24). It is the same data /api/v1/status carries plus
// the obs.Metrics latency histograms and per-class verdict tally, rendered for a
// scraper. It is off the packet path: every value is a counter read or a
// histogram snapshot.
//
// The endpoint sits at /metrics (not /api/v1/*) by Prometheus convention. It
// carries no auth of its own; like the mutating routes it relies on the
// loopback bind and the reverse proxy in front (issue #58, PROJECT.md §21).
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	p := obs.NewWriter(w)

	p.Gauge("synapseids_build_info",
		"Build metadata; the value is always 1.", 1,
		obs.Label{Name: "version", Value: version.Short("synapsed")},
		obs.Label{Name: "commit", Value: version.Commit},
	)
	p.GaugeInt("synapseids_uptime_seconds",
		"Seconds since the daemon started.", int64(time.Since(s.start).Seconds()))
	p.GaugeInt("synapseids_listener_loopback",
		"1 when server.listen is a loopback address, 0 otherwise.", boolToInt(s.cfg.LoopbackOnly()))

	// ---- capture: packets, bytes, decode errors, kernel drops -------------
	if s.cap != nil {
		var totPkts, totDecoded, totDecErr, totBytes, totDrops uint64
		for _, src := range s.cap.List() {
			ls := []obs.Label{{Name: "source", Value: src.Name}}
			p.Counter("synapseids_capture_packets_total", "Frames delivered by a capture source.", src.Packets, ls...)
			p.Counter("synapseids_capture_decoded_total", "Frames that decoded to a packet.", src.Decoded, ls...)
			p.Counter("synapseids_capture_decode_errors_total", "Frames that failed to decode (counted, skipped).", src.DecodeErrors, ls...)
			p.Counter("synapseids_capture_bytes_total", "Bytes delivered by a capture source.", src.Bytes, ls...)
			p.Counter("synapseids_capture_kernel_drops_total", "Frames the kernel dropped before the source read them.", src.Drops, ls...)
			totPkts += src.Packets
			totDecoded += src.Decoded
			totDecErr += src.DecodeErrors
			totBytes += src.Bytes
			totDrops += src.Drops
		}
		// Aggregates, so a scrape without per-source math still has the totals.
		p.Counter("synapseids_capture_packets_total", "Frames delivered by a capture source.", totPkts, obs.Label{Name: "source", Value: "_all"})
		p.Counter("synapseids_capture_decoded_total", "Frames that decoded to a packet.", totDecoded, obs.Label{Name: "source", Value: "_all"})
		p.Counter("synapseids_capture_decode_errors_total", "Frames that failed to decode (counted, skipped).", totDecErr, obs.Label{Name: "source", Value: "_all"})
		p.Counter("synapseids_capture_bytes_total", "Bytes delivered by a capture source.", totBytes, obs.Label{Name: "source", Value: "_all"})
		p.Counter("synapseids_capture_kernel_drops_total", "Frames the kernel dropped before the source read them.", totDrops, obs.Label{Name: "source", Value: "_all"})
		p.Counter("synapseids_capture_shutdown_drops_total",
			"Packets discarded by the fan-in at shutdown or on a terminal source error (issue #138).", s.cap.ShutdownDrops())
	}

	// ---- sensor connectivity --------------------------------------------------
	if s.sensors != nil {
		sensors := s.sensors.Sensors()
		var running int
		for _, se := range sensors {
			if se.State == "running" {
				running++
			}
		}
		p.GaugeInt("synapseids_sensors_connected", "Remote SYNPOIP sensors currently connected.", int64(len(sensors)))
		p.GaugeInt("synapseids_sensors_running", "Connected sensors in the running state.", int64(running))
	}

	// ---- flow table ---------------------------------------------------------
	fs := FlowStats{Max: s.cfg.Capture.MaxFlows}
	if s.fs != nil {
		fs = s.fs.FlowStats()
	}
	p.GaugeInt("synapseids_flows_active", "Flows held in the live flow table right now.", int64(fs.Active))
	p.GaugeInt("synapseids_flows_max", "Configured flow-table cap (capture.max_flows).", int64(fs.Max))
	p.Counter("synapseids_flows_started_total", "Flows opened over the daemon's lifetime.", fs.Started)
	p.Counter("synapseids_flows_closed_total", "Flows closed (FIN/RST/idle/max-life/capture-end).", fs.Closed)
	p.Counter("synapseids_flow_snapshots_total", "Periodic snapshot records emitted for long-lived flows.", fs.Snapshots)
	p.Counter("synapseids_flows_evicted_total", "Flows evicted from a full table, oldest-idle first.", fs.Evicted)

	// ---- storage ----------------------------------------------------------
	stg := s.store.Stats()
	p.GaugeInt("synapseids_storage_flows", "Flow records retained by the store.", int64(stg.Flows))
	p.GaugeInt("synapseids_storage_classifications", "Classifications retained by the store.", int64(stg.Classifications))
	p.Counter("synapseids_storage_flows_evicted_total", "Flow records dropped by the store's ring bound.", stg.FlowsEvicted)
	p.Counter("synapseids_storage_classifications_evicted_total", "Classifications dropped by the store's ring bound.", stg.ClassEvicted)
	p.Counter("synapseids_storage_flow_versions_dropped_total", "Per-flow snapshot versions dropped over the history cap.", stg.FlowVersionsDropped)
	p.Counter("synapseids_model_disagreements_total", "Verdicts where the alert-driving models disagreed (PROJECT.md §12).", stg.Disagreements)

	// ---- inference (obs.Metrics) ----------------------------------------------
	ms := s.metrics.Snapshot()
	p.Histogram("synapseids_inference_latency_seconds", "Wall-clock cost of one runtime scoring call.", ms.InferenceLatency)
	p.Histogram("synapseids_feature_extract_latency_seconds", "Wall-clock cost of one features.Extract call.", ms.FeatureLatency)
	p.Counter("synapseids_inference_failures_total", "Scoring calls that could not produce a verdict.", ms.InferenceFailures)
	for class, n := range ms.Classified {
		p.Counter("synapseids_classifications_total", "Verdicts produced, by traffic-classes-v1 class.", n, obs.Label{Name: "class", Value: class})
	}

	// ---- event bus + live channel ---------------------------------------------
	pub, edrop, subs := s.bus.Stats()
	p.Counter("synapseids_events_published_total", "Events published on the internal bus.", pub)
	p.Counter("synapseids_events_dropped_total", "Events a slow subscriber missed (bus never blocks ingestion).", edrop)
	p.GaugeInt("synapseids_event_subscribers", "Bus subscribers right now.", int64(subs))

	ws := s.hub.Stats()
	p.GaugeInt("synapseids_ws_clients", "WebSocket clients connected right now.", int64(ws.Clients))
	p.Counter("synapseids_ws_accepted_total", "WebSocket connections ever accepted.", ws.Accepted)
	p.Counter("synapseids_ws_frames_batched_total", "Batched payloads handed to the fan-out (one per pump flush).", ws.FramesBatched)
	p.Counter("synapseids_ws_client_drops_total", "Clients dropped for a full send queue (§22).", ws.Drops)

	// ---- detections / alert policy ------------------------------------------
	al := s.alerts.Stats()
	p.GaugeInt("synapseids_alerts_enabled", "1 when the alert policy is enabled.", boolToInt(al.Enabled))
	p.Counter("synapseids_detections_created_total", "New detections opened (== AlertCreated events).", al.Created)
	p.Counter("synapseids_detections_deduped_total", "Verdicts folded into an existing detection.", al.Deduped)
	p.Counter("synapseids_detections_suppressed_threshold_total", "Alertable verdicts below their confidence threshold.", al.Suppressed)
	p.Counter("synapseids_detections_suppressed_rule_total", "Verdicts suppressed by an alerts.suppress rule (issue #133).", al.SuppressedByRule)
	p.Counter("synapseids_detections_evicted_total", "Detections dropped by the max_recent bound.", al.Evicted)
	p.Counter("synapseids_detections_dropped_total", "Verdicts the alert ingest queue could not accept.", al.Dropped)
	p.GaugeInt("synapseids_detections_retained", "Detections held right now.", int64(al.Retained))

	// ---- investigation aggregates -----------------------------------------
	ins := s.insight.Stats()
	p.GaugeInt("synapseids_insight_hosts", "Hosts tracked by the investigation index.", int64(ins.Hosts))
	p.Counter("synapseids_insight_hosts_evicted_total", "Hosts evicted from the investigation index bound.", ins.HostsEvicted)
	p.Counter("synapseids_insight_dropped_total", "Flow records the investigation ingest queue could not accept.", ins.Dropped)

	if err := p.Err(); err != nil {
		// The header and some body are already on the wire; nothing useful to do
		// but stop. A scraper sees a truncated payload and retries.
		return
	}
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
