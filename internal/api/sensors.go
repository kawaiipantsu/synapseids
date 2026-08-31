package api

import (
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/capture"
)

// SensorStatusProvider is the daemon-side SYNPOIP collector as the API reads it:
// the connected reverse-connecting sensors and their live counters (PROJECT.md
// §5.3, §19.15; issue #43, feeds #46). capture.Collector implements it. A nil
// provider means "no collector wired": GET /api/v1/sensors returns an empty
// array and GET /api/v1/sensors/{id} is a 404.
//
// This is a read-only projection. It inherits the same loopback-only posture as
// the rest of the state surface (PROJECT.md §21); there is nothing here to
// mutate — a sensor is added and removed by connecting and disconnecting.
type SensorStatusProvider interface {
	Sensors() []capture.SensorStatus
	Sensor(id string) (capture.SensorStatus, bool)
}

// handleSensors serves GET /api/v1/sensors — every connected sensor, newest
// first. With no collector configured it returns an empty JSON array, never a
// 503, so the topology/sources UI can always render.
func (s *Server) handleSensors(w http.ResponseWriter, _ *http.Request) {
	list := []capture.SensorStatus{}
	if s.sensors != nil {
		if got := s.sensors.Sensors(); got != nil {
			list = got
		}
	}
	writeJSON(w, http.StatusOK, list)
}

// handleSensor serves GET /api/v1/sensors/{id} — one sensor by its id, or 404.
func (s *Server) handleSensor(w http.ResponseWriter, r *http.Request) {
	if s.sensors == nil {
		http.Error(w, "sensor not found", http.StatusNotFound)
		return
	}
	st, ok := s.sensors.Sensor(r.PathValue("id"))
	if !ok {
		http.Error(w, "sensor not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
