package api

import (
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/dataset"
)

// GET /api/v1/datasets/{ref}/stats — the Dataset Explorer bundle (PROJECT.md
// §19.11; issues #37, #67): per-feature distributions and histograms, the label
// distribution, the 48×48 Pearson correlation matrix, protocol/port splits, a
// bounded outlier list and the top-3 PCA projection.
//
// Read-only, unauthenticated (same posture as the other GET /api/v1/datasets
// routes). The response is large but bounded: the correlation matrix is a fixed
// 48×48, and pca.projection is capped at dataset.StatsProjectionCap rows
// (projection_sampled is set when the dataset is larger). The dataset manager
// computes the bundle once per content hash and serves a cached copy after, so
// repeated calls are cheap and byte-identical.
//
//	400 the ref is not "<id>@<version>"
//	404 unknown dataset version
//	500 the dataset's CSV on disk is unreadable or malformed
//	503 no dataset manager wired
func (s *Server) handleDatasetStats(w http.ResponseWriter, r *http.Request) {
	if s.ds == nil {
		http.Error(w, "dataset manager not available", http.StatusServiceUnavailable)
		return
	}
	id, version, err := dataset.ParseRef(r.PathValue("ref"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, ok := s.ds.Get(id, version); !ok {
		http.Error(w, "unknown dataset "+id+"@"+version, http.StatusNotFound)
		return
	}
	st, err := s.ds.Stats(id, version)
	if err != nil {
		// The version exists (checked above), so a failure here is a disk or
		// parse problem with its materialised CSV, not a client error.
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
