package api

// GET /api/v1/flows/{id}/snapshots — the retained version history of one flow
// (PROJECT.md §19.3 "historical snapshots of the flow", issue #38).
//
// A long-lived flow emits a ReasonSnapshot record every snapshot_interval with
// cumulative counters, then a terminal record. The investigative value is seeing
// how the counters *and the verdict* moved between them, so each version is
// paired with the classification computed from it.

import (
	"net/http"
	"strconv"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// versionVerdict is the verdict computed from one flow version.
type versionVerdict struct {
	Class        string  `json:"class"`
	ClassID      int     `json:"class_id"`
	Score        float64 `json:"score"`
	Disagreement bool    `json:"disagreement"`
}

// flowVersionView is one retained version of a flow.
type flowVersionView struct {
	SnapshotIndex int       `json:"snapshot_index"`
	CloseReason   string    `json:"close_reason"`
	Terminal      bool      `json:"terminal"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	DurationSec   float64   `json:"duration_sec"`
	FwdPackets    uint64    `json:"fwd_packets"`
	BwdPackets    uint64    `json:"bwd_packets"`
	FwdBytes      uint64    `json:"fwd_bytes"`
	BwdBytes      uint64    `json:"bwd_bytes"`

	// Verdict is nil when the classification for this version has aged out of
	// the bounded ring. Nil means "not retained", never "not classified".
	Verdict *versionVerdict `json:"verdict,omitempty"`
}

// flowSnapshots is the GET /api/v1/flows/{id}/snapshots payload.
type flowSnapshots struct {
	FlowID   uint64 `json:"flow_id"`
	Retained int    `json:"retained"`
	Cap      int    `json:"cap"`

	// Truncated is true when this flow's earliest versions were dropped because
	// it exceeded the per-flow cap. Detected exactly: the first snapshot a flow
	// emits carries snapshot_index 1, so a history starting above that is
	// missing earlier versions.
	Truncated bool `json:"truncated"`

	// Snapshotting is false for a flow that only ever produced its terminal
	// record — the common case, and not a gap.
	Snapshotting bool `json:"snapshotting"`

	Versions []flowVersionView `json:"versions"`
	Notes    []string          `json:"notes,omitempty"`
}

// handleFlowSnapshots serves GET /api/v1/flows/{id}/snapshots.
func (s *Server) handleFlowSnapshots(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad flow id", http.StatusBadRequest)
		return
	}
	hist := s.store.FlowHistory(id)
	if len(hist) == 0 {
		http.Error(w, "flow not found", http.StatusNotFound)
		return
	}

	out := flowSnapshots{
		FlowID:   id,
		Retained: len(hist),
		Cap:      storage.FlowHistoryCap,
		Versions: make([]flowVersionView, 0, len(hist)),
	}

	verdicts := s.classificationsFor(id)
	missing := 0

	for _, rec := range hist {
		if rec.CloseReason == "snapshot" {
			out.Snapshotting = true
		}
		v := flowVersionView{
			SnapshotIndex: rec.SnapshotIndex,
			CloseReason:   rec.CloseReason,
			Terminal:      rec.CloseReason != "snapshot",
			FirstSeen:     rec.FirstSeen,
			LastSeen:      rec.LastSeen,
			DurationSec:   rec.DurationSec,
			FwdPackets:    rec.FwdPackets,
			BwdPackets:    rec.BwdPackets,
			FwdBytes:      rec.FwdBytes,
			BwdBytes:      rec.BwdBytes,
		}
		// The pipeline stamps Classification.TS from the record's LastSeen, so
		// versions pair with verdicts by exact timestamp. Matches are consumed
		// so two versions sharing a LastSeen cannot claim the same verdict.
		if c, ok := takeVerdict(verdicts, rec.LastSeen); ok {
			v.Verdict = &versionVerdict{
				Class: c.Result.Class, ClassID: c.Result.ClassID,
				Score: c.Result.Score, Disagreement: c.Result.Disagreement,
			}
		} else {
			missing++
		}
		out.Versions = append(out.Versions, v)
	}

	if len(hist) > 0 && hist[0].CloseReason == "snapshot" && hist[0].SnapshotIndex > 1 {
		out.Truncated = true
		out.Notes = append(out.Notes,
			"This flow's earliest snapshots are no longer retained: history is capped at "+
				strconv.Itoa(storage.FlowHistoryCap)+" versions per flow and the oldest are "+
				"dropped first.")
	}
	if missing > 0 {
		out.Notes = append(out.Notes,
			strconv.Itoa(missing)+" of these versions have no retained verdict — their "+
				"classifications aged out of the bounded ring. That is a retention gap, "+
				"not an unclassified flow.")
	}
	if out.Snapshotting {
		out.Notes = append(out.Notes,
			"Counters are cumulative, not per-interval: each version reports the flow's "+
				"totals as of its own last_seen. Note also that a long flow's terminal "+
				"record inherits the last snapshot's snapshot_index, so the final two rows "+
				"may share an index.")
	}

	writeJSON(w, http.StatusOK, out)
}

// classificationsFor collects the retained verdicts for one flow, oldest first.
func (s *Server) classificationsFor(id uint64) []storage.Classification {
	all := s.store.RecentClassifications(0) // newest-first
	out := make([]storage.Classification, 0, 4)
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].FlowID == id {
			out = append(out, all[i])
		}
	}
	return out
}

// takeVerdict removes and returns the first verdict stamped at ts. The slice is
// mutated through the pointer-free trick of zeroing the consumed entry's FlowID,
// so a later version cannot match it again.
func takeVerdict(verdicts []storage.Classification, ts time.Time) (storage.Classification, bool) {
	for i := range verdicts {
		if verdicts[i].FlowID != 0 && verdicts[i].TS.Equal(ts) {
			c := verdicts[i]
			verdicts[i].FlowID = 0 // consumed
			return c, true
		}
	}
	return storage.Classification{}, false
}
