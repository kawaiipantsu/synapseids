package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/review"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/workbench"
)

// SetWorkbench attaches the external-worker queue; no process is launched here.
func (s *Server) SetWorkbench(q *workbench.Store) { s.workbench = q }
func (s *Server) handleWorkbench(w http.ResponseWriter, r *http.Request) {
	if s.workbench == nil {
		http.Error(w, "Training workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case "GET":
		jobs, online := s.workbench.List()
		writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs, "worker_online": online, "corpora": s.workbench.Corpora(), "attack_classes": schema.AttackV2(), "application_classes": schema.ApplicationV1()})
	case "POST":
		var req workbench.Request
		if !workbenchBody(w, r, &req) {
			return
		}
		if req.Kind == "prepare" {
			known := false
			classes := schema.AttackV2()
			if req.Task == "application" {
				classes = schema.ApplicationV1()
			}
			for _, c := range classes.Classes {
				if req.Label == c.Name {
					known = true
				}
			}
			if !known {
				http.Error(w, "Unknown training label", http.StatusBadRequest)
				return
			}
		}
		j, e := s.workbench.Enqueue(req)
		if e != nil {
			http.Error(w, e.Error(), http.StatusBadRequest)
			return
		}
		s.audit.LogSubject("TrainingJobQueued", audit.ActorLocal, audit.SubjectTraining, j.ID, "kind="+req.Kind+" task="+req.Task)
		writeJSON(w, http.StatusCreated, j)
	}
}
func workbenchBody(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "Invalid request JSON", http.StatusBadRequest)
		return false
	}
	return true
}
func (s *Server) handleWorkbenchClaim(w http.ResponseWriter, _ *http.Request) {
	if s.workbench == nil {
		http.Error(w, "Workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	j, ok, e := s.workbench.Claim()
	if e != nil {
		http.Error(w, "Could not persist worker lease", http.StatusInternalServerError)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, j)
}
func (s *Server) handleWorkbenchUpdate(w http.ResponseWriter, r *http.Request) {
	if s.workbench == nil {
		http.Error(w, "Workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Lease   string `json:"lease"`
		Status  string `json:"status"`
		RunID   string `json:"run_id"`
		ModelID string `json:"model_id"`
		Message string `json:"message"`
	}
	if !workbenchBody(w, r, &req) {
		return
	}
	if e := s.workbench.Update(r.PathValue("id"), req.Lease, req.Status, req.RunID, req.ModelID, req.Message); e != nil {
		http.Error(w, e.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleWorkbenchCancel(w http.ResponseWriter, r *http.Request) {
	if s.workbench == nil {
		http.Error(w, "Workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	if e := s.workbench.Cancel(r.PathValue("id")); e != nil {
		http.Error(w, e.Error(), http.StatusConflict)
		return
	}
	s.audit.LogSubject("TrainingJobCancelled", audit.ActorLocal, audit.SubjectTraining, r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}

// Upload is a bounded offline PCAP import. It never injects traffic or opens it
// through the live pipeline; a separate worker extracts numeric training rows.
func (s *Server) handleWorkbenchUpload(w http.ResponseWriter, r *http.Request) {
	if s.workbench == nil {
		http.Error(w, "Workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	dir := filepath.Join(s.workbench.Dir(), "uploads")
	entries, e := os.ReadDir(dir)
	if e != nil {
		http.Error(w, "Upload directory unavailable", http.StatusInternalServerError)
		return
	}
	var total int64
	for _, f := range entries {
		if info, e := f.Info(); e == nil {
			total += info.Size()
		}
	}
	if len(entries) >= 32 || total >= 1<<30 {
		http.Error(w, "Capture quota reached (32 files / 1 GiB). Remove unused local uploads.", http.StatusConflict)
		return
	}
	f, e := os.CreateTemp(dir, "capture-*.pcap")
	if e != nil {
		http.Error(w, "Could not create capture", http.StatusInternalServerError)
		return
	}
	path := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	n, e := io.Copy(f, http.MaxBytesReader(w, r.Body, 128<<20))
	if e != nil || n < 24 {
		http.Error(w, "Expected a PCAP / PCAPNG file up to 128 MiB", http.StatusBadRequest)
		return
	}
	if f.Close() != nil {
		http.Error(w, "Could not save capture", http.StatusInternalServerError)
		return
	}
	src, e := capture.OpenPCAPFile(path)
	if e != nil {
		http.Error(w, "Unsupported or invalid PCAP header", http.StatusBadRequest)
		return
	}
	_ = src.Close()
	keep = true
	id := filepath.Base(path)
	id = id[:len(id)-len(".pcap")]
	writeJSON(w, http.StatusCreated, map[string]any{"capture_id": id, "bytes": n})
}
func (s *Server) handleWorkbenchRegister(w http.ResponseWriter, r *http.Request) {
	if s.workbench == nil || s.reg == nil {
		http.Error(w, "Workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	jobs, _ := s.workbench.List()
	var id string
	for _, j := range jobs {
		if j.ID == r.PathValue("id") && j.Status == "completed" {
			id = j.ModelID
		}
	}
	if !workbench.ValidID(id) {
		http.Error(w, "No completed candidate for this job", http.StatusConflict)
		return
	}
	b, e := model.Load(filepath.Join(s.cfg.Models.Directory, id))
	if e != nil {
		http.Error(w, "Candidate bundle is unavailable", http.StatusConflict)
		return
	}
	if b.Meta().ModelID != id {
		http.Error(w, "Candidate identity mismatch", http.StatusConflict)
		return
	}
	entry, e := s.reg.Register(b)
	if e != nil {
		http.Error(w, "Candidate failed validation: "+e.Error(), http.StatusConflict)
		return
	}
	s.audit.Log(audit.EventModelRegistered, audit.ActorLocal, id, "workbench candidate registered; inactive")
	writeJSON(w, http.StatusOK, entry)
}

// handleWorkbenchReviews creates training data only after an operator explicitly
// requests it. Reviewer identities, addresses, notes and predictions are omitted.
func (s *Server) handleWorkbenchReviews(w http.ResponseWriter, _ *http.Request) {
	if s.workbench == nil || s.rv == nil {
		http.Error(w, "Review export unavailable", http.StatusServiceUnavailable)
		return
	}
	rows := []workbench.NumericRow{}
	skipped := 0
	for _, r := range s.rv.List(review.Filter{Labelled: true, Limit: 100000}) {
		created, e := time.Parse(time.RFC3339, r.CreatedAt)
		if e != nil || created.Before(s.start) {
			skipped++
			continue
		}
		fr, ok := s.store.Flow(r.FlowID)
		label := r.EffectiveLabel()
		if !ok || fr.Behavior == nil || label == "" {
			skipped++
			continue
		}
		groupHash := sha256.Sum256([]byte(fr.Sensor + "/" + s.start.Format(time.RFC3339Nano)))
		conversation := fmt.Sprintf("%s/%s/%d/%s/%d/%d", fr.Proto, fr.InitiatorIP, fr.InitiatorPort, fr.ResponderIP, fr.ResponderPort, fr.FirstSeen.UnixNano())
		convHash := sha256.Sum256([]byte(conversation))
		rows = append(rows, workbench.NumericRow{Values: fr.Behavior.Values, Label: label, Group: hex.EncodeToString(groupHash[:]), Conversation: hex.EncodeToString(convHash[:]), Time: float64(fr.FirstSeen.UnixNano()) / 1e9})
	}
	corpus, e := s.workbench.ExportReviewed(rows)
	if e != nil {
		http.Error(w, e.Error(), http.StatusConflict)
		return
	}
	s.audit.LogSubject("ReviewedCorpusCreated", audit.ActorLocal, audit.SubjectTraining, corpus.ID, "human-labeled vectors exported")
	writeJSON(w, http.StatusCreated, map[string]any{"corpus": corpus, "skipped": skipped})
}
