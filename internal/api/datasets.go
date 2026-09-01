package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/dataset"
)

// The dataset routes (PROJECT.md §14, §19.10; issue #33).
//
// POST and DELETE are state-changing and unauthenticated for now — the same
// posture as POST /api/v1/replay, POST /api/v1/captures and the model
// activate/deactivate routes, where binding to loopback by default is the only
// control. Creating a dataset reads the flow store and writes a directory under
// datasets.directory; deleting one removes that directory.
// When auth.enabled, POST/DELETE here require role `admin`; otherwise the
// loopback bind is the only control (issue #58).
//
// Addressing a dataset: an id may contain one "/" (PROJECT.md §14 writes
// "thugs/lab-attacks-2026-08"), which would otherwise split into two path
// segments and make {id}/{version} ambiguous. So a single dataset is addressed
// by one url-escaped {ref} segment holding "<id>@<version>":
//
//	GET /api/v1/datasets/thugs%2Flab-attacks-2026-08%40v1
//
// net/http's ServeMux matches wildcards against the escaped path and unescapes
// each segment for PathValue, so an encoded "%2F" stays inside one segment and
// arrives intact. A reverse proxy that normalises "%2F" into "/" would break
// this; document that with any non-loopback deployment (docs/api.md).

// maxDatasetBody bounds a create request. The body is metadata plus a
// selection — kilobytes at most.
const maxDatasetBody = 1 << 16

// datasetCreateRequest is the POST /api/v1/datasets body: the §14 metadata plus
// the row selection, plus an optional parent for a derive.
type datasetCreateRequest struct {
	ID               string   `json:"id"`
	Version          string   `json:"version"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Location         string   `json:"location"`
	Tags             []string `json:"tags"`
	SourceCaptureIDs []string `json:"source_capture_ids"`

	// DeriveFrom is "<id>@<version>". When set the new dataset records that
	// dataset as its parent (PROJECT.md §14 parent_datasets).
	DeriveFrom string `json:"derive_from"`

	Selection datasetSelectionRequest `json:"selection"`
}

// datasetSelectionRequest mirrors dataset.Selection on the wire, but takes the
// time bounds as RFC3339 strings and min_confidence the way the flow log's
// slider sends it, so the field names and meanings match the
// GET /api/v1/classifications query parameters an operator already knows.
type datasetSelectionRequest struct {
	From          string  `json:"from"`
	To            string  `json:"to"`
	Class         string  `json:"class"`
	Model         string  `json:"model"`
	Proto         string  `json:"proto"`
	InitiatorIP   string  `json:"initiator_ip"`
	ResponderIP   string  `json:"responder_ip"`
	MinConfidence float64 `json:"min_confidence"`
	Disagreement  bool    `json:"disagreement"`
	Limit         int     `json:"limit"`
	Scan          int     `json:"scan"`

	// Reviewed cuts a curated dataset from the human review store instead of the
	// classification ring, using the operator's label (PROJECT.md §16, issue
	// #42). It is the only way a manifest's labeling_source can say
	// "human_review". IncludeIgnored opts ignored_pattern reviews in, which makes
	// the cut mixed and says so in labeling_source.
	Reviewed       bool `json:"reviewed"`
	IncludeIgnored bool `json:"include_ignored"`
}

// toSelection converts the wire form, parsing the timestamps and normalising a
// percentage min_confidence to 0..1 exactly as parseClassFilters does.
func (r datasetSelectionRequest) toSelection() (dataset.Selection, error) {
	sel := dataset.Selection{
		Class:          r.Class,
		Model:          r.Model,
		Proto:          r.Proto,
		InitiatorIP:    r.InitiatorIP,
		ResponderIP:    r.ResponderIP,
		MinConfidence:  r.MinConfidence,
		Disagreement:   r.Disagreement,
		Limit:          r.Limit,
		Scan:           r.Scan,
		Reviewed:       r.Reviewed,
		IncludeIgnored: r.IncludeIgnored,
	}
	if r.MinConfidence > 1 { // accept a 0..100 percentage, like the web UI's slider
		sel.MinConfidence = r.MinConfidence / 100
	}
	var err error
	if sel.From, err = parseTimeParam("from", r.From); err != nil {
		return dataset.Selection{}, err
	}
	if sel.To, err = parseTimeParam("to", r.To); err != nil {
		return dataset.Selection{}, err
	}
	return sel, nil
}

func parseTimeParam(name, v string) (time.Time, error) {
	if strings.TrimSpace(v) == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("selection.%s: %q is not an RFC3339 timestamp", name, v)
	}
	return t, nil
}

// datasetStatus maps a dataset error to its HTTP status.
func datasetStatus(err error) int {
	switch {
	case errors.Is(err, dataset.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, dataset.ErrExists):
		return http.StatusConflict
	case errors.Is(err, dataset.ErrUnusable):
		return http.StatusUnprocessableEntity
	case errors.Is(err, dataset.ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// handleDatasets serves GET /api/v1/datasets — every dataset version's
// manifest, newest created first. With no dataset manager wired it returns an
// empty array rather than 503, so the Datasets view always renders.
func (s *Server) handleDatasets(w http.ResponseWriter, _ *http.Request) {
	list := []dataset.Dataset{}
	if s.ds != nil {
		if got := s.ds.List(); got != nil {
			list = got
		}
	}
	cols := dataset.Columns()
	writeJSON(w, http.StatusOK, map[string]any{
		"datasets":     list,
		"columns":      cols,
		"label_column": dataset.LabelColumn,
		"min_rows":     dataset.MinRows,
	})
}

// handleDataset serves GET /api/v1/datasets/{ref} — one manifest, plus the
// other versions of the same id for context.
//
//	400 the ref is not "<id>@<version>"
//	404 unknown dataset version
//	503 no dataset manager wired
func (s *Server) handleDataset(w http.ResponseWriter, r *http.Request) {
	if s.ds == nil {
		http.Error(w, "dataset manager not available", http.StatusServiceUnavailable)
		return
	}
	id, version, err := dataset.ParseRef(r.PathValue("ref"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d, ok := s.ds.Get(id, version)
	if !ok {
		http.Error(w, "unknown dataset "+id+"@"+version, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dataset":  d,
		"versions": s.ds.Versions(id),
	})
}

// handleDatasetCreate serves POST /api/v1/datasets: it materialises the
// selection into an immutable version on disk and returns its manifest.
//
//	201 + {"dataset": …} on success
//	400 bad body, bad id/version, bad selection
//	404 derive_from names a dataset that does not exist
//	409 (id, version) already exists — a version is immutable, pick a new one
//	422 the selection yields nothing a trainer could use
//	503 no dataset manager wired
func (s *Server) handleDatasetCreate(w http.ResponseWriter, r *http.Request) {
	if s.ds == nil {
		http.Error(w, "dataset manager not available", http.StatusServiceUnavailable)
		return
	}

	var req datasetCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDatasetBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	sel, err := req.Selection.toSelection()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	spec := dataset.Spec{
		ID:               req.ID,
		Version:          req.Version,
		Name:             req.Name,
		Description:      req.Description,
		Location:         req.Location,
		Tags:             req.Tags,
		SourceCaptureIDs: req.SourceCaptureIDs,
		Selection:        sel,
	}

	var (
		d     *dataset.Dataset
		event = audit.EventDatasetCreated
	)
	if req.DeriveFrom != "" {
		pid, pver, perr := dataset.ParseRef(req.DeriveFrom)
		if perr != nil {
			http.Error(w, "derive_from: "+perr.Error(), http.StatusBadRequest)
			return
		}
		event = audit.EventDatasetDerived
		d, err = s.ds.Derive(pid, pver, spec)
	} else {
		d, err = s.ds.Create(spec)
	}
	if err != nil {
		http.Error(w, err.Error(), datasetStatus(err))
		return
	}

	detail := fmt.Sprintf("hash=%s flows=%d labeling_source=%s", d.ContentHash, d.FlowCount, d.LabelingSource)
	if req.DeriveFrom != "" {
		detail += " parent=" + req.DeriveFrom
	}
	s.audit.LogSubject(event, audit.ActorLocal, audit.SubjectDataset, d.Ref(), detail)

	writeJSON(w, http.StatusCreated, map[string]any{"dataset": d})
}

// handleDatasetDownload serves GET /api/v1/datasets/{ref}/download — the
// dataset.csv itself, so a trainer host can fetch a dataset over the API
// instead of needing the daemon's filesystem.
//
//	404 unknown dataset version, or its CSV has gone missing under it
//	503 no dataset manager wired
func (s *Server) handleDatasetDownload(w http.ResponseWriter, r *http.Request) {
	if s.ds == nil {
		http.Error(w, "dataset manager not available", http.StatusServiceUnavailable)
		return
	}
	id, version, err := dataset.ParseRef(r.PathValue("ref"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d, ok := s.ds.Get(id, version)
	if !ok {
		http.Error(w, "unknown dataset "+id+"@"+version, http.StatusNotFound)
		return
	}
	path, err := s.ds.CSVPath(id, version)
	if err != nil {
		http.Error(w, err.Error(), datasetStatus(err))
		return
	}
	f, err := os.Open(path) //nolint:gosec // path comes from the manager's validated id/version, never from the request
	if err != nil {
		http.Error(w, "dataset csv is not readable", http.StatusNotFound)
		return
	}
	defer func() { _ = f.Close() }()

	// The filename is built from the validated slug id/version, so it cannot
	// contain a quote, a newline or a path separator other than the id's single
	// "/", which is replaced. Still quote it, and still send the header content
	// hash so a downloader can verify what it got.
	name := strings.ReplaceAll(d.ID, "/", "_") + "-" + d.Version + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Synapse-Dataset-Hash", d.ContentHash)
	w.Header().Set("X-Synapse-Feature-Schema", d.FeatureSchema)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, filepath.Base(path), time.Time{}, f)
}

// handleDatasetDelete serves DELETE /api/v1/datasets/{ref}. Immutability
// protects a version's contents, not its existence: an operator who cut a
// dataset from the wrong window must be able to remove it. It is audited.
//
//	404 unknown dataset version
//	503 no dataset manager wired
func (s *Server) handleDatasetDelete(w http.ResponseWriter, r *http.Request) {
	if s.ds == nil {
		http.Error(w, "dataset manager not available", http.StatusServiceUnavailable)
		return
	}
	id, version, err := dataset.ParseRef(r.PathValue("ref"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d, ok := s.ds.Get(id, version)
	if !ok {
		http.Error(w, "unknown dataset "+id+"@"+version, http.StatusNotFound)
		return
	}
	if err := s.ds.Delete(id, version); err != nil {
		http.Error(w, err.Error(), datasetStatus(err))
		return
	}
	s.audit.LogSubject(audit.EventDatasetDeleted, audit.ActorLocal, audit.SubjectDataset, d.Ref(),
		fmt.Sprintf("hash=%s flows=%d", d.ContentHash, d.FlowCount))
	writeJSON(w, http.StatusOK, map[string]string{"deleted": d.Ref()})
}
