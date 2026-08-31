package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

func quiet(string, ...any) {}

// modelServer builds an API server with a real registry + audit log over a temp
// model directory, and returns the server so a test can inspect the live Runtime.
func modelServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Models.Directory = dir
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	reg := registry.Open(dir, quiet)
	aud := audit.New(dir, quiet)
	srv := New(cfg, events.New(), storage.NewMem(100, 100), rt, reg, aud, nil, nil, nil)
	return srv, dir
}

// registerBundle writes a valid bundle under dir/name and registers it.
func registerBundle(t *testing.T, srv *Server, dir, name string, b modeltest.Bundle) registry.Entry {
	t.Helper()
	bdir := filepath.Join(dir, name)
	if _, err := modeltest.Write(bdir, b); err != nil {
		t.Fatalf("modeltest.Write: %v", err)
	}
	loaded, err := model.Load(bdir)
	if err != nil {
		t.Fatalf("model.Load: %v", err)
	}
	e, err := srv.reg.Register(loaded)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return e
}

func do(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
	return rr
}

func TestModelActivateUnknownID(t *testing.T) {
	srv, _ := modelServer(t)
	rr := do(t, srv.Handler(), "POST", "/api/v1/models/ghost/activate")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("activate unknown id = %d, want 404", rr.Code)
	}
	rr = do(t, srv.Handler(), "POST", "/api/v1/models/ghost/deactivate")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("deactivate unknown id = %d, want 404", rr.Code)
	}
	rr = do(t, srv.Handler(), "GET", "/api/v1/models/ghost")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET unknown id = %d, want 404", rr.Code)
	}
}

func TestModelActivateInvalidBundle(t *testing.T) {
	srv, dir := modelServer(t)
	e := registerBundle(t, srv, dir, "m1", modeltest.Bundle{ModelID: "onnx-1"})

	// Corrupt model.onnx on disk after registration: the activate gate re-loads
	// and re-validates, so it must now 409.
	if err := os.WriteFile(filepath.Join(e.Dir, "model.onnx"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	rr := do(t, srv.Handler(), "POST", "/api/v1/models/onnx-1/activate")
	if rr.Code != http.StatusConflict {
		t.Fatalf("activate a no-longer-valid bundle = %d, want 409 (%s)", rr.Code, rr.Body.String())
	}
	// The Runtime must be untouched — still the heuristic.
	if got := srv.rt.Models(); len(got) != 1 || got[0].ID() != "heuristic-v1" {
		t.Fatalf("Runtime changed on a failed activate: %v", got)
	}
}

func TestModelActivateHappyPathAndDeactivate(t *testing.T) {
	srv, dir := modelServer(t)
	registerBundle(t, srv, dir, "m1", modeltest.Bundle{ModelID: "onnx-1"})
	h := srv.Handler()

	// Before: listed as registered, not loaded.
	rr := do(t, h, "GET", "/api/v1/models")
	var list struct {
		Models []struct {
			ModelID string `json:"model_id"`
			Status  string `json:"status"`
			Runtime struct {
				Loaded bool `json:"loaded"`
			} `json:"runtime"`
		} `json:"models"`
		Runtime []struct {
			ID         string `json:"id"`
			Registered bool   `json:"registered"`
		} `json:"runtime"`
	}
	mustJSON(t, rr, &list)
	if len(list.Models) != 1 || list.Models[0].Status != "registered" || list.Models[0].Runtime.Loaded {
		t.Fatalf("pre-activate model view = %+v", list.Models)
	}
	if len(list.Runtime) != 1 || list.Runtime[0].ID != "heuristic-v1" || list.Runtime[0].Registered {
		t.Fatalf("pre-activate runtime view = %+v", list.Runtime)
	}

	// Activate.
	rr = do(t, h, "POST", "/api/v1/models/onnx-1/activate")
	if rr.Code != http.StatusOK {
		t.Fatalf("activate = %d (%s)", rr.Code, rr.Body.String())
	}
	if got := srv.rt.Models(); len(got) != 1 || got[0].ID() != "onnx-1" {
		t.Fatalf("Runtime after activate = %v", got)
	}

	// GET /api/v1/models/{id} shows active + loaded, with lineage.
	rr = do(t, h, "GET", "/api/v1/models/onnx-1")
	var detail struct {
		Entry struct {
			Status  string `json:"status"`
			Runtime struct {
				Loaded bool   `json:"loaded"`
				Role   string `json:"role"`
			} `json:"runtime"`
		} `json:"entry"`
		Lineage  []map[string]any `json:"lineage"`
		Children []map[string]any `json:"children"`
	}
	mustJSON(t, rr, &detail)
	if detail.Entry.Status != "active" || !detail.Entry.Runtime.Loaded || detail.Entry.Runtime.Role != "primary" {
		t.Fatalf("detail after activate = %+v", detail.Entry)
	}
	if len(detail.Lineage) != 1 {
		t.Fatalf("lineage of a root model = %v", detail.Lineage)
	}

	// Deactivate flips it back and restores the heuristic.
	rr = do(t, h, "POST", "/api/v1/models/onnx-1/deactivate")
	if rr.Code != http.StatusOK {
		t.Fatalf("deactivate = %d (%s)", rr.Code, rr.Body.String())
	}
	if got := srv.rt.Models(); len(got) != 1 || got[0].ID() != "heuristic-v1" {
		t.Fatalf("Runtime after deactivate = %v", got)
	}
	if e, _ := srv.reg.Get("onnx-1"); e.Status != "deactivated" {
		t.Fatalf("entry status after deactivate = %s", e.Status)
	}

	// The audit log recorded activate + deactivate.
	blob, err := os.ReadFile(filepath.Join(dir, audit.FileName))
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	s := string(blob)
	if !strings.Contains(s, "ModelActivated") || !strings.Contains(s, "ModelDeactivated") {
		t.Fatalf("audit log missing events:\n%s", s)
	}
}

func TestModelLineageEndpoint(t *testing.T) {
	srv, dir := modelServer(t)
	registerBundle(t, srv, dir, "g", modeltest.Bundle{ModelID: "global", Seed: 1})
	registerBundle(t, srv, dir, "c", modeltest.Bundle{ModelID: "cph", DerivedFrom: "global", Seed: 2})
	registerBundle(t, srv, dir, "c2", modeltest.Bundle{ModelID: "cph-v2", DerivedFrom: "cph", Seed: 3})

	rr := do(t, srv.Handler(), "GET", "/api/v1/models/cph-v2/lineage")
	if rr.Code != http.StatusOK {
		t.Fatalf("lineage = %d", rr.Code)
	}
	var out struct {
		Lineage []struct {
			ModelID string `json:"model_id"`
		} `json:"lineage"`
		Tree []struct {
			Entry struct {
				ModelID string `json:"model_id"`
			} `json:"entry"`
		} `json:"tree"`
	}
	mustJSON(t, rr, &out)
	if len(out.Lineage) != 3 || out.Lineage[0].ModelID != "global" || out.Lineage[2].ModelID != "cph-v2" {
		t.Fatalf("lineage chain = %+v", out.Lineage)
	}
	if len(out.Tree) != 1 || out.Tree[0].Entry.ModelID != "global" {
		t.Fatalf("lineage forest = %+v", out.Tree)
	}
}

func TestModelRoutesWithoutRegistry(t *testing.T) {
	// New(..., reg=nil, ...): GET /api/v1/models still works (runtime only),
	// state-changing routes report 503.
	h := newTestServer()
	if rr := do(t, h, "GET", "/api/v1/models"); rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/models with no registry = %d", rr.Code)
	}
	if rr := do(t, h, "POST", "/api/v1/models/x/activate"); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("activate with no registry = %d, want 503", rr.Code)
	}
}

func mustJSON(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		t.Fatalf("response not JSON (%d): %v\n%s", rr.Code, err, rr.Body.String())
	}
}
