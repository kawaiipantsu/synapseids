package registry_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/modeltest"
	"github.com/kawaiipantsu/synapseids/internal/registry"
)

func status(t *testing.T, reg *registry.Registry, id string) registry.Status {
	t.Helper()
	e, ok := reg.Get(id)
	if !ok {
		t.Fatalf("Get(%q): not found", id)
	}
	return e.Status
}

// A primary classifier and an anomaly autoencoder can be Active at the same
// time; activating a new model demotes only the previous Active in the *same*
// role (ADR 0037).
func TestRolesCoexistAndDemoteWithinRole(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)

	mustRegister(t, reg, bundle(t, root, "clf1", modeltest.Bundle{ModelID: "clf-1", Seed: 1}))
	mustRegister(t, reg, bundle(t, root, "clf2", modeltest.Bundle{ModelID: "clf-2", Seed: 2}))
	mustRegister(t, reg, bundle(t, root, "ae1", modeltest.Bundle{Family: "flow-anomaly-v1", ModelID: "ae-1", Seed: 3}))
	mustRegister(t, reg, bundle(t, root, "ae2", modeltest.Bundle{Family: "flow-anomaly-v1", ModelID: "ae-2", Seed: 4}))

	if e, _ := reg.Get("clf-1"); e.Role != "primary" {
		t.Fatalf("clf-1 role = %q, want primary", e.Role)
	}
	if e, _ := reg.Get("ae-1"); e.Role != "anomaly" {
		t.Fatalf("ae-1 role = %q, want anomaly", e.Role)
	}

	if _, err := reg.SetStatus("clf-1", registry.StatusActive); err != nil {
		t.Fatalf("activate clf-1: %v", err)
	}
	if _, err := reg.SetStatus("ae-1", registry.StatusActive); err != nil {
		t.Fatalf("activate ae-1: %v", err)
	}

	// Both live, in their own roles.
	if a, ok := reg.Active(); !ok || a.ModelID != "clf-1" {
		t.Fatalf("Active() = %+v ok=%v, want clf-1", a, ok)
	}
	if a, ok := reg.ActiveByRole("anomaly"); !ok || a.ModelID != "ae-1" {
		t.Fatalf("ActiveByRole(anomaly) = %+v ok=%v, want ae-1", a, ok)
	}
	if status(t, reg, "clf-1") != registry.StatusActive {
		t.Fatalf("activating an anomaly model must not demote the primary")
	}

	// A second anomaly model demotes ae-1 only.
	if _, err := reg.SetStatus("ae-2", registry.StatusActive); err != nil {
		t.Fatalf("activate ae-2: %v", err)
	}
	if status(t, reg, "ae-1") != registry.StatusDeactivated {
		t.Fatalf("ae-1 should be deactivated")
	}
	if status(t, reg, "clf-1") != registry.StatusActive {
		t.Fatalf("clf-1 must stay active while anomaly models swap")
	}

	// A second classifier demotes clf-1 only.
	if _, err := reg.SetStatus("clf-2", registry.StatusActive); err != nil {
		t.Fatalf("activate clf-2: %v", err)
	}
	if status(t, reg, "clf-1") != registry.StatusDeactivated {
		t.Fatalf("clf-1 should be deactivated")
	}
	if status(t, reg, "ae-2") != registry.StatusActive {
		t.Fatalf("ae-2 must stay active while classifiers swap")
	}
}

// Role is persisted and survives the startup reconcile, which still demotes
// every Active entry regardless of role.
func TestRolePersistsAndBothRolesReconcile(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	mustRegister(t, reg, bundle(t, root, "clf", modeltest.Bundle{ModelID: "clf-1", Seed: 1}))
	mustRegister(t, reg, bundle(t, root, "ae", modeltest.Bundle{Family: "flow-anomaly-v1", ModelID: "ae-1", Seed: 2}))
	if _, err := reg.SetStatus("clf-1", registry.StatusActive); err != nil {
		t.Fatalf("activate clf-1: %v", err)
	}
	if _, err := reg.SetStatus("ae-1", registry.StatusActive); err != nil {
		t.Fatalf("activate ae-1: %v", err)
	}

	reopened := registry.Open(root, silent)
	for _, id := range []string{"clf-1", "ae-1"} {
		if status(t, reopened, id) != registry.StatusDeactivated {
			t.Fatalf("%s must be reconciled to deactivated on restart", id)
		}
	}
	if got := len(reopened.Reconciled()); got != 2 {
		t.Fatalf("Reconciled() = %d, want 2", got)
	}
	if e, _ := reopened.Get("ae-1"); e.Role != "anomaly" {
		t.Fatalf("ae-1 role not preserved across reload: %q", e.Role)
	}
}

// A registry.json written before the Role field existed loads with every entry
// treated as a primary.
func TestLegacyRegistryJSONWithoutRole(t *testing.T) {
	root := t.TempDir()
	legacy := `{"version":1,"entries":[{"model_id":"legacy-1","family":"flow-classifier-v1","status":"deactivated"}]}`
	if err := os.WriteFile(filepath.Join(root, registry.FileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := registry.Open(root, silent)
	if _, err := reg.SetStatus("legacy-1", registry.StatusActive); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if a, ok := reg.Active(); !ok || a.ModelID != "legacy-1" {
		t.Fatalf("a role-less legacy entry must count as primary: %+v ok=%v", a, ok)
	}
	if _, ok := reg.ActiveByRole("anomaly"); ok {
		t.Fatalf("no anomaly model is active")
	}
}
