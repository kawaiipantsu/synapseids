package registry_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
	"github.com/kawaiipantsu/synapseids/internal/registry"
)

func silent(string, ...any) {}

func mustRegister(t *testing.T, reg *registry.Registry, b *model.Bundle) {
	t.Helper()
	if _, err := reg.Register(b); err != nil {
		t.Fatalf("Register(%s): %v", b.Dir(), err)
	}
}

// bundle writes a valid bundle under root/name and loads it.
func bundle(t *testing.T, root, name string, b modeltest.Bundle) *model.Bundle {
	t.Helper()
	dir := filepath.Join(root, name)
	if _, err := modeltest.Write(dir, b); err != nil {
		t.Fatalf("modeltest.Write: %v", err)
	}
	loaded, err := model.Load(dir)
	if err != nil {
		t.Fatalf("model.Load(%s): %v", dir, err)
	}
	return loaded
}

func TestRegisterListGet(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)

	b1 := bundle(t, root, "m1", modeltest.Bundle{ModelID: "model-1", Seed: 1})
	b2 := bundle(t, root, "m2", modeltest.Bundle{ModelID: "model-2", Seed: 2})

	e1, err := reg.Register(b1)
	if err != nil {
		t.Fatalf("Register b1: %v", err)
	}
	if e1.Status != registry.StatusRegistered || e1.RegisteredAt == "" {
		t.Fatalf("new entry = %+v", e1)
	}
	if e1.ContentHash != b1.Hash() || e1.ParameterCount != 455 || e1.ArtifactBytes <= 0 {
		t.Fatalf("entry metadata wrong: %+v", e1)
	}
	if _, err := reg.Register(b2); err != nil {
		t.Fatalf("Register b2: %v", err)
	}

	list := reg.List()
	if len(list) != 2 || list[0].ModelID != "model-2" || list[1].ModelID != "model-1" {
		t.Fatalf("List not newest-first: %+v", list)
	}
	got, ok := reg.Get("model-1")
	if !ok || got.ModelID != "model-1" {
		t.Fatalf("Get(model-1) = %+v ok=%v", got, ok)
	}
	if _, ok := reg.Get("nope"); ok {
		t.Fatalf("Get(nope) should be absent")
	}
}

func TestRegisterRejectsInvalidBundle(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	b := bundle(t, root, "bad", modeltest.Bundle{ModelID: "bad-1"})
	// Corrupt model.onnx so the recomputed hash no longer matches metadata.
	if err := os.WriteFile(filepath.Join(root, "bad", "model.onnx"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := model.Load(filepath.Join(root, "bad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Register(reloaded); err == nil {
		t.Fatalf("Register must reject a bundle that fails Validate")
	}
	_ = b
}

func TestRegisterDuplicateHashRejected(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)

	// Same seed => identical model.onnx => identical content hash.
	b1 := bundle(t, root, "a", modeltest.Bundle{ModelID: "model-a", Seed: 7})
	b2 := bundle(t, root, "b", modeltest.Bundle{ModelID: "model-b", Seed: 7})

	if _, err := reg.Register(b1); err != nil {
		t.Fatalf("Register b1: %v", err)
	}
	_, err := reg.Register(b2)
	if err == nil {
		t.Fatalf("Register must reject the same content hash under a different id")
	}
}

func TestRegisterIdempotentSameIDSameHash(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	b := bundle(t, root, "m", modeltest.Bundle{ModelID: "model-x", Seed: 3})

	e1, err := reg.Register(b)
	if err != nil {
		t.Fatalf("Register 1: %v", err)
	}
	if _, err := reg.SetStatus("model-x", registry.StatusActive); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	reloaded, err := model.Load(b.Dir())
	if err != nil {
		t.Fatal(err)
	}
	e2, err := reg.Register(reloaded)
	if err != nil {
		t.Fatalf("re-Register same id+hash must succeed: %v", err)
	}
	if e2.Status != registry.StatusActive {
		t.Fatalf("re-Register must not reset status, got %s", e2.Status)
	}
	if e2.RegisteredAt != e1.RegisteredAt {
		t.Fatalf("re-Register must keep RegisteredAt")
	}
	if len(reg.List()) != 1 {
		t.Fatalf("re-Register must not add a second entry")
	}
}

func TestRegisterSameIDDifferentHashRejected(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	b := bundle(t, root, "m", modeltest.Bundle{ModelID: "model-y", Seed: 3})
	if _, err := reg.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Rewrite the same dir with different weights (new hash) but the same id.
	b2 := bundle(t, root, "m", modeltest.Bundle{ModelID: "model-y", Seed: 999})
	if _, err := reg.Register(b2); err == nil {
		t.Fatalf("Register must reject the same id with a different content hash")
	}
}

func TestLineageChainChildrenAndTree(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)

	// global -> copenhagen -> copenhagen-v2 ; global -> london
	mustRegister(t, reg, bundle(t, root, "g", modeltest.Bundle{ModelID: "global", Seed: 1}))
	mustRegister(t, reg, bundle(t, root, "c1", modeltest.Bundle{ModelID: "cph", DerivedFrom: "global", Seed: 2}))
	mustRegister(t, reg, bundle(t, root, "c2", modeltest.Bundle{ModelID: "cph-v2", DerivedFrom: "cph", Seed: 3}))
	mustRegister(t, reg, bundle(t, root, "l", modeltest.Bundle{ModelID: "london", DerivedFrom: "global", Seed: 4}))

	chain := reg.Lineage("cph-v2")
	if len(chain) != 3 || chain[0].ModelID != "global" || chain[1].ModelID != "cph" || chain[2].ModelID != "cph-v2" {
		t.Fatalf("Lineage(cph-v2) = %v", ids(chain))
	}

	kids := reg.Children("global")
	if len(kids) != 2 {
		t.Fatalf("Children(global) = %v", ids(kids))
	}

	tree := reg.Tree()
	if len(tree) != 1 || tree[0].Entry.ModelID != "global" {
		t.Fatalf("Tree roots = %v", tree)
	}
	// global has children cph and london; cph has child cph-v2.
	if len(tree[0].Children) != 2 {
		t.Fatalf("global children in tree = %d", len(tree[0].Children))
	}
	var cphNode *registry.TreeNode
	for i := range tree[0].Children {
		if tree[0].Children[i].Entry.ModelID == "cph" {
			cphNode = &tree[0].Children[i]
		}
	}
	if cphNode == nil || len(cphNode.Children) != 1 || cphNode.Children[0].Entry.ModelID != "cph-v2" {
		t.Fatalf("expected cph -> cph-v2 in tree, got %+v", tree[0].Children)
	}
}

func TestLineageOrphanParentIsRoot(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	mustRegister(t, reg, bundle(t, root, "x", modeltest.Bundle{ModelID: "x", DerivedFrom: "ghost", Seed: 1}))
	chain := reg.Lineage("x")
	if len(chain) != 1 || chain[0].ModelID != "x" {
		t.Fatalf("orphan lineage = %v", ids(chain))
	}
	if len(reg.Tree()) != 1 || reg.Tree()[0].Entry.ModelID != "x" {
		t.Fatalf("orphan must be a tree root")
	}
}

func TestStatusTransitions(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	mustRegister(t, reg, bundle(t, root, "a", modeltest.Bundle{ModelID: "a", Seed: 1}))
	mustRegister(t, reg, bundle(t, root, "b", modeltest.Bundle{ModelID: "b", Seed: 2}))

	ea, err := reg.SetStatus("a", registry.StatusActive)
	if err != nil {
		t.Fatalf("activate a: %v", err)
	}
	if ea.Status != registry.StatusActive || ea.ActivatedAt == "" {
		t.Fatalf("a = %+v", ea)
	}
	if act, ok := reg.Active(); !ok || act.ModelID != "a" {
		t.Fatalf("Active() = %+v ok=%v", act, ok)
	}

	// Activating b demotes a to deactivated.
	if _, err := reg.SetStatus("b", registry.StatusActive); err != nil {
		t.Fatalf("activate b: %v", err)
	}
	a, _ := reg.Get("a")
	if a.Status != registry.StatusDeactivated {
		t.Fatalf("a should be deactivated after b activated, got %s", a.Status)
	}
	if act, _ := reg.Active(); act.ModelID != "b" {
		t.Fatalf("Active() should be b, got %s", act.ModelID)
	}

	if _, err := reg.SetStatus("b", registry.StatusDeactivated); err != nil {
		t.Fatalf("deactivate b: %v", err)
	}
	if _, ok := reg.Active(); ok {
		t.Fatalf("no model should be active")
	}
	if _, err := reg.SetStatus("nope", registry.StatusActive); err == nil {
		t.Fatalf("SetStatus on unknown id must error")
	}
	if _, err := reg.SetStatus("a", registry.Status("weird")); err == nil {
		t.Fatalf("SetStatus with an invalid status must error")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	mustRegister(t, reg, bundle(t, root, "g", modeltest.Bundle{ModelID: "global", Seed: 1}))
	mustRegister(t, reg, bundle(t, root, "c", modeltest.Bundle{ModelID: "cph", DerivedFrom: "global", Seed: 2}))
	if _, err := reg.SetStatus("cph", registry.StatusActive); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, registry.FileName)); err != nil {
		t.Fatalf("registry.json not written: %v", err)
	}

	reopened := registry.Open(root, silent)
	list := reopened.List()
	if len(list) != 2 {
		t.Fatalf("reopened List = %v", ids(list))
	}
	cph, ok := reopened.Get("cph")
	// Activation does not survive a restart (PROJECT.md §28.10): a persisted
	// "active" is reconciled to "deactivated" on load, ActivatedAt kept.
	if !ok || cph.Status != registry.StatusDeactivated || cph.ActivatedAt == "" || cph.DerivedFrom != "global" {
		t.Fatalf("reopened cph = %+v", cph)
	}
	if _, active := reopened.Active(); active {
		t.Fatalf("no model should be active after a reopen")
	}
	if chain := reopened.Lineage("cph"); len(chain) != 2 {
		t.Fatalf("reopened lineage = %v", ids(chain))
	}
}

func TestActiveIsReconciledToDeactivatedOnReopen(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	mustRegister(t, reg, bundle(t, root, "m", modeltest.Bundle{ModelID: "m", Seed: 1}))
	if _, err := reg.SetStatus("m", registry.StatusActive); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	var logged bool
	reopened := registry.Open(root, func(f string, _ ...any) {
		if len(f) > 0 {
			logged = true
		}
	})
	e, _ := reopened.Get("m")
	if e.Status != registry.StatusDeactivated {
		t.Fatalf("reopened status = %s, want deactivated (activation must not survive a restart)", e.Status)
	}
	if e.ActivatedAt == "" {
		t.Fatalf("ActivatedAt must be preserved across the reconciliation")
	}
	if !logged {
		t.Fatalf("the reconciliation should be logged")
	}
	// And it must be persisted, so a third open is already consistent.
	third := registry.Open(root, silent)
	if e, _ := third.Get("m"); e.Status != registry.StatusDeactivated {
		t.Fatalf("reconciliation not persisted: %s", e.Status)
	}
}

// Reconciled names the models the reopen demoted, so the daemon can write the
// matching ModelDeactivated audit line — without it the model's last audit
// record would still claim it is active (PROJECT.md §21, §28.10).
func TestReconciledNamesDemotedModels(t *testing.T) {
	root := t.TempDir()
	reg := registry.Open(root, silent)
	mustRegister(t, reg, bundle(t, root, "m", modeltest.Bundle{ModelID: "m", Seed: 1}))
	mustRegister(t, reg, bundle(t, root, "n", modeltest.Bundle{ModelID: "n", Seed: 2}))

	// Nothing was active on disk, so nothing was reconciled.
	if got := reg.Reconciled(); len(got) != 0 {
		t.Fatalf("fresh registry reconciled %v, want none", got)
	}
	if _, err := reg.SetStatus("m", registry.StatusActive); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	reopened := registry.Open(root, silent)
	if got := reopened.Reconciled(); len(got) != 1 || got[0] != "m" {
		t.Fatalf("Reconciled() = %v, want [m]", got)
	}
	// A further reopen has nothing left to demote: the reconciliation was
	// persisted, so the audit line is written once, not on every boot.
	if got := registry.Open(root, silent).Reconciled(); len(got) != 0 {
		t.Fatalf("second reopen reconciled %v, want none", got)
	}
	// The returned slice is a copy — a caller cannot corrupt registry state.
	again := reopened.Reconciled()
	if len(again) > 0 {
		again[0] = "tampered"
		if reopened.Reconciled()[0] != "m" {
			t.Fatal("Reconciled() aliases internal state")
		}
	}
}

func TestCorruptFileToleratedStartsEmpty(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, registry.FileName), []byte("{ this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	var logged bool
	reg := registry.Open(root, func(string, ...any) { logged = true })
	if len(reg.List()) != 0 {
		t.Fatalf("corrupt file must start empty")
	}
	if !logged {
		t.Fatalf("corrupt file must be logged")
	}
	// The registry must still be usable and overwrite the bad file.
	mustRegister(t, reg, bundle(t, root, "m", modeltest.Bundle{ModelID: "m", Seed: 1}))
	if registry.Open(root, silent).List()[0].ModelID != "m" {
		t.Fatalf("registry must recover after a corrupt file")
	}
}

func ids[T any](xs []T) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		switch v := any(x).(type) {
		case registry.Entry:
			out = append(out, v.ModelID)
		}
	}
	return out
}
