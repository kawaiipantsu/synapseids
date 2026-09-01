package inference

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

func vec(r flow.Record) features.Vector { return features.Extract(r) }

func TestHeuristicScan(t *testing.T) {
	h := NewHeuristic("", "")
	r := flow.Record{
		ID: 1, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("10.0.0.66"), InitiatorPort: 40001,
		ResponderIP: netip.MustParseAddr("10.0.0.1"), ResponderPort: 22,
		FirstSeen: time.Unix(0, 0), LastSeen: time.Unix(0, 0),
		FwdPackets: 1, FwdBytes: 60, SynCount: 1,
		PktSizeMin: 60, PktSizeMax: 60,
	}
	sc := h.Classify(vec(r))
	idx, p := sc.Top()
	if schema.ClassName(idx) != "scan" {
		t.Fatalf("unanswered SYN should be scan, got %s (%.2f)", schema.ClassName(idx), p)
	}
	if p < 0.8 {
		t.Fatalf("scan confidence too low: %.2f", p)
	}
}

func TestHeuristicNormal(t *testing.T) {
	h := NewHeuristic("", "")
	start := time.Unix(0, 0)
	r := flow.Record{
		ID: 2, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("192.168.1.50"), InitiatorPort: 49712,
		ResponderIP: netip.MustParseAddr("93.184.216.34"), ResponderPort: 443,
		FirstSeen: start, LastSeen: start.Add(120 * time.Millisecond),
		FwdPackets: 6, BwdPackets: 5, FwdBytes: 900, BwdBytes: 6000,
		SynCount: 2, AckCount: 9, FinCount: 2, PshCount: 2,
		PktSizeMin: 52, PktSizeMax: 1420,
	}
	sc := h.Classify(vec(r))
	idx, p := sc.Top()
	if schema.ClassName(idx) != "normal" {
		t.Fatalf("clean HTTPS flow should be normal, got %s (%.2f)", schema.ClassName(idx), p)
	}
	if p < 0.8 {
		t.Fatalf("normal confidence too low: %.2f", p)
	}
}

// TestHeuristicNeverEmitsWebAttack pins the #134/#135 decision: the removed
// byte-asymmetry rule fired on ordinary uploads, and no flow-features-v1
// threshold separates an upload from an injection payload, so the heuristic
// produces no web_attack at all. The exact flow that was inspected on hardware
// (113368 bytes out, 6478 back, port 443 — a file upload) must read as normal.
func TestHeuristicNeverEmitsWebAttack(t *testing.T) {
	h := NewHeuristic("", "")
	start := time.Unix(0, 0)
	r := flow.Record{
		ID: 9, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("192.168.1.50"), InitiatorPort: 51000,
		ResponderIP: netip.MustParseAddr("93.184.216.34"), ResponderPort: 443,
		FirstSeen: start, LastSeen: start.Add(2 * time.Second),
		FwdPackets: 90, BwdPackets: 40, FwdBytes: 113368, BwdBytes: 6478,
		SynCount: 2, AckCount: 128, FinCount: 2, PshCount: 40,
		PktSizeMin: 52, PktSizeMax: 1460,
	}
	idx, _ := h.Classify(vec(r)).Top()
	if got := schema.ClassName(idx); got == "web_attack" {
		t.Fatalf("a large upload to :443 was classified web_attack — the removed rule is back")
	}

	if got := h.UnsupportedClasses(); len(got) != 1 || got[0] != "web_attack" {
		t.Fatalf("UnsupportedClasses() = %v, want [web_attack]", got)
	}
	// The accessor must hand back a copy, not the package slice.
	h.UnsupportedClasses()[0] = "mutated"
	if HeuristicUnsupportedClasses[0] != "web_attack" {
		t.Fatal("UnsupportedClasses() exposed the shared slice")
	}
}

func TestRuntimeRecordsPerModelAndDisagreement(t *testing.T) {
	primary := NewHeuristic("primary", RolePrimary)
	// A second alert-driving model that always says "normal", to force a
	// disagreement on a scan. (Role-specific disagreement rules — experimental
	// and anomaly excluded — are covered in inference_test.go.)
	shadow := constModel{id: "always-normal", role: RoleGlobal, class: 0}
	rt := NewRuntime(primary, shadow)

	r := flow.Record{
		ID: 3, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("10.0.0.66"), InitiatorPort: 40002,
		ResponderIP: netip.MustParseAddr("10.0.0.1"), ResponderPort: 3389,
		FwdPackets: 1, FwdBytes: 60, SynCount: 1, PktSizeMin: 60, PktSizeMax: 60,
	}
	res := rt.Score(vec(r))
	if res.Class != "scan" {
		t.Fatalf("primary verdict should win: %s", res.Class)
	}
	if len(res.Models) != 2 {
		t.Fatalf("want 2 per-model outputs, got %d", len(res.Models))
	}
	if !res.Disagreement {
		t.Fatalf("scan vs normal must be flagged as disagreement")
	}
}

type constModel struct {
	id    string
	role  Role
	class int
}

func (c constModel) ID() string     { return c.id }
func (c constModel) Family() string { return "flow-classifier-v1" }
func (c constModel) Role() Role     { return c.role }
func (c constModel) Classify(features.Vector) Scores {
	var s Scores
	s[c.class] = 1
	return s
}
