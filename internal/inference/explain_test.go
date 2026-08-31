package inference

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// ruleIDs lists the fired rules in order.
func ruleIDs(ex Explanation) []string {
	out := make([]string, 0, len(ex.Rules))
	for _, r := range ex.Rules {
		out = append(out, r.Rule)
	}
	return out
}

// hasRule reports whether id fired, returning it.
func hasRule(ex Explanation, id string) (FiredRule, bool) {
	for _, r := range ex.Rules {
		if r.Rule == id {
			return r, true
		}
	}
	return FiredRule{}, false
}

// ruleFeature fetches a named feature value a rule reported.
func ruleFeature(t *testing.T, r FiredRule, name string) float64 {
	t.Helper()
	for _, f := range r.Features {
		if f.Name == name {
			return f.Value
		}
	}
	t.Fatalf("rule %q did not report feature %q (reported %v)", r.Rule, name, r.Features)
	return 0
}

// TestExplainLoneSYNNamesTheScanRules covers the headline case: a single
// unanswered SYN must be explained by the scan rules, on the real values.
func TestExplainLoneSYNNamesTheScanRules(t *testing.T) {
	h := NewHeuristic("", "")
	r := flow.Record{
		ID: 1, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("10.0.0.66"), InitiatorPort: 40001,
		ResponderIP: netip.MustParseAddr("10.10.10.21"), ResponderPort: 22,
		FirstSeen: time.Unix(0, 0), LastSeen: time.Unix(0, 0),
		FwdPackets: 1, FwdBytes: 60, SynCount: 1,
		PktSizeMin: 60, PktSizeMax: 60,
	}
	v := vec(r)
	ex := h.Explain(v)

	if ex.Kind != ExplainRules {
		t.Fatalf("Kind = %q, want %q", ex.Kind, ExplainRules)
	}
	if len(ex.Rules) == 0 {
		t.Fatal("a lone unanswered SYN fired no rules")
	}

	// Both the "no reply" and the "short probe" shapes describe this flow.
	fr, ok := hasRule(ex, "scan.unanswered_syn")
	if !ok {
		t.Fatalf("scan.unanswered_syn did not fire; fired: %v", ruleIDs(ex))
	}
	if _, ok := hasRule(ex, "scan.short_probe"); !ok {
		t.Errorf("scan.short_probe did not fire; fired: %v", ruleIDs(ex))
	}
	if fr.Class != "scan" || fr.ClassID != classScan {
		t.Errorf("rule class = %q/%d, want scan/%d", fr.Class, fr.ClassID, classScan)
	}

	// The reported values must be the flow's actual feature values.
	if got := ruleFeature(t, fr, "tcp_syn_count"); got != 1 {
		t.Errorf("tcp_syn_count = %v, want 1", got)
	}
	if got := ruleFeature(t, fr, "packets_backward"); got != 0 {
		t.Errorf("packets_backward = %v, want 0", got)
	}
	if got := ruleFeature(t, fr, "tcp_ack_count"); got != 0 {
		t.Errorf("tcp_ack_count = %v, want 0", got)
	}

	// Units come from the frozen schema, so the panel needs no client-side join.
	for _, f := range fr.Features {
		if f.Unit == "" {
			t.Errorf("feature %q reported an empty unit", f.Name)
		}
	}

	// scan must be the heaviest class, and the weights must be the real
	// pre-softmax input rather than a re-derivation.
	if len(ex.ClassWeights) == 0 {
		t.Fatal("no class weights reported")
	}
	if ex.ClassWeights[0].Class != "scan" {
		t.Errorf("heaviest class = %q, want scan", ex.ClassWeights[0].Class)
	}
	// 5.0 + synCount(1) + rstCount(0)
	if got := ex.ClassWeights[0].Weight; got != 6.0 {
		t.Errorf("scan weight = %v, want 6", got)
	}
}

// TestExplainMySQLBruteForce trips the brute-force rule on a 3306 shape.
func TestExplainMySQLBruteForce(t *testing.T) {
	h := NewHeuristic("", "")
	start := time.Unix(0, 0)
	r := flow.Record{
		ID: 2, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("10.0.0.66"), InitiatorPort: 51000,
		ResponderIP: netip.MustParseAddr("10.10.10.21"), ResponderPort: 3306,
		FirstSeen: start, LastSeen: start.Add(900 * time.Millisecond),
		FwdPackets: 6, BwdPackets: 5, FwdBytes: 500, BwdBytes: 420,
		SynCount: 1, AckCount: 8, FinCount: 1,
		PktSizeMin: 54, PktSizeMax: 140,
	}
	v := vec(r)
	ex := h.Explain(v)

	fr, ok := hasRule(ex, "brute_force.auth_port_rounds")
	if !ok {
		t.Fatalf("brute_force.auth_port_rounds did not fire; fired: %v", ruleIDs(ex))
	}
	if fr.Class != "brute_force" {
		t.Errorf("rule class = %q, want brute_force", fr.Class)
	}
	if got := ruleFeature(t, fr, "destination_port"); got != 3306 {
		t.Errorf("destination_port = %v, want 3306", got)
	}
	if got := ruleFeature(t, fr, "packets_forward"); got != 6 {
		t.Errorf("packets_forward = %v, want 6", got)
	}
	if got := ruleFeature(t, fr, "packets_backward"); got != 5 {
		t.Errorf("packets_backward = %v, want 5", got)
	}
	if got := ruleFeature(t, fr, "tcp_fin_count"); got != 1 {
		t.Errorf("tcp_fin_count = %v, want 1", got)
	}

	// And the verdict the operator sees agrees with the explanation.
	idx, _ := h.Classify(v).Top()
	if schema.ClassName(idx) != "brute_force" {
		t.Errorf("verdict = %q, want brute_force", schema.ClassName(idx))
	}
}

// TestExplainNoRulesFiredIsStatedNotImplied is the anti-misleading test: a clean
// flow must report an *empty* rule list plus the prior that actually decided it.
func TestExplainNoRulesFiredIsStatedNotImplied(t *testing.T) {
	h := NewHeuristic("", "")
	start := time.Unix(0, 0)
	r := flow.Record{
		ID: 3, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("192.168.1.50"), InitiatorPort: 49712,
		ResponderIP: netip.MustParseAddr("93.184.216.34"), ResponderPort: 443,
		FirstSeen: start, LastSeen: start.Add(120 * time.Millisecond),
		FwdPackets: 6, BwdPackets: 5, FwdBytes: 900, BwdBytes: 6000,
		SynCount: 2, AckCount: 9, FinCount: 2, PshCount: 2,
		PktSizeMin: 52, PktSizeMax: 1420,
	}
	ex := h.Explain(vec(r))

	if len(ex.Rules) != 0 {
		t.Fatalf("a clean HTTPS flow fired rules: %v", ruleIDs(ex))
	}
	if ex.Kind != ExplainRules {
		t.Errorf("Kind = %q, want %q even with no rules", ex.Kind, ExplainRules)
	}
	if ex.NormalPrior != HeuristicNormalPrior {
		t.Errorf("NormalPrior = %v, want %v", ex.NormalPrior, HeuristicNormalPrior)
	}
	// The note must say the verdict is a prior, and must not imply a baseline check.
	if !strings.Contains(ex.Note, "prior") {
		t.Errorf("no-rules note does not explain the prior: %q", ex.Note)
	}
	if !strings.Contains(ex.Note, "not the same as") {
		t.Errorf("no-rules note does not disclaim a baseline check: %q", ex.Note)
	}
	// Only the normal prior should carry weight.
	if len(ex.ClassWeights) != 1 || ex.ClassWeights[0].Class != "normal" {
		t.Errorf("class weights = %+v, want only normal", ex.ClassWeights)
	}
}

// TestExplainMatchesClassify pins the property that makes the panel trustworthy:
// the explanation's weights soft-max to the very scores Classify returned.
func TestExplainMatchesClassify(t *testing.T) {
	h := NewHeuristic("", "")
	start := time.Unix(0, 0)
	cases := []struct {
		name string
		rec  flow.Record
	}{
		{"lone syn", flow.Record{
			ID: 1, Proto: packet.ProtoTCP,
			InitiatorIP: netip.MustParseAddr("10.0.0.1"), ResponderIP: netip.MustParseAddr("10.0.0.2"),
			ResponderPort: 22, FirstSeen: start, LastSeen: start,
			FwdPackets: 1, FwdBytes: 60, SynCount: 1, PktSizeMin: 60, PktSizeMax: 60,
		}},
		{"mysql brute", flow.Record{
			ID: 2, Proto: packet.ProtoTCP,
			InitiatorIP: netip.MustParseAddr("10.0.0.1"), ResponderIP: netip.MustParseAddr("10.0.0.2"),
			ResponderPort: 3306, FirstSeen: start, LastSeen: start.Add(900 * time.Millisecond),
			FwdPackets: 6, BwdPackets: 5, FwdBytes: 500, BwdBytes: 420,
			SynCount: 1, AckCount: 8, FinCount: 1, PktSizeMin: 54, PktSizeMax: 140,
		}},
		{"clean https", flow.Record{
			ID: 3, Proto: packet.ProtoTCP,
			InitiatorIP: netip.MustParseAddr("10.0.0.1"), ResponderIP: netip.MustParseAddr("10.0.0.2"),
			ResponderPort: 443, FirstSeen: start, LastSeen: start.Add(120 * time.Millisecond),
			FwdPackets: 6, BwdPackets: 5, FwdBytes: 900, BwdBytes: 6000,
			SynCount: 2, AckCount: 9, FinCount: 2, PktSizeMin: 52, PktSizeMax: 1420,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := vec(tc.rec)
			want := h.Classify(v)
			ex := h.Explain(v)

			// Rebuild the weight map from the explanation and soft-max it.
			w := map[int]float64{}
			for _, cw := range ex.ClassWeights {
				w[cw.ClassID] = cw.Weight
			}
			got := softmax(w)
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("class %d: explanation implies %.12f, Classify returned %.12f",
						i, got[i], want[i])
				}
			}
		})
	}
}

// TestExplainIsPure guards against the explanation path mutating the vector it
// is handed — the inspector reads a stored record.
func TestExplainIsPure(t *testing.T) {
	h := NewHeuristic("", "")
	r := flow.Record{
		ID: 1, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("10.0.0.1"), ResponderIP: netip.MustParseAddr("10.0.0.2"),
		ResponderPort: 22, FirstSeen: time.Unix(0, 0), LastSeen: time.Unix(0, 0),
		FwdPackets: 1, FwdBytes: 60, SynCount: 1, PktSizeMin: 60, PktSizeMax: 60,
	}
	v := vec(r)
	before := v.Values

	h.Explain(v)
	h.Explain(v)

	if v.Values != before {
		t.Error("Explain mutated the feature vector")
	}
	// Two calls must agree exactly.
	a, b := h.Explain(v), h.Explain(v)
	if len(a.Rules) != len(b.Rules) {
		t.Errorf("Explain is not deterministic: %v vs %v", ruleIDs(a), ruleIDs(b))
	}
}

// TestHeuristicImplementsExplainer keeps the api fallback honest: if this ever
// stops holding, the inspector silently drops to "unavailable".
func TestHeuristicImplementsExplainer(t *testing.T) {
	var c Classifier = NewHeuristic("", "")
	if _, ok := c.(Explainer); !ok {
		t.Fatal("*Heuristic no longer implements Explainer")
	}
}

// TestExplanationRulesMarshalAsListNotNull is a regression test: a nil Rules
// slice serialises as `null`, and a client that reasonably does
// `explanation.rules.length` then crashes on exactly the common case — a clean
// flow where nothing fired.
func TestExplanationRulesMarshalAsListNotNull(t *testing.T) {
	h := NewHeuristic("", "")
	start := time.Unix(0, 0)
	clean := flow.Record{
		ID: 1, Proto: packet.ProtoTCP,
		InitiatorIP: netip.MustParseAddr("10.0.0.1"), ResponderIP: netip.MustParseAddr("10.0.0.2"),
		ResponderPort: 443, FirstSeen: start, LastSeen: start.Add(120 * time.Millisecond),
		FwdPackets: 6, BwdPackets: 5, FwdBytes: 900, BwdBytes: 6000,
		SynCount: 2, AckCount: 9, FinCount: 2, PktSizeMin: 52, PktSizeMax: 1420,
	}

	for name, ex := range map[string]Explanation{
		"no rules fired": h.Explain(vec(clean)),
		"unavailable":    UnavailableExplanation("m", RolePrimary, "why"),
	} {
		blob, err := json.Marshal(ex)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if !strings.Contains(string(blob), `"rules":[]`) {
			t.Errorf("%s: rules did not marshal as []: %s", name, blob)
		}
		if strings.Contains(string(blob), `"rules":null`) {
			t.Errorf("%s: rules marshalled as null: %s", name, blob)
		}
	}
}

func TestUnavailableExplanationClaimsNothing(t *testing.T) {
	ex := UnavailableExplanation("some-model", RolePrimary, "because reasons")
	if ex.Kind != ExplainUnavailable {
		t.Errorf("Kind = %q, want %q", ex.Kind, ExplainUnavailable)
	}
	if len(ex.Rules) != 0 || len(ex.ClassWeights) != 0 {
		t.Error("an unavailable explanation must carry no rules and no weights")
	}
	if ex.Note != "because reasons" {
		t.Errorf("Note = %q", ex.Note)
	}
}

// TestONNXModelIsNotAnExplainer documents the deliberate gap: a trained model
// has no per-feature attribution in this build, and must not acquire a fake one
// by accident.
func TestONNXModelIsNotAnExplainer(t *testing.T) {
	var c Classifier = &ONNXModel{}
	if _, ok := c.(Explainer); ok {
		t.Fatal("*ONNXModel implements Explainer — attribution for trained models " +
			"needs gradients or SHAP; a proxy must not be presented as an explanation")
	}
}

func TestFeatureUnitKnownAndUnknown(t *testing.T) {
	if got := featureUnit("flow_duration"); got == "" {
		t.Error("flow_duration has no unit")
	}
	if got := featureUnit("no_such_feature"); got != "" {
		t.Errorf("unknown feature unit = %q, want empty", got)
	}
	// Every feature the schema freezes must resolve.
	for _, f := range schema.FlowFeaturesV1().Features {
		if featureUnit(f.Name) != f.Unit {
			t.Errorf("featureUnit(%q) = %q, want %q", f.Name, featureUnit(f.Name), f.Unit)
		}
	}
}

// TestExplainRuleFeaturesAreRealSchemaNames stops a typo in a rule's feature
// list from silently reporting 0 for a name that does not exist.
func TestExplainRuleFeaturesAreRealSchemaNames(t *testing.T) {
	known := map[string]bool{}
	for _, f := range schema.FlowFeaturesV1().Features {
		known[f.Name] = true
	}

	h := NewHeuristic("", "")
	start := time.Unix(0, 0)
	// A spread of shapes, to fire as many rules as possible across the set.
	recs := []flow.Record{
		{ID: 1, Proto: packet.ProtoTCP, ResponderPort: 22, FirstSeen: start, LastSeen: start,
			FwdPackets: 1, FwdBytes: 60, SynCount: 1, PktSizeMin: 60, PktSizeMax: 60},
		{ID: 2, Proto: packet.ProtoTCP, ResponderPort: 3306, FirstSeen: start,
			LastSeen: start.Add(900 * time.Millisecond), FwdPackets: 6, BwdPackets: 5,
			FwdBytes: 500, BwdBytes: 420, SynCount: 1, AckCount: 8, FinCount: 1,
			PktSizeMin: 54, PktSizeMax: 140},
		{ID: 3, Proto: packet.ProtoTCP, ResponderPort: 80, FirstSeen: start,
			LastSeen: start.Add(time.Second), FwdPackets: 8, BwdPackets: 2,
			FwdBytes: 9000, BwdBytes: 300, SynCount: 1, AckCount: 6, FinCount: 1,
			PktSizeMin: 60, PktSizeMax: 1500},
		{ID: 4, Proto: packet.ProtoUDP, ResponderPort: 53, FirstSeen: start,
			LastSeen: start.Add(50 * time.Millisecond), FwdPackets: 400, FwdBytes: 20000,
			PktSizeMin: 50, PktSizeMax: 50, SmallPkts: 400},
		{ID: 5, Proto: packet.ProtoTCP, ResponderPort: 4444, FirstSeen: start,
			LastSeen: start.Add(300 * time.Second), FwdPackets: 10, BwdPackets: 10,
			FwdBytes: 800, BwdBytes: 800, SynCount: 1, AckCount: 18, PshCount: 8,
			PktSizeMin: 60, PktSizeMax: 100},
	}

	fires := 0
	for _, r := range recs {
		ex := h.Explain(features.Extract(r))
		fires += len(ex.Rules)
		for _, rule := range ex.Rules {
			if len(rule.Features) == 0 {
				t.Errorf("rule %q reported no feature values", rule.Rule)
			}
			for _, f := range rule.Features {
				if !known[f.Name] {
					t.Errorf("rule %q reports unknown feature %q", rule.Rule, f.Name)
				}
			}
			if rule.Detail == "" {
				t.Errorf("rule %q has no human detail", rule.Rule)
			}
			if schema.ClassName(rule.ClassID) != rule.Class {
				t.Errorf("rule %q class %q does not match class_id %d",
					rule.Rule, rule.Class, rule.ClassID)
			}
		}
	}
	// Guard against the loop passing vacuously if the shapes stop firing.
	if fires < 4 {
		t.Fatalf("only %d rules fired across %d shapes — the fixtures no longer "+
			"exercise the rule set", fires, len(recs))
	}
}
