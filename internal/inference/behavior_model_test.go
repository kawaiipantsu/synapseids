package inference

import (
	"bytes"
	"math"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

func behaviorFixture(t *testing.T, family string, n, want int) *BehaviorModel {
	t.Helper()
	w := make([][]float32, n)
	b := make([]float32, n)
	for i := range w {
		w[i] = make([]float32, 160)
	}
	w[want][113] = 2
	g := onnxbuild.MLP(160, []onnxbuild.Layer{{W: w, B: b}}, true)
	net, e := nn.Load(bytes.NewReader(g.Encode()))
	if e != nil {
		t.Fatal(e)
	}
	m, e := NewBehaviorModel("context-test", family, net, nil)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestBehaviorInputTraceAndCoarseProjection(t *testing.T) {
	m := behaviorFixture(t, schema.FamilyBehaviorV1, 19, 14)
	v := features.BehaviorVector{}
	v.Values[113] = 10
	sc, d := m.ClassifyBehavior(v)
	if !d.Available || d.Class != "dga_dns" {
		t.Fatal(d)
	}
	if idx, _ := sc.Top(); idx != 6 {
		t.Fatal("DGA must project to suspicious")
	}
	tr, e := m.TraceBehavior(v)
	if e != nil {
		t.Fatal(e)
	}
	for i, x := range tr.Output {
		if math.Abs(float64(x)-d.Scores[i]) > 1e-6 {
			t.Fatal("trace did not reproduce score")
		}
	}
}
func TestApplicationAndShadowNeverDriveThreatVerdict(t *testing.T) {
	rt := NewRuntime(NewHeuristic("rules", RolePrimary))
	v := features.Vector{}
	v.Values[1] = 10
	v.Values[2] = 10
	v.Values[24] = 1
	b := features.BehaviorVector{}
	copy(b.Values[:48], v.Values[:])
	b.Values[113] = 10
	before := rt.Score(v)
	shadow := behaviorFixture(t, schema.FamilyBehaviorV1, 19, 14)
	rt.ActivateShadow(shadow)
	app := behaviorFixture(t, schema.FamilyApplicationV1, 14, 7)
	rt.ActivateRole(RoleApplication, app)
	got := rt.ScoreContext(v, nil, b)
	if got.Class != before.Class || got.Disagreement != before.Disagreement || got.Application == nil || got.Application.Class != "irc" {
		t.Fatal(got)
	}
	if len(got.Models) != 2 || got.Models[1].Role != RoleExperimental {
		t.Fatal("shadow missing")
	}
	rt.DeactivateShadow(shadow.ID())
	if len(rt.Models()) != 1 || rt.ApplicationModel() == nil {
		t.Fatal("shadow removal affected other roles")
	}
}
func TestPatternSignalsNeedEvidence(t *testing.T) {
	var b features.BehaviorVector
	b.Values[132] = 4
	b.Values[135] = 20
	if len(BehaviorSignals(b)) != 0 {
		t.Fatal("entropy alone is not a DGA signal")
	}
	b.Values[127] = 1
	b.Values[153] = 20
	b.Values[154] = 15
	b.Values[145] = 15
	b.Values[148] = 1
	sig := BehaviorSignals(b)
	if len(sig) != 2 || sig[0].Kind != "port_scan" || sig[1].Kind != "dga_dns" {
		t.Fatal(sig)
	}
}
