package schema

import "testing"

func TestSchemasLoadAndAreConsistent(t *testing.T) {
	fs := FlowFeaturesV1()
	if fs.Schema != "flow-features-v1" || fs.InputSize != 48 || len(fs.Features) != 48 {
		t.Fatalf("flow-features-v1 shape wrong: %+v", fs.Schema)
	}
	if !fs.Frozen {
		t.Fatalf("flow-features-v1 must be marked frozen")
	}
	os := TrafficClassesV1()
	if os.OutputSize != 7 || len(os.Classes) != 7 {
		t.Fatalf("traffic-classes-v1 size wrong")
	}
	if ClassName(0) != "normal" || ClassName(1) != "scan" || ClassName(6) != "suspicious" {
		t.Fatalf("class ordering changed: %q %q %q", ClassName(0), ClassName(1), ClassName(6))
	}
	if FeatureName(0) != "flow_duration" || FeatureName(47) != "snapshot_index" {
		t.Fatalf("feature ordering changed")
	}
}

func TestValidateBundle(t *testing.T) {
	ok := BundleMeta{
		Family: "flow-classifier-v1", FeatureSchema: "flow-features-v1",
		InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7,
	}
	if err := ValidateBundle(ok); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	for _, bad := range []BundleMeta{
		{Family: "flow-classifier-v1", FeatureSchema: "flow-features-v2", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7},
		{Family: "flow-classifier-v1", FeatureSchema: "flow-features-v1", InputSize: 56, OutputSchema: "traffic-classes-v1", OutputSize: 7},
		{Family: "flow-classifier-v1", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 9},
		{Family: "", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7},
		{Family: "flow-classifier-v9", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7},
		// the anomaly family must not accept the classifier's output contract
		{Family: "flow-anomaly-v1", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7},
		// nor the classifier family the anomaly output contract
		{Family: "flow-classifier-v1", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "reconstruction-v1", OutputSize: 48},
	} {
		if err := ValidateBundle(bad); err == nil {
			t.Errorf("incompatible bundle accepted: %+v", bad)
		}
	}
}

func TestReconstructionV1MirrorsFeatures(t *testing.T) {
	rc := ReconstructionV1()
	fs := FlowFeaturesV1()
	if rc.Schema != "reconstruction-v1" || rc.OutputSize != 48 || len(rc.Classes) != 48 {
		t.Fatalf("reconstruction-v1 shape wrong: %+v", rc.Schema)
	}
	if !rc.Frozen {
		t.Fatalf("reconstruction-v1 must be marked frozen")
	}
	for i, c := range rc.Classes {
		if c.Index != i || c.Name != fs.Features[i].Name {
			t.Fatalf("reconstruction-v1 slot %d = (%d,%q), want (%d,%q)", i, c.Index, c.Name, i, fs.Features[i].Name)
		}
	}
}

func TestValidateBundleAnomalyFamily(t *testing.T) {
	ok := BundleMeta{
		Family: "flow-anomaly-v1", FeatureSchema: "flow-features-v1",
		InputSize: 48, OutputSchema: "reconstruction-v1", OutputSize: 48,
	}
	if err := ValidateBundle(ok); err != nil {
		t.Fatalf("valid anomaly bundle rejected: %v", err)
	}
	if !KnownFamily("flow-anomaly-v1") || !KnownFamily("flow-classifier-v1") || KnownFamily("nope") {
		t.Fatalf("KnownFamily wrong")
	}
}

func TestValidateBundleSequenceFamily(t *testing.T) {
	ok := BundleMeta{
		Family: "flow-sequence-v1", FeatureSchema: "flow-features-v1",
		InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7,
		SeqLen: SequenceLenV1,
	}
	if err := ValidateBundle(ok); err != nil {
		t.Fatalf("valid sequence bundle rejected: %v", err)
	}
	if !KnownFamily("flow-sequence-v1") {
		t.Fatal("flow-sequence-v1 not a known family")
	}
	for _, bad := range []BundleMeta{
		// missing seq_len
		{Family: "flow-sequence-v1", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7},
		// wrong seq_len
		{Family: "flow-sequence-v1", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7, SeqLen: 8},
		// a classifier bundle must not carry a seq_len
		{Family: "flow-classifier-v1", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7, SeqLen: SequenceLenV1},
		// the sequence family still uses the classifier output contract
		{Family: "flow-sequence-v1", FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "reconstruction-v1", OutputSize: 48, SeqLen: SequenceLenV1},
	} {
		if err := ValidateBundle(bad); err == nil {
			t.Errorf("incompatible sequence bundle accepted: %+v", bad)
		}
	}
}

func TestValidateArchitectureForFamily(t *testing.T) {
	ae := Architecture{
		InputSize: 48, OutputSize: 48,
		Hidden: []HiddenLayer{
			{Width: 16, Activation: "relu"}, {Width: 8, Activation: "relu"}, {Width: 16, Activation: "relu"},
		},
	}
	if err := ValidateArchitectureForFamily("flow-anomaly-v1", ae); err != nil {
		t.Fatalf("valid autoencoder architecture rejected: %v", err)
	}
	// classifier family rejects a 48-wide output; anomaly family rejects 7 and 47.
	if err := ValidateArchitectureForFamily("flow-classifier-v1", ae); err == nil {
		t.Errorf("classifier family accepted output_size 48")
	}
	for _, out := range []int{7, 47} {
		bad := ae
		bad.OutputSize = out
		if err := ValidateArchitectureForFamily("flow-anomaly-v1", bad); err == nil {
			t.Errorf("anomaly family accepted output_size %d", out)
		}
	}
	if err := ValidateArchitectureForFamily("", ae); err == nil {
		t.Errorf("empty family accepted")
	}

	// flow-sequence-v1: input 48, output 7, seq_len 16; the first Dense sees
	// 16*48 = 768 (effectiveInputSize).
	seq := Architecture{
		InputSize: 48, OutputSize: 7, SeqLen: SequenceLenV1,
		Hidden: []HiddenLayer{{Width: 16, Activation: "relu"}},
	}
	if err := ValidateArchitectureForFamily("flow-sequence-v1", seq); err != nil {
		t.Fatalf("valid sequence architecture rejected: %v", err)
	}
	if got, want := seq.ParameterCount(), 16*768+16+7*16+7; got != want {
		t.Fatalf("sequence ParameterCount() = %d, want %d (768-wide first Dense)", got, want)
	}
	// wrong / missing seq_len is rejected; a classifier arch with seq_len is too.
	for _, bad := range []Architecture{
		{InputSize: 48, OutputSize: 7, SeqLen: 8, Hidden: []HiddenLayer{{Width: 16}}},
		{InputSize: 48, OutputSize: 7, Hidden: []HiddenLayer{{Width: 16}}},
	} {
		if err := ValidateArchitectureForFamily("flow-sequence-v1", bad); err == nil {
			t.Errorf("sequence family accepted bad seq_len: %+v", bad)
		}
	}
	if err := ValidateArchitectureForFamily("flow-classifier-v1", seq); err == nil {
		t.Errorf("classifier family accepted a seq_len")
	}
}

func TestValidateArchitecture(t *testing.T) {
	ok := Architecture{
		InputSize: 48, OutputSize: 7,
		Hidden: []HiddenLayer{{Width: 64, Activation: "relu", Dropout: 0.3, BatchNorm: true}},
	}
	if err := ValidateArchitecture(ok); err != nil {
		t.Fatalf("valid architecture rejected: %v", err)
	}
	if (Architecture{}).IsZero() != true {
		t.Fatalf("empty Architecture must report IsZero")
	}
	if ok.IsZero() {
		t.Fatalf("populated Architecture must not report IsZero")
	}
	for _, bad := range []Architecture{
		{InputSize: 47, OutputSize: 7},
		{InputSize: 48, OutputSize: 6},
		{InputSize: 0, OutputSize: 0},
	} {
		if err := ValidateArchitecture(bad); err == nil {
			t.Errorf("incompatible architecture accepted: %+v", bad)
		}
	}
}
