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
		{FeatureSchema: "flow-features-v2", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 7},
		{FeatureSchema: "flow-features-v1", InputSize: 56, OutputSchema: "traffic-classes-v1", OutputSize: 7},
		{FeatureSchema: "flow-features-v1", InputSize: 48, OutputSchema: "traffic-classes-v1", OutputSize: 9},
	} {
		if err := ValidateBundle(bad); err == nil {
			t.Errorf("incompatible bundle accepted: %+v", bad)
		}
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
