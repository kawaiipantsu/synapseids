// Package schema holds the frozen, versioned data contracts: the flow-features-v1
// feature vector, the traffic-classes-v1 output vector, and the event envelope.
//
// The JSON documents under //schemas are embedded so the daemon and the CLI ship
// a single self-describing binary. Once a schema is released its field order and
// meaning never change — a new contract gets a new version (PROJECT.md §8, §9, §28.5).
package schema

import (
	"encoding/json"
	"fmt"

	"github.com/kawaiipantsu/synapseids/schemas"
)

var (
	flowFeaturesV1JSON   = schemas.FlowFeaturesV1
	trafficClassesV1JSON = schemas.TrafficClassesV1
	eventEnvelopeV1JSON  = schemas.EventEnvelopeV1
)

// Feature describes one entry of a feature schema.
type Feature struct {
	Index   int    `json:"index"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Unit    string `json:"unit"`
	Calc    string `json:"calc"`
	Missing string `json:"missing"`
	Norm    string `json:"norm"`
}

// FeatureSchema is a frozen ordered feature contract.
type FeatureSchema struct {
	Schema         string    `json:"schema"`
	Version        int       `json:"version"`
	Frozen         bool      `json:"frozen"`
	Description    string    `json:"description"`
	InputSize      int       `json:"input_size"`
	DefaultMissing float64   `json:"default_missing"`
	Features       []Feature `json:"features"`
}

// Class describes one entry of an output schema.
type Class struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// OutputSchema is a frozen classification output contract.
type OutputSchema struct {
	Schema      string  `json:"schema"`
	Version     int     `json:"version"`
	Frozen      bool    `json:"frozen"`
	Description string  `json:"description"`
	OutputSize  int     `json:"output_size"`
	Classes     []Class `json:"classes"`
}

var (
	flowFeaturesV1   FeatureSchema
	trafficClassesV1 OutputSchema
)

func init() {
	if err := json.Unmarshal(flowFeaturesV1JSON, &flowFeaturesV1); err != nil {
		panic(fmt.Sprintf("schema: flow-features-v1.json: %v", err))
	}
	if err := json.Unmarshal(trafficClassesV1JSON, &trafficClassesV1); err != nil {
		panic(fmt.Sprintf("schema: traffic-classes-v1.json: %v", err))
	}
	if got := len(flowFeaturesV1.Features); got != flowFeaturesV1.InputSize {
		panic(fmt.Sprintf("schema: flow-features-v1 has %d features but input_size=%d", got, flowFeaturesV1.InputSize))
	}
	for i, f := range flowFeaturesV1.Features {
		if f.Index != i {
			panic(fmt.Sprintf("schema: flow-features-v1 feature %q has index %d, expected %d", f.Name, f.Index, i))
		}
	}
	if got := len(trafficClassesV1.Classes); got != trafficClassesV1.OutputSize {
		panic(fmt.Sprintf("schema: traffic-classes-v1 has %d classes but output_size=%d", got, trafficClassesV1.OutputSize))
	}
}

// FlowFeaturesV1 returns the frozen flow-features-v1 schema.
func FlowFeaturesV1() FeatureSchema { return flowFeaturesV1 }

// TrafficClassesV1 returns the frozen traffic-classes-v1 schema.
func TrafficClassesV1() OutputSchema { return trafficClassesV1 }

// FlowFeaturesV1JSON returns the raw embedded flow-features-v1 document.
func FlowFeaturesV1JSON() []byte { return flowFeaturesV1JSON }

// TrafficClassesV1JSON returns the raw embedded traffic-classes-v1 document.
func TrafficClassesV1JSON() []byte { return trafficClassesV1JSON }

// EventEnvelopeV1JSON returns the raw embedded event-envelope-v1 document.
func EventEnvelopeV1JSON() []byte { return eventEnvelopeV1JSON }

// ClassName returns the traffic-classes-v1 class name for an index, or "" if out of range.
func ClassName(i int) string {
	if i < 0 || i >= len(trafficClassesV1.Classes) {
		return ""
	}
	return trafficClassesV1.Classes[i].Name
}

// FeatureName returns the flow-features-v1 feature name for an index, or "" if out of range.
func FeatureName(i int) string {
	if i < 0 || i >= len(flowFeaturesV1.Features) {
		return ""
	}
	return flowFeaturesV1.Features[i].Name
}

// BundleMeta is the subset of a model bundle's metadata.json that the daemon
// checks before it will run a model (PROJECT.md §11, §28.6).
type BundleMeta struct {
	Family        string `json:"family"`
	FeatureSchema string `json:"feature_schema"`
	InputSize     int    `json:"input_size"`
	OutputSchema  string `json:"output_schema"`
	OutputSize    int    `json:"output_size"`
}

// HiddenLayer is one configurable hidden layer of a model's architecture
// (PROJECT.md §10). Only the hidden layers are editable; the input and output
// layers are locked to the family's feature and output schemas.
type HiddenLayer struct {
	Width      int     `json:"width"`
	Activation string  `json:"activation"`
	Dropout    float64 `json:"dropout"`
	BatchNorm  bool    `json:"batchnorm"`
	Residual   bool    `json:"residual"`
}

// Architecture is a model's declared layer shape from metadata.json. InputSize
// and OutputSize restate the locked family contract; Hidden is the configurable
// middle (PROJECT.md §10, §11).
type Architecture struct {
	InputSize  int           `json:"input_size"`
	OutputSize int           `json:"output_size"`
	Hidden     []HiddenLayer `json:"hidden"`
}

// IsZero reports whether the architecture block was absent from metadata.json.
func (a Architecture) IsZero() bool {
	return a.InputSize == 0 && a.OutputSize == 0 && len(a.Hidden) == 0
}

// ValidateArchitecture reports whether a model's declared input and output
// layers still match this build's frozen feature and output schemas. The hidden
// layers are the trainer's to choose; the edge layers are not (PROJECT.md §10,
// §28.6).
func ValidateArchitecture(a Architecture) error {
	if a.InputSize != flowFeaturesV1.InputSize {
		return fmt.Errorf("architecture.input_size %d != %s input_size %d", a.InputSize, flowFeaturesV1.Schema, flowFeaturesV1.InputSize)
	}
	if a.OutputSize != trafficClassesV1.OutputSize {
		return fmt.Errorf("architecture.output_size %d != %s output_size %d", a.OutputSize, trafficClassesV1.Schema, trafficClassesV1.OutputSize)
	}
	return nil
}

// ValidateBundle reports whether a model bundle's feature/output contract matches
// what this build of the daemon can feed and interpret. An incompatible model is
// rejected before inference, never silently run (PROJECT.md §9, §28.6).
func ValidateBundle(m BundleMeta) error {
	if m.FeatureSchema != flowFeaturesV1.Schema {
		return fmt.Errorf("feature schema %q is not supported (daemon speaks %q)", m.FeatureSchema, flowFeaturesV1.Schema)
	}
	if m.InputSize != flowFeaturesV1.InputSize {
		return fmt.Errorf("model input_size %d != %s input_size %d", m.InputSize, flowFeaturesV1.Schema, flowFeaturesV1.InputSize)
	}
	if m.OutputSchema != trafficClassesV1.Schema {
		return fmt.Errorf("output schema %q is not supported (daemon speaks %q)", m.OutputSchema, trafficClassesV1.Schema)
	}
	if m.OutputSize != trafficClassesV1.OutputSize {
		return fmt.Errorf("model output_size %d != %s output_size %d", m.OutputSize, trafficClassesV1.Schema, trafficClassesV1.OutputSize)
	}
	return nil
}
