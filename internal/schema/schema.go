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
	reconstructionV1JSON = schemas.ReconstructionV1
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
	reconstructionV1 OutputSchema
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

	if err := json.Unmarshal(reconstructionV1JSON, &reconstructionV1); err != nil {
		panic(fmt.Sprintf("schema: reconstruction-v1.json: %v", err))
	}
	if got := len(reconstructionV1.Classes); got != reconstructionV1.OutputSize {
		panic(fmt.Sprintf("schema: reconstruction-v1 has %d classes but output_size=%d", got, reconstructionV1.OutputSize))
	}
	// reconstruction-v1 mirrors flow-features-v1 slot for slot: the autoencoder
	// reconstructs the feature vector, so its output ordering is locked to the
	// feature ordering it targets (ADR 0037).
	if reconstructionV1.OutputSize != flowFeaturesV1.InputSize {
		panic(fmt.Sprintf("schema: reconstruction-v1 output_size=%d != flow-features-v1 input_size=%d",
			reconstructionV1.OutputSize, flowFeaturesV1.InputSize))
	}
	for i, c := range reconstructionV1.Classes {
		if c.Index != i {
			panic(fmt.Sprintf("schema: reconstruction-v1 slot %q has index %d, expected %d", c.Name, c.Index, i))
		}
		if c.Name != flowFeaturesV1.Features[i].Name {
			panic(fmt.Sprintf("schema: reconstruction-v1 slot %d is %q, must mirror flow-features-v1 feature %q",
				i, c.Name, flowFeaturesV1.Features[i].Name))
		}
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

// ReconstructionV1 returns the frozen reconstruction-v1 output schema (the
// flow-anomaly-v1 autoencoder family's output contract, ADR 0037).
func ReconstructionV1() OutputSchema { return reconstructionV1 }

// ReconstructionV1JSON returns the raw embedded reconstruction-v1 document.
func ReconstructionV1JSON() []byte { return reconstructionV1JSON }

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
	// SeqLen is the history length T of a temporal family (flow-sequence-v1); it
	// is 0 / absent for a single-vector family. Additive and optional.
	SeqLen int `json:"seq_len,omitempty"`
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
	// SeqLen is the history length T for a temporal family (flow-sequence-v1):
	// the first Dense sees SeqLen*InputSize values (the [T, 48] window is
	// flattened). 0 / absent for a single-vector family.
	SeqLen int `json:"seq_len,omitempty"`
}

// IsZero reports whether the architecture block was absent from metadata.json.
func (a Architecture) IsZero() bool {
	return a.InputSize == 0 && a.OutputSize == 0 && len(a.Hidden) == 0
}

// effectiveInputSize is the width the first Dense layer sees: InputSize for a
// single-vector model, SeqLen*InputSize for a temporal model whose [T, 48]
// window is flattened before the stack.
func (a Architecture) effectiveInputSize() int {
	if a.SeqLen > 1 {
		return a.InputSize * a.SeqLen
	}
	return a.InputSize
}

// Model family identifiers. Each family locks its own feature/output edge
// contract; ValidateBundle and ValidateArchitectureForFamily switch on it. A new
// need is a new family, never an edit to a released one (PROJECT.md §10, §28.5-6,
// ADR 0037).
const (
	// FamilyClassifierV1 is the supervised traffic classifier: flow-features-v1
	// in, traffic-classes-v1 (7 classes) out.
	FamilyClassifierV1 = "flow-classifier-v1"
	// FamilyAnomalyV1 is the autoencoder novelty detector: flow-features-v1 in,
	// reconstruction-v1 (48 slots) out; the per-flow reconstruction error is the
	// anomaly score (PROJECT.md §13).
	FamilyAnomalyV1 = "flow-anomaly-v1"
	// FamilySequenceV1 is the temporal classifier: the last SequenceLenV1
	// flow-features-v1 vectors of one conversation (a [T, 48] window, oldest
	// first, left-padded) in, traffic-classes-v1 (7) out — a supervised peer
	// with memory (PROJECT.md §30, issue #62, ADR 0040).
	FamilySequenceV1 = "flow-sequence-v1"
)

// SequenceLenV1 is the frozen history length T of the flow-sequence-v1 family. A
// different T is a flow-sequence-v2, not an edit.
const SequenceLenV1 = 16

// familyEdges is a model family's locked edge contract: the feature schema and
// per-step input width it consumes, the output schema and width it produces, and
// — for a temporal family — the frozen sequence length (0 for a single-vector
// family).
type familyEdges struct {
	featureSchema string
	inputSize     int
	outputSchema  string
	outputSize    int
	seqLen        int
}

// familyEdgesFor returns the locked edge contract for a known model family.
func familyEdgesFor(family string) (familyEdges, bool) {
	switch family {
	case FamilyClassifierV1:
		return familyEdges{
			featureSchema: flowFeaturesV1.Schema, inputSize: flowFeaturesV1.InputSize,
			outputSchema: trafficClassesV1.Schema, outputSize: trafficClassesV1.OutputSize,
		}, true
	case FamilyAnomalyV1:
		return familyEdges{
			featureSchema: flowFeaturesV1.Schema, inputSize: flowFeaturesV1.InputSize,
			outputSchema: reconstructionV1.Schema, outputSize: reconstructionV1.OutputSize,
		}, true
	case FamilySequenceV1:
		return familyEdges{
			featureSchema: flowFeaturesV1.Schema, inputSize: flowFeaturesV1.InputSize,
			outputSchema: trafficClassesV1.Schema, outputSize: trafficClassesV1.OutputSize,
			seqLen: SequenceLenV1,
		}, true
	default:
		return familyEdges{}, false
	}
}

// KnownFamily reports whether family is a model family this build can run.
func KnownFamily(family string) bool {
	_, ok := familyEdgesFor(family)
	return ok
}

// ValidateArchitecture is ValidateArchitectureForFamily for the supervised
// flow-classifier-v1 family — the original signature, kept for callers that only
// ever build that family.
func ValidateArchitecture(a Architecture) error {
	return ValidateArchitectureForFamily(FamilyClassifierV1, a)
}

// ValidateArchitectureForFamily reports whether an architecture is buildable for
// the given model family: its input and output layers must match that family's
// locked edge contract (the edge layers are not the trainer's to choose —
// PROJECT.md §10, §28.6), and every editable hidden layer must have a positive
// width, a supported activation, an in-range dropout and — if residual — a
// matching previous width. The hidden-stack rules mirror the trainer's
// architecture.py.
func ValidateArchitectureForFamily(family string, a Architecture) error {
	edges, ok := familyEdgesFor(family)
	if !ok {
		if family == "" {
			return fmt.Errorf("architecture: model family is empty")
		}
		return fmt.Errorf("architecture: model family %q is not supported by this build", family)
	}
	if a.InputSize != edges.inputSize {
		return fmt.Errorf("architecture.input_size %d != %s input_size %d", a.InputSize, edges.featureSchema, edges.inputSize)
	}
	if a.OutputSize != edges.outputSize {
		return fmt.Errorf("architecture.output_size %d != %s output_size %d", a.OutputSize, edges.outputSchema, edges.outputSize)
	}
	if a.SeqLen != edges.seqLen {
		return fmt.Errorf("architecture.seq_len %d != %s seq_len %d", a.SeqLen, family, edges.seqLen)
	}
	return validateHiddenStack(a)
}

// ValidateBundle reports whether a model bundle's family and feature/output
// contract match what this build of the daemon can feed and interpret. An
// incompatible model is rejected before inference, never silently run
// (PROJECT.md §9, §28.6).
func ValidateBundle(m BundleMeta) error {
	edges, ok := familyEdgesFor(m.Family)
	if !ok {
		if m.Family == "" {
			return fmt.Errorf("model family is empty")
		}
		return fmt.Errorf("model family %q is not supported (daemon runs %q, %q and %q)", m.Family, FamilyClassifierV1, FamilyAnomalyV1, FamilySequenceV1)
	}
	if m.FeatureSchema != edges.featureSchema {
		return fmt.Errorf("feature schema %q is not supported (daemon speaks %q)", m.FeatureSchema, edges.featureSchema)
	}
	if m.InputSize != edges.inputSize {
		return fmt.Errorf("model input_size %d != %s input_size %d", m.InputSize, edges.featureSchema, edges.inputSize)
	}
	if m.OutputSchema != edges.outputSchema {
		return fmt.Errorf("output schema %q is not supported for family %q (daemon speaks %q)", m.OutputSchema, m.Family, edges.outputSchema)
	}
	if m.OutputSize != edges.outputSize {
		return fmt.Errorf("model output_size %d != %s output_size %d", m.OutputSize, edges.outputSchema, edges.outputSize)
	}
	if m.SeqLen != edges.seqLen {
		return fmt.Errorf("model seq_len %d != %s seq_len %d", m.SeqLen, m.Family, edges.seqLen)
	}
	return nil
}
