package inference

import (
	"fmt"
	"math"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/nn"
)

// Normalizer maps a raw flow-features-v1 vector into a model's input space. A
// trained model supplies one built from its bundle's normalizer.json; the
// heuristic path passes raw values, so a nil Normalizer means "feed raw".
type Normalizer func(features.Vector) [features.Size]float64

// ONNXModel adapts a network loaded by internal/nn to the Classifier interface,
// so trained models score flows alongside the heuristic in the same Runtime
// (PROJECT.md §10, §12). internal/nn stays free of inference/features; the
// feature/score mapping lives here.
type ONNXModel struct {
	id   string
	role Role
	net  *nn.Model
	norm Normalizer
}

// NewONNXModel wraps net. norm may be nil (raw features are fed). The model's
// input/output dimensions must match flow-features-v1 / traffic-classes-v1 —
// schema.ValidateBundle is the contract check at bundle-load time; this is the
// defensive re-check at wiring time.
func NewONNXModel(id string, role Role, net *nn.Model, norm Normalizer) (*ONNXModel, error) {
	if net == nil {
		return nil, fmt.Errorf("inference: nil model")
	}
	if net.InputSize() != features.Size {
		return nil, fmt.Errorf("inference: model input size %d != flow-features-v1 size %d", net.InputSize(), features.Size)
	}
	if net.OutputSize() != OutputSize {
		return nil, fmt.Errorf("inference: model output size %d != traffic-classes-v1 size %d", net.OutputSize(), OutputSize)
	}
	if id == "" {
		id = "onnx-model"
	}
	if role == "" {
		role = RolePrimary
	}
	return &ONNXModel{id: id, role: role, net: net, norm: norm}, nil
}

// ID returns the instance name.
func (o *ONNXModel) ID() string { return o.id }

// Family returns the locked contract this model belongs to.
func (o *ONNXModel) Family() string { return "flow-classifier-v1" }

// Role returns the model's ensemble role.
func (o *ONNXModel) Role() Role { return o.role }

// Classify maps the feature vector to the model's input, runs it, and returns the
// class distribution. The graph ends in Softmax, but the result is still clamped
// and renormalised so a numerically degenerate model can never emit a non-
// distribution. If inference fails outright the model abstains with an all-normal
// distribution rather than taking down the pipeline.
func (o *ONNXModel) Classify(v features.Vector) Scores {
	var in [features.Size]float64
	if o.norm != nil {
		in = o.norm(v)
	} else {
		in = v.Values
	}
	fin := make([]float32, features.Size)
	for i, x := range in {
		fin[i] = float32(x)
	}

	out, err := o.net.Run(fin)
	if err != nil || len(out) != OutputSize {
		return normalFallback()
	}

	var s Scores
	var sum float64
	for i := 0; i < OutputSize; i++ {
		p := float64(out[i])
		if math.IsNaN(p) || math.IsInf(p, 0) || p < 0 {
			p = 0
		}
		s[i] = p
		sum += p
	}
	if sum <= 0 {
		return normalFallback()
	}
	for i := range s {
		s[i] /= sum
	}
	return s
}

func normalFallback() Scores {
	var s Scores
	s[classNormal] = 1
	return s
}
