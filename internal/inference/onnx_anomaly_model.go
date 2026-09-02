package inference

import (
	"fmt"
	"math"
	"sort"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// anomalyTopK is how many per-feature reconstruction gaps ScoreAnomaly returns,
// largest absolute delta first — enough for a Flow Inspector "what looked wrong"
// panel without carrying all 48.
const anomalyTopK = 8

// ONNXAnomalyModel adapts a 48->48 autoencoder network loaded by internal/nn to
// the AnomalyScorer interface. The reconstruction error is measured in the
// model's normalized input space, so a fitted normalizer is required; the
// per-flow error is squashed into a bounded 0..1 score and compared against the
// bundle's calibrated threshold (ADR 0037).
type ONNXAnomalyModel struct {
	id        string
	net       *nn.Model
	norm      Normalizer
	p50       float64 // reconstruction-error median over the training NORMAL set; squash denominator
	threshold float64 // raw-error alert threshold; 0 means the bundle carried no calibration
}

// NewONNXAnomalyModel wraps net as an anomaly scorer. norm must map a raw
// flow-features-v1 vector into the model's input space (the error is meaningless
// across a raw/normalized mix). p50 and threshold come from the bundle's
// metadata.json "anomaly" block; both may be zero, in which case the score falls
// back to err/(err+1) and never flags Exceeds.
func NewONNXAnomalyModel(id string, net *nn.Model, norm Normalizer, p50, threshold float64) (*ONNXAnomalyModel, error) {
	if net == nil {
		return nil, fmt.Errorf("inference: nil anomaly model")
	}
	if net.InputSize() != features.Size {
		return nil, fmt.Errorf("inference: anomaly model input size %d != flow-features-v1 size %d", net.InputSize(), features.Size)
	}
	if net.OutputSize() != features.Size {
		return nil, fmt.Errorf("inference: anomaly model output size %d != reconstruction-v1 size %d", net.OutputSize(), features.Size)
	}
	if id == "" {
		id = "onnx-anomaly-model"
	}
	if p50 < 0 || math.IsNaN(p50) || math.IsInf(p50, 0) {
		p50 = 0
	}
	if threshold < 0 || math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		threshold = 0
	}
	return &ONNXAnomalyModel{id: id, net: net, norm: norm, p50: p50, threshold: threshold}, nil
}

// ID returns the instance name.
func (o *ONNXAnomalyModel) ID() string { return o.id }

// Family returns the locked contract this model belongs to.
func (o *ONNXAnomalyModel) Family() string { return schema.FamilyAnomalyV1 }

// Role is always RoleAnomaly.
func (o *ONNXAnomalyModel) Role() Role { return RoleAnomaly }

// ScoreAnomaly normalizes v, reconstructs it, and reports the mean squared
// reconstruction error, a bounded score, whether it exceeds the calibrated
// threshold, and the largest per-feature gaps. If the network fails to run it
// abstains (Available:false) rather than fabricate a novelty signal (§16).
func (o *ONNXAnomalyModel) ScoreAnomaly(v features.Vector) AnomalyOutput {
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
	if err != nil || len(out) != features.Size {
		return AnomalyOutput{ModelID: o.id, Available: false}
	}

	deltas := make([]FeatureDelta, features.Size)
	var sse float64
	for i := 0; i < features.Size; i++ {
		got := float64(out[i])
		if math.IsNaN(got) || math.IsInf(got, 0) {
			got = in[i] // a degenerate output contributes no error rather than NaN
		}
		d := got - in[i]
		sse += d * d
		deltas[i] = FeatureDelta{
			Index: i, Name: schema.FeatureName(i),
			Input: in[i], Output: got, Delta: d,
		}
	}
	recon := sse / float64(features.Size)

	sort.SliceStable(deltas, func(a, b int) bool {
		return math.Abs(deltas[a].Delta) > math.Abs(deltas[b].Delta)
	})
	if len(deltas) > anomalyTopK {
		deltas = deltas[:anomalyTopK]
	}

	den := o.p50
	if den <= 0 {
		den = 1
	}
	score := recon / (recon + den)
	exceeds := o.threshold > 0 && recon >= o.threshold

	return AnomalyOutput{
		ModelID:    o.id,
		Available:  true,
		ReconError: recon,
		Score:      score,
		Threshold:  o.threshold,
		Exceeds:    exceeds,
		TopDeltas:  deltas,
	}
}
