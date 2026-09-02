package inference

import (
	"fmt"
	"math"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// ONNXSequenceModel adapts a windowed-FFN network to the SequenceScorer
// interface: it flattens the last SeqLen feature vectors of a conversation
// (oldest first, left-padded with the frozen missing vector) into a SeqLen*48
// input and runs the graph to a traffic-classes-v1 distribution (ADR 0040).
//
// The graph itself is a plain [SeqLen*48] -> … -> [7] softmax MLP — a trained
// TCN / GRU model that keeps the time axis is a follow-up that adds Conv/GRU to
// internal/nn; the SequenceScorer contract does not change when it lands.
type ONNXSequenceModel struct {
	id     string
	role   Role
	seqLen int
	net    *nn.Model
	norm   Normalizer
}

// NewONNXSequenceModel wraps net. seqLen is the frozen family history length
// (schema.SequenceLenV1); norm may be nil (raw values fed). The graph's input
// must be seqLen*48 wide and its output traffic-classes-v1 wide.
func NewONNXSequenceModel(id string, role Role, seqLen int, net *nn.Model, norm Normalizer) (*ONNXSequenceModel, error) {
	if net == nil {
		return nil, fmt.Errorf("inference: nil sequence model")
	}
	if seqLen < 1 {
		return nil, fmt.Errorf("inference: sequence model seq_len %d must be >= 1", seqLen)
	}
	want := seqLen * features.Size
	if net.InputSize() != want {
		return nil, fmt.Errorf("inference: sequence model input size %d != seq_len*48 = %d", net.InputSize(), want)
	}
	if net.OutputSize() != OutputSize {
		return nil, fmt.Errorf("inference: sequence model output size %d != traffic-classes-v1 size %d", net.OutputSize(), OutputSize)
	}
	if id == "" {
		id = "onnx-sequence-model"
	}
	if role == "" {
		role = RoleSequence
	}
	return &ONNXSequenceModel{id: id, role: role, seqLen: seqLen, net: net, norm: norm}, nil
}

// ID returns the instance name.
func (o *ONNXSequenceModel) ID() string { return o.id }

// Family returns the locked contract this model belongs to.
func (o *ONNXSequenceModel) Family() string { return schema.FamilySequenceV1 }

// Role is always RoleSequence.
func (o *ONNXSequenceModel) Role() Role { return o.role }

// ScoreSequence flattens the window (oldest first) into seqLen*48 values,
// left-padding a short window with the zero (missing) vector, normalises each
// step, runs the net and returns the class distribution. On any failure it
// abstains with an all-normal distribution rather than break the pipeline.
func (o *ONNXSequenceModel) ScoreSequence(window [][features.Size]float64) Scores {
	fin := make([]float32, o.seqLen*features.Size)
	// The window's newest o.seqLen entries, right-aligned: the last row of the
	// window lands in the last slot, older rows before it, and any leading slots
	// stay zero (the missing vector).
	start := len(window) - o.seqLen
	for slot := 0; slot < o.seqLen; slot++ {
		wi := start + slot
		if wi < 0 {
			continue // left pad: zero
		}
		row := window[wi]
		if o.norm != nil {
			row = o.norm(features.Vector{Values: row})
		}
		for j := 0; j < features.Size; j++ {
			fin[slot*features.Size+j] = float32(row[j])
		}
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
