package schema

import "fmt"

// hiddenActivations is the activation set internal/nn can execute (Relu,
// LeakyRelu, Sigmoid, Tanh — see internal/nn/nn.go). The Architecture Builder
// offers exactly these; a hidden layer naming any other activation is rejected
// before it could reach the trainer (PROJECT.md §10, §19.9).
var hiddenActivations = map[string]bool{
	"relu":       true,
	"leaky_relu": true,
	"sigmoid":    true,
	"tanh":       true,
}

// LayerParams is one row of an architecture's parameter breakdown: a Dense
// layer's name, its input and output widths, and the trainable-parameter count
// that Dense contributes (its BatchNorm affine folded in when present). The rows
// returned by Architecture.LayerBreakdown sum to Architecture.ParameterCount.
type LayerParams struct {
	Name   string `json:"name"`
	In     int    `json:"in"`
	Out    int    `json:"out"`
	Params int    `json:"params"`
}

// ParameterCount is the trainable-parameter total of the locked-edge MLP this
// Architecture describes. It matches the trainer's architecture.py exactly: a
// Dense prev->w layer contributes w*prev + w (weight + bias), an affine
// BatchNorm1d(w) adds 2*w (gamma + beta; running stats are buffers, not
// parameters), and activation / dropout / residual add nothing. InputSize and
// OutputSize are used as given — callers that need the locked family edges
// should set them to the frozen 48 / 7 first (PROJECT.md §10).
func (a Architecture) ParameterCount() int {
	total := 0
	prev := a.effectiveInputSize()
	for _, h := range a.Hidden {
		total += prev*h.Width + h.Width
		if h.BatchNorm {
			total += 2 * h.Width
		}
		prev = h.Width
	}
	total += prev*a.OutputSize + a.OutputSize
	return total
}

// ApproxBytes is the raw fp32 parameter storage for this architecture: four
// bytes per trainable parameter. It mirrors architecture.py's
// estimated_size_bytes and is only a lower bound on a real bundle's on-disk size
// (ONNX graph overhead, metadata and the normalizer are extra).
func (a Architecture) ApproxBytes() int { return a.ParameterCount() * 4 }

// RoughFLOPs approximates the multiply-accumulate FLOPs of one batch-1 forward
// pass as 2*in*out per Dense layer — the dominant term, with activations and
// normalisation ignored. It matches architecture.py's rough_flops.
func (a Architecture) RoughFLOPs() int {
	flops := 0
	prev := a.effectiveInputSize()
	for _, h := range a.Hidden {
		flops += 2 * prev * h.Width
		prev = h.Width
	}
	flops += 2 * prev * a.OutputSize
	return flops
}

// LayerBreakdown returns one row per Dense layer: each hidden block in order,
// then the locked output layer. A row's Params includes that block's BatchNorm
// affine, so the rows sum to ParameterCount.
func (a Architecture) LayerBreakdown() []LayerParams {
	rows := make([]LayerParams, 0, len(a.Hidden)+1)
	prev := a.effectiveInputSize()
	for i, h := range a.Hidden {
		p := prev*h.Width + h.Width
		if h.BatchNorm {
			p += 2 * h.Width
		}
		name := fmt.Sprintf("hidden_%d", i+1)
		if h.BatchNorm {
			name += " (+bn)"
		}
		rows = append(rows, LayerParams{Name: name, In: prev, Out: h.Width, Params: p})
		prev = h.Width
	}
	rows = append(rows, LayerParams{
		Name:   "output",
		In:     prev,
		Out:    a.OutputSize,
		Params: prev*a.OutputSize + a.OutputSize,
	})
	return rows
}

// validateHiddenStack checks the editable middle of an architecture: each hidden
// layer's width (> 0), activation (one internal/nn supports), dropout (in
// [0, 1)) and — for a residual layer — that the previous width equals this
// width, since a skip connection needs matching dimensions. This mirrors the
// trainer's architecture.py so the builder UI, the estimate endpoint and a
// trained bundle all agree on what is buildable (PROJECT.md §10, §19.9).
func validateHiddenStack(a Architecture) error {
	prev := a.effectiveInputSize()
	for i, h := range a.Hidden {
		if h.Width <= 0 {
			return fmt.Errorf("architecture.hidden[%d]: width %d must be > 0", i, h.Width)
		}
		if h.Dropout < 0 || h.Dropout >= 1 {
			return fmt.Errorf("architecture.hidden[%d]: dropout %g must be in [0, 1)", i, h.Dropout)
		}
		act := h.Activation
		if act == "" {
			act = "relu"
		}
		if !hiddenActivations[act] {
			return fmt.Errorf("architecture.hidden[%d]: activation %q is not one of relu, leaky_relu, sigmoid, tanh", i, h.Activation)
		}
		if h.Residual && prev != h.Width {
			return fmt.Errorf("architecture.hidden[%d]: residual needs the previous width (%d) to equal this width (%d)", i, prev, h.Width)
		}
		prev = h.Width
	}
	return nil
}
