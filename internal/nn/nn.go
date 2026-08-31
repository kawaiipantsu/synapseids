// Package nn is a minimal, dependency-free executor for the feed-forward neural
// networks SynapseIDS trains (PROJECT.md §10). It reads the subset of the ONNX
// protobuf wire format those models use and runs them on the CPU with plain
// float32 arithmetic — no CGO, no onnxruntime, no protobuf library, so the
// daemon still cross-compiles cleanly to every Linux target and builds offline.
//
// The supported op set is deliberately small: Gemm, MatMul, Add, Relu,
// LeakyRelu, Sigmoid, Tanh, BatchNormalization (inference-time affine fold),
// Dropout (identity), Softmax, Identity, Flatten, Reshape (constant shape) and
// Constant (folded to an initializer). Any other op is a hard load-time error.
// Batch size is fixed at 1, every value is float32 and evaluation is
// deterministic. A malformed model returns an error, never a panic. See
// docs/adr/0005-go-onnx-inference-runtime.md.
package nn

import (
	"fmt"
	"io"
	"os"
)

// maxModelBytes guards against a hostile or accidental huge input.
const maxModelBytes = 256 << 20

// Model is a compiled, ready-to-run network. It is immutable after loading, so
// Run may be called concurrently (Run allocates all of its working state).
type Model struct {
	inputName    string
	outputName   string
	inputSize    int
	outputSize   int
	initializers map[string]*tensor
	nodes        []node
	opCounts     map[string]int
}

// Load parses and compiles an ONNX model (a serialized ModelProto) from r.
func Load(r io.Reader) (*Model, error) {
	if r == nil {
		return nil, fmt.Errorf("nn: nil reader")
	}
	b, err := io.ReadAll(io.LimitReader(r, maxModelBytes+1))
	if err != nil {
		return nil, fmt.Errorf("nn: reading model: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("nn: empty model")
	}
	if len(b) > maxModelBytes {
		return nil, fmt.Errorf("nn: model exceeds the %d-byte limit", maxModelBytes)
	}
	return loadBytes(b)
}

// LoadFile is Load on the contents of the file at path.
func LoadFile(path string) (*Model, error) {
	f, err := os.Open(path) //nolint:gosec // the caller (a bundle loader) names the model to run
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	m, err := Load(f)
	if err != nil {
		return nil, fmt.Errorf("nn: %s: %w", path, err)
	}
	return m, nil
}

func loadBytes(b []byte) (m *Model, err error) {
	defer func() {
		if r := recover(); r != nil {
			m, err = nil, fmt.Errorf("nn: malformed model (recovered from %v)", r)
		}
	}()
	om, perr := parseModel(b)
	if perr != nil {
		return nil, fmt.Errorf("nn: parse: %w", perr)
	}
	if len(om.graph.nodes) == 0 && len(om.graph.initializers) == 0 {
		return nil, fmt.Errorf("nn: model carries no graph (not an ONNX ModelProto?)")
	}
	return compile(om)
}

// Run scores a single feature vector. len(input) must equal InputSize; the
// result has OutputSize values. It never panics — a structurally broken model
// surfaces as an error.
func (m *Model) Run(input []float32) (out []float32, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("nn: recovered from panic during inference: %v", r)
		}
	}()
	if len(input) != m.inputSize {
		return nil, fmt.Errorf("nn: input has %d values, model expects %d", len(input), m.inputSize)
	}

	vals := make(map[string]*tensor, len(m.initializers)+len(m.nodes)+1)
	for k, v := range m.initializers {
		vals[k] = v // read-only: ops always allocate fresh outputs, never mutate inputs
	}
	vals[m.inputName] = &tensor{
		data:  append([]float32(nil), input...),
		shape: []int{1, m.inputSize},
	}

	for _, n := range m.nodes {
		if err := evalNode(n, vals); err != nil {
			return nil, fmt.Errorf("nn: %s: %w", n.label(), err)
		}
	}

	res, ok := vals[m.outputName]
	if !ok || res == nil {
		return nil, fmt.Errorf("nn: graph did not produce output %q", m.outputName)
	}
	if len(res.data) != m.outputSize {
		return nil, fmt.Errorf("nn: output %q has %d values, expected %d", m.outputName, len(res.data), m.outputSize)
	}
	return append([]float32(nil), res.data...), nil
}

// InputSize is the number of features the model consumes (batch size is 1).
func (m *Model) InputSize() int { return m.inputSize }

// OutputSize is the number of class scores the model produces.
func (m *Model) OutputSize() int { return m.outputSize }

// OpCounts returns a copy of the op-type histogram of the compiled graph, for
// diagnostics and tests.
func (m *Model) OpCounts() map[string]int {
	out := make(map[string]int, len(m.opCounts))
	for k, v := range m.opCounts {
		out[k] = v
	}
	return out
}
