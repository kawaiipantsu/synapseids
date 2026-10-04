package nn

import (
	"fmt"
	"math"
	"sort"
)

// Trace captures exact values from a forward pass, with bounded visualization
// samples. Animation timing belongs to the UI, not the model execution clock.
type Trace struct {
	Nodes  []TraceNode `json:"nodes"`
	Output []float32   `json:"output"`
	Note   string      `json:"note"`
}

// TraceNode is an ONNX operation's actual output tensor, not an estimated layer.
type TraceNode struct {
	Name        string       `json:"name"`
	Op          string       `json:"op"`
	Inputs      []string     `json:"inputs"`
	Values      []float32    `json:"values"`
	Shape       []int        `json:"shape"`
	Sample      []int        `json:"sample"`
	Connections []Connection `json:"connections,omitempty"`
}

// Connection is one sampled Dense edge; contribution is weight times input.
// Bias and activation are separate operations, so contribution is not attribution.
type Connection struct {
	From         int     `json:"from"`
	To           int     `json:"to"`
	Weight       float32 `json:"weight"`
	Contribution float32 `json:"contribution"`
}

// RunTrace executes the same evaluator as Run and snapshots intermediate values.
// Models exceeding the diagnostic budget return an explicit error, never a
// truncated graph presented as complete. Normal inference has no tracing cost.
func (m *Model) RunTrace(input []float32) (trace Trace, err error) {
	defer func() {
		if r := recover(); r != nil {
			trace = Trace{}
			err = fmt.Errorf("nn: trace evaluation failed")
		}
	}()
	if len(input) != m.inputSize || len(m.nodes) > 128 || len(input) > 4096 {
		return trace, fmt.Errorf("nn: trace input or graph exceeds diagnostic limit")
	}
	vals := make(map[string]*tensor, len(m.initializers)+len(m.nodes)+1)
	for k, v := range m.initializers {
		vals[k] = v
	}
	vals[m.inputName] = &tensor{data: append([]float32{}, input...), shape: []int{1, m.inputSize}}
	trace.Nodes = []TraceNode{{Name: m.inputName, Op: "Input", Inputs: []string{}, Values: append([]float32{}, input...), Shape: []int{1, m.inputSize}, Sample: sample(input)}}
	total := len(input)
	for _, n := range m.nodes {
		if err = evalNode(n, vals); err != nil {
			return Trace{}, err
		}
		for _, name := range n.outputs {
			value := vals[name]
			if value == nil {
				continue
			}
			total += len(value.data)
			if len(value.data) > 4096 || total > 32768 {
				return Trace{}, fmt.Errorf("nn: intermediate tensors exceed diagnostic limit")
			}
			for _, v := range value.data {
				if math.IsInf(float64(v), 0) || math.IsNaN(float64(v)) {
					return Trace{}, fmt.Errorf("nn: non-finite activation")
				}
			}
			inputs := []string{}
			for _, k := range n.inputs {
				if _, constant := m.initializers[k]; !constant && k != "" {
					inputs = append(inputs, k)
				}
			}
			node := TraceNode{Name: name, Op: n.op, Inputs: inputs, Values: append([]float32{}, value.data...), Shape: append([]int{}, value.shape...), Sample: sample(value.data)}
			if n.op == "Gemm" && len(n.inputs) > 1 && n.attrInt("transA", 0) == 0 {
				a, b := vals[n.inputs[0]], vals[n.inputs[1]]
				ar, ac, ae := mat2D(a)
				br, bc, be := mat2D(b)
				if ae == nil && be == nil && ar == 1 {
					trans := n.attrInt("transB", 0) != 0
					outs, ins := bc, br
					if trans {
						outs, ins = br, bc
					}
					if ins == ac && outs == len(value.data) {
						for _, from := range sample(a.data) {
							for _, to := range node.Sample {
								idx := from*outs + to
								if trans {
									idx = to*ins + from
								}
								w := b.data[idx] * n.attrFloat("alpha", 1)
								node.Connections = append(node.Connections, Connection{From: from, To: to, Weight: w, Contribution: w * a.data[from]})
							}
						}
					}
				}
			}
			trace.Nodes = append(trace.Nodes, node)
		}
	}
	out := vals[m.outputName]
	if out == nil || len(out.data) != m.outputSize {
		return Trace{}, fmt.Errorf("nn: trace output size mismatch")
	}
	trace.Output = append([]float32{}, out.data...)
	trace.Note = "Exact forward-pass values replayed from the retained input and loaded model. Up to 12 highest-magnitude units per operation are drawn; all values are available. Edge contributions exclude bias and later nonlinearities, and are not causal feature attribution. Animation is slowed for readability."
	return trace, nil
}
func sample(values []float32) []int {
	indices := make([]int, len(values))
	for i := range indices {
		indices[i] = i
	}
	sort.SliceStable(indices, func(i, j int) bool {
		return math.Abs(float64(values[indices[i]])) > math.Abs(float64(values[indices[j]]))
	})
	if len(indices) > 12 {
		indices = indices[:12]
	}
	sort.Ints(indices)
	return indices
}
