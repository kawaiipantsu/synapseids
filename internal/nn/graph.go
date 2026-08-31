package nn

import (
	"fmt"
	"math"
	"sort"
)

// supportedOps is the executable op set. Anything outside it (and outside the
// specially handled "Constant") is a hard load-time error. See
// docs/adr/0005-go-onnx-inference-runtime.md for the rationale.
var supportedOps = map[string]bool{
	"Gemm":               true,
	"MatMul":             true,
	"Add":                true,
	"Relu":               true,
	"LeakyRelu":          true,
	"Sigmoid":            true,
	"Tanh":               true,
	"BatchNormalization": true,
	"Dropout":            true,
	"Softmax":            true,
	"Identity":           true,
	"Flatten":            true,
	"Reshape":            true,
}

// node is a compiled graph node, ready for sequential evaluation.
type node struct {
	op      string
	name    string
	inputs  []string
	outputs []string
	attrs   []onnxAttr
}

func (n node) attrFloat(name string, def float32) float32 {
	for i := range n.attrs {
		if n.attrs[i].name == name {
			return n.attrs[i].f
		}
	}
	return def
}

func (n node) attrInt(name string, def int64) int64 {
	for i := range n.attrs {
		if n.attrs[i].name == name {
			return n.attrs[i].i
		}
	}
	return def
}

func (n node) label() string {
	if n.name != "" {
		return fmt.Sprintf("%s (%s)", n.name, n.op)
	}
	return n.op
}

// compile turns a decoded ONNX model into an executable Model: it materializes
// initializers, folds Constant nodes, validates every op, topologically orders
// the graph and resolves the fixed input / output sizes.
func compile(om *onnxModel) (*Model, error) {
	g := om.graph
	m := &Model{
		initializers: make(map[string]*tensor, len(g.initializers)),
		opCounts:     map[string]int{},
	}

	initNames := map[string]bool{}
	for i := range g.initializers {
		ot := &g.initializers[i]
		if ot.name == "" {
			return nil, fmt.Errorf("nn: graph initializer %d has no name", i)
		}
		t, err := ot.materialize()
		if err != nil {
			return nil, err
		}
		m.initializers[ot.name] = t
		initNames[ot.name] = true
	}

	// The runtime input is the graph input that is not also an initializer
	// (older IR versions list initializers among the inputs).
	var runtimeInputs []onnxValueInfo
	for _, vi := range g.inputs {
		if !initNames[vi.name] {
			runtimeInputs = append(runtimeInputs, vi)
		}
	}
	if len(runtimeInputs) != 1 {
		return nil, fmt.Errorf("nn: expected exactly one runtime input, found %d", len(runtimeInputs))
	}
	if len(g.outputs) != 1 {
		return nil, fmt.Errorf("nn: expected exactly one graph output, found %d", len(g.outputs))
	}
	m.inputName = runtimeInputs[0].name
	m.outputName = g.outputs[0].name
	if m.inputName == "" || m.outputName == "" {
		return nil, fmt.Errorf("nn: graph input/output is unnamed")
	}

	for i := range g.nodes {
		on := g.nodes[i]
		if on.opType == "" {
			return nil, fmt.Errorf("nn: node %d has no op_type", i)
		}
		if on.opType == "Constant" {
			t, name, err := constantValue(on)
			if err != nil {
				return nil, err
			}
			m.initializers[name] = t
			initNames[name] = true
			m.opCounts["Constant"]++
			continue
		}
		if !supportedOps[on.opType] {
			return nil, fmt.Errorf("nn: unsupported op %q", on.opType)
		}
		m.opCounts[on.opType]++
		m.nodes = append(m.nodes, node{
			op:      on.opType,
			name:    on.name,
			inputs:  on.input,
			outputs: on.output,
			attrs:   on.attrs,
		})
	}
	if len(m.nodes) == 0 {
		return nil, fmt.Errorf("nn: graph has no executable nodes")
	}

	ordered, err := topoOrder(m.nodes, initNames, m.inputName)
	if err != nil {
		return nil, err
	}
	m.nodes = ordered

	m.inputSize, err = resolveInputSize(runtimeInputs[0], m)
	if err != nil {
		return nil, err
	}
	m.outputSize, err = resolveOutputSize(g.outputs[0], m)
	if err != nil {
		return nil, err
	}
	if m.inputSize <= 0 || m.outputSize <= 0 {
		return nil, fmt.Errorf("nn: could not resolve fixed input/output size (input=%d output=%d)", m.inputSize, m.outputSize)
	}
	return m, nil
}

// constantValue extracts the tensor a Constant node produces and its output name.
func constantValue(on onnxNode) (*tensor, string, error) {
	if len(on.output) != 1 || on.output[0] == "" {
		return nil, "", fmt.Errorf("nn: Constant node %q must have exactly one named output", on.name)
	}
	for _, a := range on.attrs {
		switch a.name {
		case "value":
			if a.typ != 0 && a.typ != attrTENSOR {
				return nil, "", fmt.Errorf("nn: Constant %q value attribute has type %d, want TENSOR", on.name, a.typ)
			}
			if a.t == nil {
				return nil, "", fmt.Errorf("nn: Constant %q value attribute carries no tensor", on.name)
			}
			t, err := a.t.materialize()
			if err != nil {
				return nil, "", err
			}
			return t, on.output[0], nil
		case "value_float":
			return &tensor{data: []float32{a.f}}, on.output[0], nil
		case "value_floats":
			return &tensor{data: append([]float32(nil), a.floats...), shape: []int{len(a.floats)}}, on.output[0], nil
		case "value_int":
			return &tensor{data: []float32{float32(a.i)}}, on.output[0], nil
		case "value_ints":
			d := make([]float32, len(a.ints))
			for i, v := range a.ints {
				d[i] = float32(v)
			}
			return &tensor{data: d, shape: []int{len(a.ints)}}, on.output[0], nil
		}
	}
	return nil, "", fmt.Errorf("nn: Constant %q has no supported value attribute", on.name)
}

// topoOrder returns the nodes in an order where every input is produced before it
// is consumed. It is a fixpoint scan (graphs here are a handful of layers), and
// reports a cycle / missing tensor rather than looping forever.
func topoOrder(nodes []node, initNames map[string]bool, inputName string) ([]node, error) {
	available := map[string]bool{inputName: true}
	for k := range initNames {
		available[k] = true
	}
	remaining := append([]node(nil), nodes...)
	out := make([]node, 0, len(nodes))
	for len(remaining) > 0 {
		var next []node
		progress := false
		for _, n := range remaining {
			ready := true
			for _, in := range n.inputs {
				if in != "" && !available[in] {
					ready = false
					break
				}
			}
			if !ready {
				next = append(next, n)
				continue
			}
			out = append(out, n)
			for _, o := range n.outputs {
				if o != "" {
					available[o] = true
				}
			}
			progress = true
		}
		if !progress {
			labels := make([]string, len(next))
			for i, n := range next {
				labels[i] = n.label()
			}
			sort.Strings(labels)
			return nil, fmt.Errorf("nn: graph has unresolvable nodes (cycle or missing tensor): %v", labels)
		}
		remaining = next
	}
	return out, nil
}

// resolveInputSize takes the last concrete dimension of the input's declared
// shape, falling back to the K dimension of the first Gemm / MatMul weight.
func resolveInputSize(vi onnxValueInfo, m *Model) (int, error) {
	if vi.hasShape {
		if n, ok := shapeElemsBatch1(vi.shape); ok {
			return n, nil
		}
	}
	for _, n := range m.nodes {
		for pos, in := range n.inputs {
			if in != m.inputName {
				continue
			}
			switch n.op {
			case "Gemm":
				if pos != 0 || len(n.inputs) < 2 {
					continue
				}
				w := m.initializers[n.inputs[1]]
				if w == nil || len(w.shape) != 2 {
					continue
				}
				if n.attrInt("transB", 0) != 0 {
					return w.shape[1], nil
				}
				return w.shape[0], nil
			case "MatMul":
				if pos != 0 || len(n.inputs) < 2 {
					continue
				}
				w := m.initializers[n.inputs[1]]
				if w != nil && len(w.shape) == 2 {
					return w.shape[0], nil
				}
			}
		}
	}
	return 0, fmt.Errorf("nn: graph input %q has no concrete shape and no inferable first layer", m.inputName)
}

// resolveOutputSize takes the concrete element count of the output's declared
// shape (batch pinned to 1), falling back to walking the producer chain back
// through shape-preserving ops to the last Gemm / MatMul and taking its N.
func resolveOutputSize(vi onnxValueInfo, m *Model) (int, error) {
	if vi.hasShape {
		if n, ok := shapeElemsBatch1(vi.shape); ok {
			return n, nil
		}
	}
	producer := map[string]node{}
	for _, n := range m.nodes {
		for _, o := range n.outputs {
			if o != "" {
				producer[o] = n
			}
		}
	}
	name := m.outputName
	for hops := 0; hops < 128; hops++ {
		n, ok := producer[name]
		if !ok {
			return 0, fmt.Errorf("nn: cannot infer output size; %q has no producer", name)
		}
		switch n.op {
		case "Gemm":
			if len(n.inputs) < 2 {
				return 0, fmt.Errorf("nn: Gemm %q is missing its weight input", n.label())
			}
			w := m.initializers[n.inputs[1]]
			if w == nil || len(w.shape) != 2 {
				return 0, fmt.Errorf("nn: Gemm %q weight is not a 2-D initializer", n.label())
			}
			if n.attrInt("transB", 0) != 0 {
				return w.shape[0], nil
			}
			return w.shape[1], nil
		case "MatMul":
			if len(n.inputs) < 2 {
				return 0, fmt.Errorf("nn: MatMul %q is missing an operand", n.label())
			}
			w := m.initializers[n.inputs[1]]
			if w != nil && len(w.shape) == 2 {
				return w.shape[1], nil
			}
			return 0, fmt.Errorf("nn: cannot infer output size through MatMul %q", n.label())
		case "Relu", "LeakyRelu", "Sigmoid", "Tanh", "Softmax", "Dropout", "Identity", "Flatten", "BatchNormalization":
			name = firstNonEmpty(n.inputs)
		case "Add":
			name = firstNonEmpty(n.inputs)
		default:
			return 0, fmt.Errorf("nn: cannot infer output size through op %q", n.op)
		}
		if name == "" {
			return 0, fmt.Errorf("nn: cannot infer output size; reached an op with no inputs")
		}
	}
	return 0, fmt.Errorf("nn: output-size inference exceeded its hop limit")
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// evalNode evaluates one compiled node against the live value map.
func evalNode(n node, vals map[string]*tensor) error {
	in := func(i int) (*tensor, error) {
		if i >= len(n.inputs) || n.inputs[i] == "" {
			return nil, fmt.Errorf("missing input %d", i)
		}
		t, ok := vals[n.inputs[i]]
		if !ok || t == nil {
			return nil, fmt.Errorf("input %q is not available", n.inputs[i])
		}
		return t, nil
	}
	set := func(t *tensor) error {
		if len(n.outputs) == 0 || n.outputs[0] == "" {
			return fmt.Errorf("node has no output name")
		}
		vals[n.outputs[0]] = t
		return nil
	}

	switch n.op {
	case "Gemm":
		return evalGemm(n, in, set)
	case "MatMul":
		a, err := in(0)
		if err != nil {
			return err
		}
		b, err := in(1)
		if err != nil {
			return err
		}
		r, err := matmul(a, b)
		if err != nil {
			return err
		}
		return set(r)
	case "Add":
		a, err := in(0)
		if err != nil {
			return err
		}
		b, err := in(1)
		if err != nil {
			return err
		}
		r, err := broadcastBinary(a, b, func(x, y float32) float32 { return x + y })
		if err != nil {
			return err
		}
		return set(r)
	case "Relu":
		return unary(in, set, func(x float32) float32 {
			if x < 0 {
				return 0
			}
			return x
		})
	case "LeakyRelu":
		alpha := n.attrFloat("alpha", 0.01)
		return unary(in, set, func(x float32) float32 {
			if x < 0 {
				return alpha * x
			}
			return x
		})
	case "Sigmoid":
		return unary(in, set, func(x float32) float32 {
			return float32(1.0 / (1.0 + math.Exp(-float64(x))))
		})
	case "Tanh":
		return unary(in, set, func(x float32) float32 {
			return float32(math.Tanh(float64(x)))
		})
	case "BatchNormalization":
		return evalBatchNorm(n, in, set)
	case "Dropout", "Identity":
		a, err := in(0)
		if err != nil {
			return err
		}
		return set(&tensor{data: append([]float32(nil), a.data...), shape: append([]int(nil), a.shape...)})
	case "Flatten":
		return evalFlatten(n, in, set)
	case "Reshape":
		return evalReshape(in, set)
	case "Softmax":
		return evalSoftmax(n, in, set)
	default:
		return fmt.Errorf("unsupported op %q", n.op) // unreachable: compile rejects first
	}
}

func unary(in func(int) (*tensor, error), set func(*tensor) error, f func(float32) float32) error {
	a, err := in(0)
	if err != nil {
		return err
	}
	out := &tensor{data: make([]float32, len(a.data)), shape: append([]int(nil), a.shape...)}
	for i, v := range a.data {
		out.data[i] = f(v)
	}
	return set(out)
}

func evalGemm(n node, in func(int) (*tensor, error), set func(*tensor) error) error {
	a, err := in(0)
	if err != nil {
		return err
	}
	b, err := in(1)
	if err != nil {
		return err
	}
	alpha := n.attrFloat("alpha", 1)
	beta := n.attrFloat("beta", 1)
	transA := n.attrInt("transA", 0) != 0
	transB := n.attrInt("transB", 0) != 0

	ar, ac, err := mat2D(a)
	if err != nil {
		return fmt.Errorf("operand A: %w", err)
	}
	br, bc, err := mat2D(b)
	if err != nil {
		return fmt.Errorf("operand B: %w", err)
	}

	adata, m, k := a.data, ar, ac
	if transA {
		adata, err = transpose(a.data, ar, ac)
		if err != nil {
			return err
		}
		m, k = ac, ar
	}
	bdata, k2, ncol := b.data, br, bc
	if transB {
		bdata, err = transpose(b.data, br, bc)
		if err != nil {
			return err
		}
		k2, ncol = bc, br
	}
	if k != k2 {
		return fmt.Errorf("nn: Gemm inner dims disagree (A is %dx%d, B is %dx%d, transB=%v)", m, k, k2, ncol, transB)
	}

	y, err := matmul2D(adata, m, k, bdata, k2, ncol)
	if err != nil {
		return err
	}
	if alpha != 1 {
		for i := range y {
			y[i] *= alpha
		}
	}
	yt := &tensor{data: y, shape: []int{m, ncol}}
	if len(n.inputs) >= 3 && n.inputs[2] != "" {
		c, err := in(2)
		if err != nil {
			return err
		}
		r, err := broadcastBinary(yt, c, func(x, cc float32) float32 { return x + beta*cc })
		if err != nil {
			return fmt.Errorf("nn: Gemm bias: %w", err)
		}
		return set(r)
	}
	return set(yt)
}

// matmul implements the standalone MatMul op for the 1-D / 2-D operand shapes an
// MLP produces (batch size is fixed at 1).
func matmul(a, b *tensor) (*tensor, error) {
	switch {
	case len(a.shape) <= 1 && len(b.shape) == 2:
		k := len(a.data)
		if len(a.shape) == 1 {
			k = a.shape[0]
		}
		y, err := matmul2D(a.data, 1, k, b.data, b.shape[0], b.shape[1])
		if err != nil {
			return nil, err
		}
		return &tensor{data: y, shape: []int{b.shape[1]}}, nil
	case len(a.shape) == 2 && len(b.shape) == 2:
		y, err := matmul2D(a.data, a.shape[0], a.shape[1], b.data, b.shape[0], b.shape[1])
		if err != nil {
			return nil, err
		}
		return &tensor{data: y, shape: []int{a.shape[0], b.shape[1]}}, nil
	case len(a.shape) == 2 && len(b.shape) == 1:
		y, err := matmul2D(a.data, a.shape[0], a.shape[1], b.data, b.shape[0], 1)
		if err != nil {
			return nil, err
		}
		return &tensor{data: y, shape: []int{a.shape[0]}}, nil
	default:
		return nil, fmt.Errorf("nn: MatMul shapes %v x %v are not supported (batch size is fixed at 1)", a.shape, b.shape)
	}
}

// evalBatchNorm applies inference-time BatchNormalization, folded to a
// per-channel affine y = scale*(x-mean)/sqrt(var+epsilon) + B. The channel index
// is the last dimension (feed-forward use); NCHW spatial layout is out of scope.
func evalBatchNorm(n node, in func(int) (*tensor, error), set func(*tensor) error) error {
	x, err := in(0)
	if err != nil {
		return err
	}
	scale, err := in(1)
	if err != nil {
		return err
	}
	bias, err := in(2)
	if err != nil {
		return err
	}
	mean, err := in(3)
	if err != nil {
		return err
	}
	variance, err := in(4)
	if err != nil {
		return err
	}
	eps := n.attrFloat("epsilon", 1e-5)

	c := len(scale.data)
	if c == 0 || len(bias.data) != c || len(mean.data) != c || len(variance.data) != c {
		return fmt.Errorf("nn: BatchNormalization params disagree (scale=%d B=%d mean=%d var=%d)",
			len(scale.data), len(bias.data), len(mean.data), len(variance.data))
	}
	if len(x.data)%c != 0 {
		return fmt.Errorf("nn: BatchNormalization input of %d values is not divisible by %d channels", len(x.data), c)
	}

	af := make([]float32, c)
	bf := make([]float32, c)
	for i := 0; i < c; i++ {
		denom := float32(math.Sqrt(float64(variance.data[i] + eps)))
		if denom == 0 || math.IsNaN(float64(denom)) {
			return fmt.Errorf("nn: BatchNormalization channel %d has non-positive var+epsilon", i)
		}
		af[i] = scale.data[i] / denom
		bf[i] = bias.data[i] - scale.data[i]*mean.data[i]/denom
	}
	out := &tensor{data: make([]float32, len(x.data)), shape: append([]int(nil), x.shape...)}
	for i, v := range x.data {
		ch := i % c
		out.data[i] = af[ch]*v + bf[ch]
	}
	return set(out)
}

func evalFlatten(n node, in func(int) (*tensor, error), set func(*tensor) error) error {
	x, err := in(0)
	if err != nil {
		return err
	}
	shape := x.shape
	if len(shape) == 0 {
		shape = []int{len(x.data)}
	}
	axis := int(n.attrInt("axis", 1))
	if axis < 0 {
		axis += len(shape)
	}
	if axis < 0 || axis > len(shape) {
		return fmt.Errorf("nn: Flatten axis %d out of range for shape %v", n.attrInt("axis", 1), x.shape)
	}
	outer, inner := 1, 1
	for i, d := range shape {
		if i < axis {
			outer *= d
		} else {
			inner *= d
		}
	}
	return set(&tensor{data: append([]float32(nil), x.data...), shape: []int{outer, inner}})
}

// evalReshape reshapes data (row-major, so the values are unchanged) using a
// constant shape operand, resolving a single -1 and per-dim 0 (copy input dim).
func evalReshape(in func(int) (*tensor, error), set func(*tensor) error) error {
	x, err := in(0)
	if err != nil {
		return err
	}
	shp, err := in(1)
	if err != nil {
		return fmt.Errorf("nn: Reshape needs a constant shape operand: %w", err)
	}
	dims := make([]int, len(shp.data))
	neg := -1
	known := 1
	for i, fv := range shp.data {
		d := int(fv)
		switch {
		case d == -1:
			if neg >= 0 {
				return fmt.Errorf("nn: Reshape has more than one -1 dimension")
			}
			neg = i
			dims[i] = -1
		case d == 0:
			if i >= len(x.shape) {
				return fmt.Errorf("nn: Reshape dim %d is 0 but the input has no dim %d", i, i)
			}
			dims[i] = x.shape[i]
			known *= dims[i]
		case d < 0:
			return fmt.Errorf("nn: Reshape dim %d is invalid (%d)", i, d)
		default:
			dims[i] = d
			known *= d
		}
	}
	total := len(x.data)
	if neg >= 0 {
		if known <= 0 || total%known != 0 {
			return fmt.Errorf("nn: Reshape cannot infer the -1 dimension (total %d, known %d)", total, known)
		}
		dims[neg] = total / known
	}
	prod := 1
	for _, d := range dims {
		prod *= d
	}
	if prod != total {
		return fmt.Errorf("nn: Reshape to %v changes the element count (%d != %d)", dims, prod, total)
	}
	return set(&tensor{data: append([]float32(nil), x.data...), shape: dims})
}

// evalSoftmax applies a numerically stable softmax along one axis (default -1).
func evalSoftmax(n node, in func(int) (*tensor, error), set func(*tensor) error) error {
	x, err := in(0)
	if err != nil {
		return err
	}
	shape := x.shape
	if len(shape) == 0 {
		shape = []int{len(x.data)}
	}
	axis := int(n.attrInt("axis", -1))
	if axis < 0 {
		axis += len(shape)
	}
	if axis < 0 || axis >= len(shape) {
		return fmt.Errorf("nn: Softmax axis %d out of range for shape %v", n.attrInt("axis", -1), x.shape)
	}
	dim := shape[axis]
	inner := 1
	for _, d := range shape[axis+1:] {
		inner *= d
	}
	outer := 1
	for _, d := range shape[:axis] {
		outer *= d
	}
	if outer*dim*inner != len(x.data) {
		return fmt.Errorf("nn: Softmax shape %v does not match %d values", x.shape, len(x.data))
	}
	out := &tensor{data: make([]float32, len(x.data)), shape: append([]int(nil), shape...)}
	for o := 0; o < outer; o++ {
		for j := 0; j < inner; j++ {
			base := o*dim*inner + j
			maxv := float32(math.Inf(-1))
			for d := 0; d < dim; d++ {
				if v := x.data[base+d*inner]; v > maxv {
					maxv = v
				}
			}
			var sum float64
			for d := 0; d < dim; d++ {
				e := math.Exp(float64(x.data[base+d*inner] - maxv))
				out.data[base+d*inner] = float32(e)
				sum += e
			}
			if sum == 0 {
				return fmt.Errorf("nn: Softmax denominator underflowed to zero")
			}
			for d := 0; d < dim; d++ {
				out.data[base+d*inner] = float32(float64(out.data[base+d*inner]) / sum)
			}
		}
	}
	return set(out)
}
