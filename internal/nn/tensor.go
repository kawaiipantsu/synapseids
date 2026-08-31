package nn

import "fmt"

// tensor is a dense, row-major float32 array with an explicit shape. Batch size
// is fixed at 1, so in practice shapes are [1, n], [n] or scalar (nil shape).
type tensor struct {
	data  []float32
	shape []int
}

func newTensor(shape ...int) *tensor {
	n := 1
	for _, d := range shape {
		n *= d
	}
	return &tensor{data: make([]float32, n), shape: append([]int(nil), shape...)}
}

// mat2D collapses a tensor to (rows, cols), treating a 1-D tensor as a row vector
// and folding any leading dimensions of an N-D tensor into rows. It verifies the
// element count matches the shape.
func mat2D(t *tensor) (rows, cols int, err error) {
	switch len(t.shape) {
	case 0:
		if len(t.data) != 1 {
			return 0, 0, fmt.Errorf("nn: scalar tensor carries %d values", len(t.data))
		}
		return 1, 1, nil
	case 1:
		rows, cols = 1, t.shape[0]
	default:
		cols = t.shape[len(t.shape)-1]
		rows = 1
		for _, d := range t.shape[:len(t.shape)-1] {
			rows *= d
		}
	}
	if rows*cols != len(t.data) {
		return 0, 0, fmt.Errorf("nn: shape %v does not match %d values", t.shape, len(t.data))
	}
	return rows, cols, nil
}

// transpose returns the transpose of a row-major r x c matrix.
func transpose(d []float32, r, c int) ([]float32, error) {
	if r*c != len(d) {
		return nil, fmt.Errorf("nn: transpose %dx%d does not match %d values", r, c, len(d))
	}
	out := make([]float32, len(d))
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			out[j*r+i] = d[i*c+j]
		}
	}
	return out, nil
}

// matmul2D computes A[m,k] @ B[k,n] -> [m,n], row-major, accumulating in float32.
func matmul2D(a []float32, m, k int, b []float32, k2, n int) ([]float32, error) {
	if k != k2 {
		return nil, fmt.Errorf("nn: matmul inner dims disagree (%d vs %d)", k, k2)
	}
	if m < 0 || n < 0 || k < 0 {
		return nil, fmt.Errorf("nn: matmul negative dimension")
	}
	if len(a) < m*k {
		return nil, fmt.Errorf("nn: matmul operand A has %d values, need %d", len(a), m*k)
	}
	if len(b) < k*n {
		return nil, fmt.Errorf("nn: matmul operand B has %d values, need %d", len(b), k*n)
	}
	out := make([]float32, m*n)
	for i := 0; i < m; i++ {
		arow := a[i*k : i*k+k]
		orow := out[i*n : i*n+n]
		for p := 0; p < k; p++ {
			av := arow[p]
			if av == 0 {
				continue
			}
			brow := b[p*n : p*n+n]
			for j := 0; j < n; j++ {
				orow[j] += av * brow[j]
			}
		}
	}
	return out, nil
}

// broadcastShape computes the NumPy-style right-aligned broadcast of two shapes.
func broadcastShape(a, b []int) ([]int, error) {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]int, n)
	for i := 0; i < n; i++ {
		ad, bd := 1, 1
		if off := i - (n - len(a)); off >= 0 {
			ad = a[off]
		}
		if off := i - (n - len(b)); off >= 0 {
			bd = b[off]
		}
		switch {
		case ad == bd:
			out[i] = ad
		case ad == 1:
			out[i] = bd
		case bd == 1:
			out[i] = ad
		default:
			return nil, fmt.Errorf("nn: shapes %v and %v are not broadcast-compatible", a, b)
		}
	}
	return out, nil
}

// broadcastStrides returns per-output-axis strides into a source of the given
// shape; an axis of size 1 (or absent) gets stride 0.
func broadcastStrides(shape, out []int) []int {
	real := make([]int, len(shape))
	acc := 1
	for d := len(shape) - 1; d >= 0; d-- {
		if shape[d] == 1 {
			real[d] = 0
		} else {
			real[d] = acc
		}
		acc *= shape[d]
	}
	str := make([]int, len(out))
	offset := len(out) - len(shape)
	for d := 0; d < len(shape); d++ {
		str[d+offset] = real[d]
	}
	return str
}

// broadcastBinary applies f elementwise over a and b with NumPy broadcasting.
func broadcastBinary(a, b *tensor, f func(x, y float32) float32) (*tensor, error) {
	if shapeEqual(a.shape, b.shape) {
		out := &tensor{data: make([]float32, len(a.data)), shape: append([]int(nil), a.shape...)}
		if len(a.data) != len(b.data) {
			return nil, fmt.Errorf("nn: operands with shape %v disagree in length (%d vs %d)", a.shape, len(a.data), len(b.data))
		}
		for i := range a.data {
			out.data[i] = f(a.data[i], b.data[i])
		}
		return out, nil
	}
	os, err := broadcastShape(a.shape, b.shape)
	if err != nil {
		return nil, err
	}
	out := newTensor(os...)
	if len(out.data) == 0 {
		return out, nil
	}
	aStr := broadcastStrides(a.shape, os)
	bStr := broadcastStrides(b.shape, os)
	idx := make([]int, len(os))
	for flat := range out.data {
		ai, bi := 0, 0
		for d := range os {
			ai += idx[d] * aStr[d]
			bi += idx[d] * bStr[d]
		}
		if ai < 0 || bi < 0 || ai >= len(a.data) || bi >= len(b.data) {
			return nil, fmt.Errorf("nn: broadcast index out of range (a=%d/%d b=%d/%d)", ai, len(a.data), bi, len(b.data))
		}
		out.data[flat] = f(a.data[ai], b.data[bi])
		for d := len(os) - 1; d >= 0; d-- {
			idx[d]++
			if idx[d] < os[d] {
				break
			}
			idx[d] = 0
		}
	}
	return out, nil
}

func shapeEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// shapeElemsBatch1 returns the number of elements a shape holds with the batch
// dimension pinned to 1: every concrete (> 0) dim is multiplied together and any
// symbolic / non-positive dim is treated as 1. ok is false when no dim is
// concrete (the shape carries no usable size).
func shapeElemsBatch1(dims []int64) (n int, ok bool) {
	if len(dims) == 0 {
		return 0, false
	}
	n = 1
	for _, d := range dims {
		if d <= 0 {
			continue
		}
		n *= int(d)
		ok = true
	}
	return n, ok
}
