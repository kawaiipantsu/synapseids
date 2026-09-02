package insight

import (
	"math"
	"testing"
)

// scanLike drives `n` one-packet TCP flows from src to a fresh destination port
// on the same responder — a lot of peers/ports, tiny volume: the scanner shape.
func scanLike(ix *Index, src string, n int, at0 int) {
	for i := 0; i < n; i++ {
		fr, cl := rec(uint64(at0+i), src, uint16(40000+i), "10.9.9.9", uint16(1+i),
			"tcp", base, 60, 40, "scan", 1, false)
		feed(ix, fr, cl)
	}
}

// serverLike drives `n` bidirectional TCP flows from many clients to one service
// port on `host` — one peer-facing port, real volume both ways: the server shape.
func serverLike(ix *Index, host string, n int, at0 int) {
	for i := 0; i < n; i++ {
		fr, cl := rec(uint64(at0+i), "10.0.0."+itoa(10+i%20), uint16(50000+i), host, 443,
			"tcp", base, 400, 8000, "normal", 0, false)
		feed(ix, fr, cl)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestFingerprintShapeAndFiniteness(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck
	scanLike(ix, "10.1.1.1", 30, 0)
	ix.Sync()

	fp, ok := ix.HostFingerprint("10.1.1.1")
	if !ok {
		t.Fatal("fingerprint not found for a tracked host")
	}
	dims := FingerprintDims()
	if len(fp.Vector) != len(dims) || len(fp.Dims) != len(dims) {
		t.Fatalf("vector len %d / dims len %d, want %d", len(fp.Vector), len(fp.Dims), len(dims))
	}
	for i, v := range fp.Vector {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("dim %d (%s) is not finite: %v", i, dims[i], v)
		}
		if fp.Dims[i].Name != dims[i] {
			t.Fatalf("dim %d name = %q, want %q", i, fp.Dims[i].Name, dims[i])
		}
	}
	if _, ok := ix.HostFingerprint("203.0.113.99"); ok {
		t.Fatal("fingerprint returned for an untracked host")
	}
}

func TestSimilarHostsGroupsLikeBehaviour(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck

	// Two scanners and two servers.
	scanLike(ix, "10.1.1.1", 40, 0)
	scanLike(ix, "10.1.1.2", 40, 1000)
	serverLike(ix, "10.2.2.1", 40, 2000)
	serverLike(ix, "10.2.2.2", 40, 3000)
	ix.Sync()

	_, sims, ok := ix.SimilarHosts("10.1.1.1", 10, 2)
	if !ok || len(sims) == 0 {
		t.Fatalf("no neighbours for 10.1.1.1 (ok=%v)", ok)
	}
	// The other scanner is the nearest; both servers are further away.
	if sims[0].IP != "10.1.1.2" {
		t.Fatalf("nearest neighbour = %q, want the other scanner 10.1.1.2 (%+v)", sims[0].IP, sims)
	}
	byIP := map[string]float64{}
	for _, s := range sims {
		byIP[s.IP] = s.Cosine
	}
	if byIP["10.1.1.2"] <= byIP["10.2.2.1"] || byIP["10.1.1.2"] <= byIP["10.2.2.2"] {
		t.Fatalf("scanner↔scanner similarity not above scanner↔server: %+v", byIP)
	}
	// The query host never appears among its own neighbours.
	if _, self := byIP["10.1.1.1"]; self {
		t.Fatal("query host listed as its own neighbour")
	}
}

func TestSimilarHostsMinFlowsFilter(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck
	serverLike(ix, "10.2.2.1", 20, 0)
	// A near-silent host: two flows only.
	f1, c1 := rec(9001, "10.3.3.3", 5000, "10.2.2.1", 443, "tcp", base, 100, 200, "normal", 0, false)
	feed(ix, f1, c1)
	f2, c2 := rec(9002, "10.3.3.3", 5001, "10.2.2.1", 443, "tcp", base, 100, 200, "normal", 0, false)
	feed(ix, f2, c2)
	ix.Sync()

	_, sims, ok := ix.SimilarHosts("10.2.2.1", 10, 5)
	if !ok {
		t.Fatal("not found")
	}
	for _, s := range sims {
		if s.IP == "10.3.3.3" {
			t.Fatalf("host with 2 flows should be filtered by min_flows=5: %+v", sims)
		}
	}
	// Lowering the floor lets it back in.
	_, sims2, _ := ix.SimilarHosts("10.2.2.1", 10, 1)
	var seen bool
	for _, s := range sims2 {
		seen = seen || s.IP == "10.3.3.3"
	}
	if !seen {
		t.Fatalf("min_flows=1 should include the 2-flow host: %+v", sims2)
	}

	if _, _, ok := ix.SimilarHosts("198.51.100.7", 10, 1); ok {
		t.Fatal("SimilarHosts ok=true for an untracked host")
	}
}

func TestCounterEntropyNorm(t *testing.T) {
	c := newCounter[int](64)
	if c.entropyNorm() != 0 {
		t.Fatal("empty counter entropy must be 0")
	}
	c.add(1)
	if c.entropyNorm() != 0 {
		t.Fatal("single-key entropy must be 0")
	}
	for i := 0; i < 8; i++ {
		c.add(i)
	}
	// 8 near-equal keys → entropy close to 1.
	if e := c.entropyNorm(); e < 0.9 || e > 1.0001 {
		t.Fatalf("flat 8-key entropy = %v, want ~1", e)
	}
}
