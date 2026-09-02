package pipeline

import (
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

func vec(mark float64) [features.Size]float64 {
	var v [features.Size]float64
	v[0] = mark
	return v
}

func TestSeqWindowsAccumulatesAndWraps(t *testing.T) {
	s := newSeqWindows(64)
	base := time.Unix(1_700_000_000, 0)

	var last [][features.Size]float64
	for i := 0; i < schema.SequenceLenV1+3; i++ {
		last = s.push("k", vec(float64(i)), base.Add(time.Duration(i)*time.Second))
	}
	if len(last) != schema.SequenceLenV1 {
		t.Fatalf("window len = %d, want %d (ring should cap)", len(last), schema.SequenceLenV1)
	}
	// Oldest-first: the first row is push #3 (0..2 fell off), the last is the newest.
	if last[0][0] != 3 {
		t.Fatalf("oldest retained row = %v, want mark 3", last[0][0])
	}
	if last[len(last)-1][0] != float64(schema.SequenceLenV1+2) {
		t.Fatalf("newest row = %v, want %d", last[len(last)-1][0], schema.SequenceLenV1+2)
	}

	// A second key is independent.
	other := s.push("k2", vec(99), base)
	if len(other) != 1 || other[0][0] != 99 {
		t.Fatalf("second key window = %v", other)
	}
}

func TestSeqWindowsPrunesLeastRecent(t *testing.T) {
	s := newSeqWindows(16) // floor
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < 40; i++ {
		s.push(seqKey("10.0.0.1", uint16(i), "10.0.0.2", 443, "tcp"), vec(1), base.Add(time.Duration(i)*time.Minute))
	}
	if len(s.m) > 16 {
		t.Fatalf("map size %d exceeds cap 16", len(s.m))
	}
	if s.evicted == 0 {
		t.Fatal("no evictions counted despite overflow")
	}
	// The most recent key must still be present.
	newest := seqKey("10.0.0.1", 39, "10.0.0.2", 443, "tcp")
	if _, ok := s.m[newest]; !ok {
		t.Fatal("prune dropped the most recently updated key")
	}
}

func TestSeqKeyDistinguishesDirectionAndProto(t *testing.T) {
	a := seqKey("10.0.0.1", 5000, "10.0.0.2", 443, "tcp")
	b := seqKey("10.0.0.2", 443, "10.0.0.1", 5000, "tcp") // swapped
	c := seqKey("10.0.0.1", 5000, "10.0.0.2", 443, "udp")
	if a == b || a == c || b == c {
		t.Fatalf("seqKey collision: %q %q %q", a, b, c)
	}
}
