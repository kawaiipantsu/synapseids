package features_test

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
)

var update = flag.Bool("update", false, "rewrite the golden feature vectors")

// vectorsFor replays a committed PCAP fixture through capture -> flow -> features
// and returns the resulting vectors sorted by initiator port for stability.
func vectorsFor(t *testing.T, name string) []features.Vector {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "pcap", name)
	src, err := capture.OpenPCAPFile(path)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	type keyed struct {
		port uint16
		v    features.Vector
	}
	var out []keyed
	tbl := flow.NewTable(flow.Options{
		IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute,
	}, func(r flow.Record) {
		out = append(out, keyed{r.InitiatorPort, features.Extract(r)})
	})

	pkts, errc := src.Packets(context.Background())
	for p := range pkts {
		tbl.Observe(p)
	}
	if err := <-errc; err != nil {
		t.Fatalf("stream %s: %v", name, err)
	}
	tbl.Flush()

	sort.Slice(out, func(i, j int) bool { return out[i].port < out[j].port })
	res := make([]features.Vector, len(out))
	for i, k := range out {
		k.v.FlowID = 0 // flow ids are not part of the golden contract
		res[i] = k.v
	}
	return res
}

func TestGoldenFeatureVectors(t *testing.T) {
	for _, name := range []string{"http.pcap", "portscan.pcap", "udp.pcap"} {
		name := name
		t.Run(name, func(t *testing.T) {
			got := vectorsFor(t, name)
			goldenPath := filepath.Join("testdata", name+".golden.json")

			if *update {
				b, _ := json.MarshalIndent(got, "", "  ")
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(goldenPath, append(b, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("updated %s (%d vectors)", goldenPath, len(got))
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden (run with -update once): %v", err)
			}
			gotJSON, _ := json.MarshalIndent(got, "", "  ")
			if string(want) != string(gotJSON)+"\n" {
				t.Errorf("feature vectors for %s drifted from the frozen golden.\n"+
					"If this change is intentional, review the diff and re-run with -update.\n"+
					"got:\n%s", name, gotJSON)
			}
		})
	}
}

func TestVectorSizeMatchesSchema(t *testing.T) {
	if features.Size != 48 {
		t.Fatalf("features.Size = %d, want 48 (flow-features-v1)", features.Size)
	}
}
