package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/dataset"
)

// statsShape is the subset of GET /api/v1/datasets/{ref}/stats this test asserts.
type statsShape struct {
	Ref          string `json:"ref"`
	ContentHash  string `json:"content_hash"`
	RowCount     int    `json:"row_count"`
	FeatureCount int    `json:"feature_count"`
	FeatureStats []struct {
		Index     int    `json:"index"`
		Name      string `json:"name"`
		BinCounts []int  `json:"bin_counts"`
	} `json:"feature_stats"`
	LabelDistribution struct {
		Classes []string `json:"classes"`
		Counts  []int    `json:"counts"`
		Total   int      `json:"total"`
	} `json:"label_distribution"`
	Correlation struct {
		Names  []string  `json:"names"`
		Size   int       `json:"size"`
		Matrix []float32 `json:"matrix"`
	} `json:"correlation"`
	Ports struct {
		TopDestination []dataset.PortCount `json:"top_destination"`
	} `json:"ports"`
	Protocols struct {
		TCP int `json:"tcp"`
	} `json:"protocols"`
	Outliers struct {
		Rule string `json:"rule"`
		Cap  int    `json:"cap"`
	} `json:"outliers"`
	PCA struct {
		Components        int         `json:"components"`
		Loadings          [][]float64 `json:"loadings"`
		ExplainedVariance []float64   `json:"explained_variance"`
		Projection        []struct {
			PC1   float64 `json:"pc1"`
			Label string  `json:"label"`
			Row   int     `json:"row"`
		} `json:"projection"`
		ProjectionSampled bool `json:"projection_sampled"`
	} `json:"pca"`
}

func TestDatasetStatsHappyPath(t *testing.T) {
	srv, _, _ := dsServer(t)
	h := srv.Handler()

	if rr := post(t, h, "/api/v1/datasets", createBody); rr.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rr.Code, rr.Body.String())
	}

	rr := do(t, h, http.MethodGet, "/api/v1/datasets/"+ref("thugs/lab-attacks-2026-08", "v1")+"/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET stats = %d: %s", rr.Code, rr.Body.String())
	}
	var s statsShape
	if err := json.Unmarshal(rr.Body.Bytes(), &s); err != nil {
		t.Fatalf("stats not JSON: %v", err)
	}

	if s.Ref != "thugs/lab-attacks-2026-08@v1" {
		t.Errorf("ref = %q", s.Ref)
	}
	if s.RowCount != dsRows || s.FeatureCount != 48 {
		t.Errorf("row_count=%d feature_count=%d", s.RowCount, s.FeatureCount)
	}
	if len(s.FeatureStats) != 48 {
		t.Fatalf("feature_stats has %d entries, want 48", len(s.FeatureStats))
	}
	if s.FeatureStats[0].Index != 0 || s.FeatureStats[0].Name == "" {
		t.Errorf("feature_stats[0] = %+v", s.FeatureStats[0])
	}
	if len(s.Correlation.Matrix) != 48*48 || s.Correlation.Size != 48 || len(s.Correlation.Names) != 48 {
		t.Fatalf("correlation matrix len=%d size=%d names=%d", len(s.Correlation.Matrix), s.Correlation.Size, len(s.Correlation.Names))
	}
	// diagonal is 1 for a non-degenerate feature
	if got := s.Correlation.Matrix[0]; got < 0.999 || got > 1.001 {
		t.Errorf("correlation[0,0] = %v, want 1", got)
	}
	if s.LabelDistribution.Total != dsRows || len(s.LabelDistribution.Classes) != 7 {
		t.Errorf("label_distribution = %+v", s.LabelDistribution)
	}
	sum := 0
	for _, c := range s.LabelDistribution.Counts {
		sum += c
	}
	if sum != dsRows {
		t.Errorf("label counts sum to %d, want %d", sum, dsRows)
	}
	if s.PCA.Components != 3 || len(s.PCA.Loadings) != 3 || len(s.PCA.Loadings[0]) != 48 {
		t.Errorf("pca shape: comps=%d loadings=%d", s.PCA.Components, len(s.PCA.Loadings))
	}
	if len(s.PCA.ExplainedVariance) != 3 {
		t.Errorf("pca explained_variance len = %d", len(s.PCA.ExplainedVariance))
	}
	if len(s.PCA.Projection) != dsRows || s.PCA.ProjectionSampled {
		t.Errorf("projection len=%d sampled=%v (dataset is small)", len(s.PCA.Projection), s.PCA.ProjectionSampled)
	}
	if s.Outliers.Rule == "" || s.Outliers.Cap != dataset.StatsOutlierCap {
		t.Errorf("outliers = %+v", s.Outliers)
	}
}

func TestDatasetStatsUnknownRef(t *testing.T) {
	srv, _, _ := dsServer(t)
	h := srv.Handler()
	rr := do(t, h, http.MethodGet, "/api/v1/datasets/"+ref("no/such", "v1")+"/stats")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown ref = %d, want 404", rr.Code)
	}
}

func TestDatasetStatsCachedBytesStable(t *testing.T) {
	srv, _, _ := dsServer(t)
	h := srv.Handler()
	if rr := post(t, h, "/api/v1/datasets", createBody); rr.Code != http.StatusCreated {
		t.Fatalf("create = %d", rr.Code)
	}
	path := "/api/v1/datasets/" + ref("thugs/lab-attacks-2026-08", "v1") + "/stats"

	a := do(t, h, http.MethodGet, path)
	b := do(t, h, http.MethodGet, path)
	if a.Code != http.StatusOK || b.Code != http.StatusOK {
		t.Fatalf("codes %d / %d", a.Code, b.Code)
	}
	if a.Body.String() != b.Body.String() {
		t.Fatal("two GET .../stats calls returned different bytes — the content-hash cache is not stable")
	}
}
