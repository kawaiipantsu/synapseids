package api

import (
	"net/http"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/insight"
)

func TestTimelineDefaultBucket(t *testing.T) {
	h := investigateServer(t)

	rr := get(t, h, "/api/v1/timeline")
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rr.Code, rr.Body.String())
	}
	s := decode[insight.Series](t, rr)
	if s.BucketSec != 1 {
		t.Errorf("default BucketSec = %d, want 1", s.BucketSec)
	}
	if s.AnomalyAvailable {
		t.Error("anomaly_available must be false until Phase 7")
	}
	// Verdicts sit at +0s, +1s, +2s, +10s, +20s, so the dense 1s series spans 21
	// buckets and totals 5.
	if len(s.Buckets) != 21 {
		t.Errorf("got %d buckets, want a dense 21", len(s.Buckets))
	}
	var total, disagree uint32
	for _, b := range s.Buckets {
		total += b.Total
		disagree += b.Disagreements
	}
	if total != 5 || disagree != 1 {
		t.Errorf("total = %d disagreements = %d, want 5 and 1", total, disagree)
	}
	if s.Buckets[0].ByClass["normal"] != 1 {
		t.Errorf("first bucket = %+v", s.Buckets[0])
	}
}

func TestTimelineBucketWidths(t *testing.T) {
	h := investigateServer(t)
	for param, want := range map[string]int{"1s": 1, "10s": 10, "1m": 60, "60s": 60} {
		s := decode[insight.Series](t, get(t, h, "/api/v1/timeline?bucket="+param))
		if s.BucketSec != want {
			t.Errorf("bucket=%s → BucketSec %d, want %d", param, s.BucketSec, want)
		}
	}
	// A 1m bucket folds the whole fixture into one slice.
	s := decode[insight.Series](t, get(t, h, "/api/v1/timeline?bucket=1m"))
	if len(s.Buckets) != 1 || s.Buckets[0].Total != 5 {
		t.Errorf("1m series = %+v", s.Buckets)
	}
}

func TestTimelineParamValidation(t *testing.T) {
	h := investigateServer(t)
	bad := []string{
		"?bucket=5s", "?bucket=2m", "?bucket=abc",
		"?from=nope", "?to=nope", "?from=2026-03-01", // not RFC3339
		"?from=2026-03-01T13:00:00Z&to=2026-03-01T12:00:00Z",
		"?class=bogus",
		"?host=nope", "?host=10.0.0.256", "?host=%3Cscript%3E",
	}
	for _, q := range bad {
		if rr := get(t, h, "/api/v1/timeline"+q); rr.Code != http.StatusBadRequest {
			t.Errorf("GET /api/v1/timeline%s = %d, want 400", q, rr.Code)
		}
	}
}

func TestTimelineScopedByHostAndClass(t *testing.T) {
	h := investigateServer(t)

	// 10.0.0.6 contributed exactly one verdict.
	s := decode[insight.Series](t, get(t, h, "/api/v1/timeline?bucket=1m&host=10.0.0.6"))
	if len(s.Buckets) != 1 || s.Buckets[0].Total != 1 {
		t.Errorf("host-scoped series = %+v", s.Buckets)
	}
	// 10.0.0.5 contributed four.
	s = decode[insight.Series](t, get(t, h, "/api/v1/timeline?bucket=1m&host=10.0.0.5"))
	if len(s.Buckets) != 1 || s.Buckets[0].Total != 4 {
		t.Errorf("host-scoped series = %+v", s.Buckets)
	}
	// class= narrows it to the single scan.
	s = decode[insight.Series](t, get(t, h, "/api/v1/timeline?bucket=1m&host=10.0.0.5&class=scan"))
	if len(s.Buckets) != 1 || s.Buckets[0].Total != 1 || s.Buckets[0].ByClass["scan"] != 1 {
		t.Errorf("host+class series = %+v", s.Buckets)
	}
	// An observed host with no verdicts in range yields an empty, non-null array.
	s = decode[insight.Series](t, get(t, h,
		"/api/v1/timeline?bucket=1s&host=10.0.0.5&from=2027-01-01T00:00:00Z"))
	if s.Buckets == nil {
		t.Error("buckets must serialise as [] rather than null")
	}
	if len(s.Buckets) != 0 {
		t.Errorf("out-of-range scoped series = %+v", s.Buckets)
	}
}

func TestTimelineTimeRange(t *testing.T) {
	h := investigateServer(t)
	s := decode[insight.Series](t, get(t, h,
		"/api/v1/timeline?bucket=1s&from=2026-03-01T12:00:05Z&to=2026-03-01T12:00:15Z"))
	var total uint32
	for _, b := range s.Buckets {
		total += b.Total
	}
	if total != 1 {
		t.Errorf("ranged total = %d, want 1 (only the +10s scan)", total)
	}
	if len(s.Buckets) != 11 {
		t.Errorf("got %d buckets, want a dense 11 across the requested range", len(s.Buckets))
	}
}
