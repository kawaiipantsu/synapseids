package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// post sends body to the estimate endpoint and returns the decoded response.
func postEstimate(t *testing.T, h http.Handler, body string) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/architecture/estimate", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		return rr.Code, nil
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("response not JSON: %v (%s)", err, rr.Body.String())
	}
	return rr.Code, out
}

func TestArchitectureEstimate(t *testing.T) {
	h := newTestServer()

	// 48 -> 64 (+bn) -> 32 -> 7
	// Dense 48->64 + bn : 48*64 + 64 + 2*64 = 3264
	// Dense 64->32      : 64*32 + 32        = 2080
	// Dense 32->7       : 32*7  + 7         =  231
	code, out := postEstimate(t, h, `{"hidden":[{"width":64,"activation":"relu","batchnorm":true},{"width":32,"activation":"relu"}]}`)
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	if out["valid"] != true {
		t.Fatalf("want valid=true, got %v (error %v)", out["valid"], out["error"])
	}
	if got := out["parameter_count"].(float64); got != 5575 {
		t.Fatalf("parameter_count = %v, want 5575", got)
	}
	if got := out["approx_bytes"].(float64); got != 5575*4 {
		t.Fatalf("approx_bytes = %v, want %d", got, 5575*4)
	}
	// rough FLOPs = 2*(48*64 + 64*32 + 32*7) = 10688
	if got := out["rough_flops"].(float64); got != 10688 {
		t.Fatalf("rough_flops = %v, want 10688", got)
	}
	layers, _ := out["layers"].([]any)
	if len(layers) != 3 {
		t.Fatalf("layers = %v", out["layers"])
	}
	last := layers[2].(map[string]any)
	if last["name"] != "output" || last["in"].(float64) != 32 || last["out"].(float64) != 7 {
		t.Fatalf("output layer row = %v", last)
	}
}

func TestArchitectureEstimateForcesLockedEdges(t *testing.T) {
	h := newTestServer()

	// The client lies about the edge sizes; the server must ignore them and
	// force 48 / 7 before doing any math or validation (PROJECT.md §10).
	code, out := postEstimate(t, h, `{"input_size":999,"output_size":3,"hidden":[{"width":32,"activation":"relu"}]}`)
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	if out["valid"] != true {
		t.Fatalf("want valid after edge lock, got %v (%v)", out["valid"], out["error"])
	}
	// 48 -> 32 -> 7 : (48*32 + 32) + (32*7 + 7) = 1568 + 231 = 1799
	if got := out["parameter_count"].(float64); got != 1799 {
		t.Fatalf("parameter_count = %v, want 1799", got)
	}
	layers := out["layers"].([]any)
	first := layers[0].(map[string]any)
	last := layers[len(layers)-1].(map[string]any)
	if first["in"].(float64) != 48 || last["out"].(float64) != 7 {
		t.Fatalf("edges not forced: first=%v last=%v", first, last)
	}
}

func TestArchitectureEstimateInvalidHiddenLayer(t *testing.T) {
	h := newTestServer()

	for _, body := range []string{
		`{"hidden":[{"width":64,"activation":"banana"}]}`,
		`{"hidden":[{"width":0,"activation":"relu"}]}`,
		`{"hidden":[{"width":64,"activation":"relu","dropout":1.5}]}`,
		`{"hidden":[{"width":64,"activation":"relu","residual":true}]}`,
	} {
		code, out := postEstimate(t, h, body)
		if code != http.StatusOK {
			t.Fatalf("%s: code %d", body, code)
		}
		if out["valid"] != false || out["error"] == "" || out["error"] == nil {
			t.Fatalf("%s: want valid=false with an error, got valid=%v error=%v", body, out["valid"], out["error"])
		}
		// The math is still returned as a best-effort estimate.
		if _, ok := out["parameter_count"].(float64); !ok {
			t.Fatalf("%s: parameter_count missing from an invalid response", body)
		}
	}
}

func TestArchitectureEstimateBadBody(t *testing.T) {
	h := newTestServer()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/architecture/estimate", strings.NewReader("not json at all")))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed body should be 400, got %d", rr.Code)
	}
}

func TestArchitectureEstimateEmptyHidden(t *testing.T) {
	h := newTestServer()
	// No hidden layers is a valid (if useless) linear model: 48 -> 7.
	code, out := postEstimate(t, h, `{"hidden":[]}`)
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	if out["valid"] != true {
		t.Fatalf("empty hidden stack should be valid, got %v", out["error"])
	}
	if got := out["parameter_count"].(float64); got != 48*7+7 {
		t.Fatalf("parameter_count = %v, want %d", got, 48*7+7)
	}
}
