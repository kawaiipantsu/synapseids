package pcapoverip

import "testing"

func TestFormatAndParseSensorIdentityRoundTrip(t *testing.T) {
	in := SensorIdentity{
		SensorID:     "edge-1",
		Location:     "wan",
		AgentVersion: "0.1.0-dev",
		OSArch:       "freebsd/amd64",
	}
	prefix := FormatSessionPrefix(in)
	sid := newSessionID(prefix)
	if len(sid) > MaxSessionIDLen {
		t.Fatalf("session id %q exceeds MaxSessionIDLen (%d)", sid, MaxSessionIDLen)
	}
	got := ParseSensorIdentity(sid)
	if got != in {
		t.Fatalf("round trip: got %+v, want %+v (session id %q)", got, in, sid)
	}
}

func TestParseSensorIdentityLegacyPlainPrefix(t *testing.T) {
	// The form older sensors sent: SessionPrefix was just the sensor id.
	sid := newSessionID("opnsense-wan")
	got := ParseSensorIdentity(sid)
	if got.SensorID != "opnsense-wan" || got.Location != "" {
		t.Fatalf("legacy parse: got %+v", got)
	}
}

func TestParseSensorIdentityTrailingEmptyFields(t *testing.T) {
	prefix := FormatSessionPrefix(SensorIdentity{SensorID: "s1", Location: "lab"})
	if prefix != "s1|lab" {
		t.Fatalf("trailing empties not trimmed: %q", prefix)
	}
	got := ParseSensorIdentity(newSessionID(prefix))
	if got.SensorID != "s1" || got.Location != "lab" || got.AgentVersion != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestFormatSessionPrefixSanitises(t *testing.T) {
	got := FormatSessionPrefix(SensorIdentity{SensorID: "a|b\tc", Location: "  x  "})
	if got != "a_b_c|x" {
		t.Fatalf("sanitise: %q", got)
	}
}

func TestFormatSessionPrefixEmpty(t *testing.T) {
	if got := FormatSessionPrefix(SensorIdentity{}); got != "" {
		t.Fatalf("empty identity should format to empty, got %q", got)
	}
	if got := ParseSensorIdentity(""); (got != SensorIdentity{}) {
		t.Fatalf("empty session id should parse to zero identity, got %+v", got)
	}
}

func TestFormatSessionPrefixClipsLongFields(t *testing.T) {
	long := ""
	for range 200 {
		long += "x"
	}
	prefix := FormatSessionPrefix(SensorIdentity{SensorID: long, Location: long})
	if len(prefix) > sensorPrefixBudget {
		t.Fatalf("prefix %d bytes exceeds budget %d", len(prefix), sensorPrefixBudget)
	}
	if len(newSessionID(prefix)) > MaxSessionIDLen {
		t.Fatalf("session id exceeds MaxSessionIDLen with clipped fields")
	}
}

func TestStripSessionSuffix(t *testing.T) {
	cases := map[string]string{
		"edge-1-0123456789abcdef": "edge-1",                  // 16 hex → stripped
		"edge-1-session":          "edge-1",                  // RNG-fallback marker → stripped
		"edge-1":                  "edge-1",                  // nothing to strip
		"edge-1-0123456789abcdeg": "edge-1-0123456789abcdeg", // 'g' is not hex
		"edge-1-0123456789abcd":   "edge-1-0123456789abcd",   // 14 chars, not 16
	}
	for in, want := range cases {
		if got := stripSessionSuffix(in); got != want {
			t.Errorf("stripSessionSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}
