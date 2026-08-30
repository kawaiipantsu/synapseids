package capture

import "testing"

func TestParseSpeed(t *testing.T) {
	cases := map[string]Speed{"": 1, "1": 1, "1x": 1, "0.5": 0.5, "2": 2, "10": 10, "max": SpeedMax, "0": SpeedMax}
	for in, want := range cases {
		got, err := ParseSpeed(in)
		if err != nil || got != want {
			t.Errorf("ParseSpeed(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseSpeed("fast"); err == nil {
		t.Errorf("ParseSpeed(\"fast\") should error")
	}
	if _, err := ParseSpeed("-2"); err == nil {
		t.Errorf("negative speed should error")
	}
}

func TestSpeedString(t *testing.T) {
	if SpeedMax.String() != "max" || Speed(2).String() != "2x" {
		t.Fatalf("Speed.String: %q %q", SpeedMax, Speed(2))
	}
}
