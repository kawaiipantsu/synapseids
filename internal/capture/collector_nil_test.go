package capture

import "testing"

// A daemon with no `capture.collector` block holds a nil *Collector. If that is
// handed to an interface-typed field the interface is non-nil — it carries a
// type — so every "if provider != nil" guard passes and the first call lands on
// a nil receiver. That shipped as a panic serving GET /api/v1/sensors and
// /api/v1/sensors/topology. The methods are nil-safe; this pins it.
func TestNilCollectorReadsAsNoSensors(t *testing.T) {
	var c *Collector

	if got := c.Sensors(); len(got) != 0 {
		t.Fatalf("Sensors() on a nil collector = %v, want empty", got)
	}
	if _, ok := c.Sensor("anything"); ok {
		t.Fatal("Sensor() on a nil collector reported a hit")
	}
}
