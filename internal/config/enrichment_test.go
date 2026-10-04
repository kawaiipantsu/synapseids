package config

import (
	"testing"
	"time"
)

func TestEnrichmentConfig(t *testing.T) {
	e := Default().Enrichment
	if e.Enabled {
		t.Fatal("external lookups must be opt-in")
	}
	e.Enabled = true
	if err := ValidateEnrichment(e); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Enrichment){
		func(c *Enrichment) { c.GeoURL = "file:///etc/passwd" },
		func(c *Enrichment) { c.GeoURL = "https://user:secret@example.test" },
		func(c *Enrichment) { c.Resolver = "example.test:53" },
		func(c *Enrichment) { c.MaxEntries = 1000000 },
		func(c *Enrichment) { c.Timeout = Duration(time.Hour) },
		func(c *Enrichment) { c.NegativeTTL = Duration(24 * time.Hour) },
	} {
		bad := e
		mutate(&bad)
		if ValidateEnrichment(bad) == nil {
			t.Errorf("accepted invalid config: %+v", bad)
		}
	}
}
