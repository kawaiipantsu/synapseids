package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

// The shipped synapse.yaml must load identically to the shipped synapse.json.
func TestContribYAMLMatchesContribJSON(t *testing.T) {
	root := filepath.Join("..", "..", "contrib", "config")
	j, err := Load(filepath.Join(root, "synapse.json"))
	if err != nil {
		t.Fatalf("Load synapse.json: %v", err)
	}
	y, err := Load(filepath.Join(root, "synapse.yaml"))
	if err != nil {
		t.Fatalf("Load synapse.yaml: %v", err)
	}
	if !reflect.DeepEqual(j, y) {
		t.Fatalf("contrib synapse.yaml != synapse.json\n json: %+v\n yaml: %+v", j, y)
	}
}
