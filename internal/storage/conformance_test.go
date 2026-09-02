package storage_test

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/storage"
	"github.com/kawaiipantsu/synapseids/internal/storage/storagetest"
)

// Mem must satisfy the shared storage.Store contract. A durable backend
// (SQLite #53, ClickHouse #51) adds one test just like this against its own
// constructor, so every backend clears the same bar.
func TestMemSatisfiesStoreConformance(t *testing.T) {
	storagetest.RunConformance(t, func(flowCap, classCap int) storage.Store {
		return storage.NewMem(flowCap, classCap)
	})
}
