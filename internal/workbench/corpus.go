package workbench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// NumericRow is de-identified, already-computed training data. The API exports
// retained vectors; feature computation remains in the pipeline/extractor.
type NumericRow struct {
	Values       [160]float64 `json:"values"`
	Label        string       `json:"label"`
	Group        string       `json:"group"`
	Conversation string       `json:"conversation"`
	Time         float64      `json:"time"`
}

// ExportReviewed persists a new immutable version of explicit human labels.
func (s *Store) ExportReviewed(rows []NumericRow) (Corpus, error) {
	if len(rows) == 0 || len(rows) > 100000 {
		return Corpus{}, errors.New("no usable reviewed vectors, or export exceeds 100000 rows")
	}
	c := Corpus{ID: "reviewed-" + token(), Name: "Human-reviewed traffic", Task: "attack", Rows: len(rows), Classes: map[string]int{}, Source: "Explicit human confirmations and corrections", Limitations: "Only still-retained vectors reviewed in this daemon session are included. Ignored, unsure and unreviewed traffic is omitted."}
	groups := map[string]bool{}
	dir := filepath.Join(s.dir, "corpora")
	file, e := os.CreateTemp(dir, ".reviewed-*")
	if e != nil {
		return c, e
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	hash := sha256.New()
	enc := json.NewEncoder(io.MultiWriter(file, hash))
	for _, r := range rows {
		if !ValidID(r.Label) {
			return c, errors.New("invalid review label")
		}
		if e = enc.Encode(r); e != nil {
			return c, e
		}
		c.Classes[r.Label]++
		groups[r.Group] = true
	}
	c.Groups = len(groups)
	c.Digest = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if e = file.Sync(); e != nil {
		return c, e
	}
	if e = file.Close(); e != nil {
		return c, e
	}
	if e = os.Rename(file.Name(), filepath.Join(dir, c.ID+".jsonl")); e != nil {
		return c, e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return c, e
	}
	meta, e := os.CreateTemp(dir, ".manifest-*")
	if e != nil {
		return c, e
	}
	defer func() { _ = meta.Close(); _ = os.Remove(meta.Name()) }()
	if _, e = meta.Write(raw); e != nil {
		return c, e
	}
	if e = meta.Close(); e != nil {
		return c, e
	}
	e = os.Rename(meta.Name(), filepath.Join(dir, c.ID+".json"))
	return c, e
}
