package model

import "github.com/kawaiipantsu/synapseids/internal/schema"

// Metadata is the full metadata.json descriptor of a model bundle
// (PROJECT.md §11). It is the contract with synapse-trainer; these field names
// and JSON tags must stay in lockstep with the trainer's writer.
type Metadata struct {
	ModelID            string              `json:"model_id"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	Family             string              `json:"family"`
	FeatureSchema      string              `json:"feature_schema"`
	InputSize          int                 `json:"input_size"`
	OutputSchema       string              `json:"output_schema"`
	OutputSize         int                 `json:"output_size"`
	Architecture       schema.Architecture `json:"architecture"`
	TrainingDatasetIDs []string            `json:"training_dataset_ids"`
	CreatedAt          string              `json:"created_at"`
	TrainerVersion     string              `json:"trainer_version"`
	ParameterCount     int64               `json:"parameter_count"`
	ModelHash          string              `json:"model_hash"`

	// DerivedFrom is the model_id of the parent this model was fine-tuned or
	// derived from, for the registry lineage tree (PROJECT.md §15, §19.12). It is
	// an additive, optional field: the trainer may populate it later, and an
	// absent value marks a lineage root. It is not part of the frozen validation
	// contract and Validate does not check it.
	DerivedFrom string `json:"derived_from,omitempty"`

	// Anomaly is the reconstruction-error calibration of a flow-anomaly-v1
	// autoencoder bundle (ADR 0037). Additive and optional like DerivedFrom;
	// present only for the anomaly family and not checked by Validate.
	Anomaly *AnomalyCalibration `json:"anomaly,omitempty"`
}

// AnomalyCalibration records how a trained flow-anomaly-v1 model's
// reconstruction error is distributed over its training NORMAL set, in the
// normalized input space the network sees. The runtime turns a raw error into a
// bounded score with ErrorPercentiles["p50"] and flags Exceeds at Threshold
// (default: the p99 percentile). All fields optional — a bundle with no
// calibration still scores, just without a real threshold (ADR 0037).
type AnomalyCalibration struct {
	// Space is the measurement space, always "normalized" for now.
	Space string `json:"space,omitempty"`
	// ErrorPercentiles maps percentile labels ("p50","p90","p95","p99","max")
	// to the reconstruction error at that percentile over the NORMAL set.
	ErrorPercentiles map[string]float64 `json:"error_percentiles,omitempty"`
	// Threshold is the suggested alerting threshold on raw reconstruction error.
	Threshold float64 `json:"threshold,omitempty"`
}

// BundleMeta projects the frozen-contract subset that schema.ValidateBundle
// checks.
func (m Metadata) BundleMeta() schema.BundleMeta {
	return schema.BundleMeta{
		Family:        m.Family,
		FeatureSchema: m.FeatureSchema,
		InputSize:     m.InputSize,
		OutputSchema:  m.OutputSchema,
		OutputSize:    m.OutputSize,
	}
}

// NormalizerSpec is normalizer.json: a method plus, for a fitted method, one
// entry per feature in flow-features-v1 order.
type NormalizerSpec struct {
	Method        string        `json:"method"` // "standard" | "minmax" | "identity"
	FeatureSchema string        `json:"feature_schema"`
	PerFeature    []NormFeature `json:"per_feature"`
}

// NormFeature holds one feature's fitted normalization constants. A "standard"
// spec populates Mean and Std; a "minmax" spec populates Min and Max.
type NormFeature struct {
	Index int     `json:"index"`
	Name  string  `json:"name"`
	Mean  float64 `json:"mean"`
	Std   float64 `json:"std"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
}
