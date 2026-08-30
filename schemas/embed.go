// Package schemas embeds the frozen JSON data contracts so they ship inside the
// binary and can be served verbatim from the API. The typed accessors live in
// internal/schema; this package is just the bytes (PROJECT.md §8, §9, §17).
package schemas

import _ "embed"

// FlowFeaturesV1 is the raw schemas/features/flow-features-v1.json document.
//
//go:embed features/flow-features-v1.json
var FlowFeaturesV1 []byte

// TrafficClassesV1 is the raw schemas/outputs/traffic-classes-v1.json document.
//
//go:embed outputs/traffic-classes-v1.json
var TrafficClassesV1 []byte

// EventEnvelopeV1 is the raw schemas/events/event-envelope-v1.json document.
//
//go:embed events/event-envelope-v1.json
var EventEnvelopeV1 []byte
