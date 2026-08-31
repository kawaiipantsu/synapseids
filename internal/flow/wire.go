package flow

// This file is the *only* sanctioned way to read and restore a Record's private
// accumulators. It exists so a flow record aggregated on a remote sensor can be
// serialized, shipped, and rebuilt on the daemon such that features.Extract
// yields bit-identical values on either side (issue #45).
//
// The layout is a released contract, exactly like flow-features-v1: never
// reorder or re-mean a field of Accumulators, and never change what
// RecordSchemaV1 names. A new need is RecordSchemaV2 (PROJECT.md §28.5-6).

// RecordSchemaV1 identifies the frozen flow-record field layout: the exported
// fields of Record plus the Accumulators below. A peer that declares a different
// schema is refused rather than misread.
const RecordSchemaV1 = "flow-record-v1"

// Accumulators is the running state a Record keeps privately so the feature
// layer can derive means, standard deviations and per-direction averages without
// retaining per-packet history.
//
// All sums are in the units the feature layer expects: packet sizes in bytes,
// TCP windows in the advertised unit, inter-arrival gaps in seconds.
type Accumulators struct {
	PktSizeSum   float64 // Σ total packet size
	PktSizeSumSq float64 // Σ (total packet size)²
	FwdSizeSum   float64 // Σ forward packet size
	BwdSizeSum   float64 // Σ backward packet size

	WindowSum   float64 // Σ advertised TCP window
	WindowCount uint64  // number of windows summed

	IATSum      float64 // Σ inter-arrival gap, seconds
	IATSumSq    float64 // Σ (inter-arrival gap)²
	IATMin      float64 // smallest gap seen, seconds
	IATMax      float64 // largest gap seen, seconds
	IATCount    uint64  // number of gaps summed
	FwdIATSum   float64 // Σ forward-direction gap, seconds
	BwdIATSum   float64 // Σ backward-direction gap, seconds
	FwdIATCount uint64
	BwdIATCount uint64
}

// Accumulators returns a copy of the record's private accumulator state.
func (r Record) Accumulators() Accumulators {
	return Accumulators{
		PktSizeSum:   r.pktSizeSum,
		PktSizeSumSq: r.pktSizeSumSq,
		FwdSizeSum:   r.fwdSizeSum,
		BwdSizeSum:   r.bwdSizeSum,
		WindowSum:    r.windowSum,
		WindowCount:  r.windowCount,
		IATSum:       r.iatSum,
		IATSumSq:     r.iatSumSq,
		IATMin:       r.iatMin,
		IATMax:       r.iatMax,
		IATCount:     r.iatCount,
		FwdIATSum:    r.fwdIATSum,
		BwdIATSum:    r.bwdIATSum,
		FwdIATCount:  r.fwdIATCount,
		BwdIATCount:  r.bwdIATCount,
	}
}

// WithAccumulators returns a copy of r with its private accumulator state
// replaced. It is the inverse of Accumulators and the only way to rebuild a
// Record that did not come from a local Table.
func (r Record) WithAccumulators(a Accumulators) Record {
	r.pktSizeSum = a.PktSizeSum
	r.pktSizeSumSq = a.PktSizeSumSq
	r.fwdSizeSum = a.FwdSizeSum
	r.bwdSizeSum = a.BwdSizeSum
	r.windowSum = a.WindowSum
	r.windowCount = a.WindowCount
	r.iatSum = a.IATSum
	r.iatSumSq = a.IATSumSq
	r.iatMin = a.IATMin
	r.iatMax = a.IATMax
	r.iatCount = a.IATCount
	r.fwdIATSum = a.FwdIATSum
	r.bwdIATSum = a.BwdIATSum
	r.fwdIATCount = a.FwdIATCount
	r.bwdIATCount = a.BwdIATCount
	return r
}

// WithDerivedKey returns a copy of r whose Key is recomputed from its
// initiator/responder endpoints. A record rebuilt from the wire carries the
// endpoints but not the normalized Key; this restores it deterministically via
// the same rule KeyOf applies to a packet.
//
// The observation scope (Key.Sensor) is preserved, not derived: no endpoint can
// say where the flow was seen. For a record off the wire it is whatever the
// caller has already stamped — the daemon sets it from the SYNPOIP session's
// sensor id once the record is decoded (issue #126).
func (r Record) WithDerivedKey() Record {
	sensor := r.Key.Sensor
	r.Key, _ = KeyOfEndpoints(r.InitiatorIP, r.InitiatorPort, r.ResponderIP, r.ResponderPort, r.Proto)
	r.Key.Sensor = sensor
	return r
}

// WithSensor returns a copy of r scoped to the observation point sensor. It is
// how a record that did not come from a local Table — one decoded from a
// `flow`-mode sensor's frame — is attributed to the sensor that produced it.
func (r Record) WithSensor(sensor string) Record {
	r.Key.Sensor = sensor
	return r
}

// Sensor reports the observation point this record was built at: a sensor id, or
// "" for traffic the daemon captured itself.
func (r Record) Sensor() string { return r.Key.Sensor }
