package pcapoverip

import "strings"

// SensorIdentity is a reverse-connecting sensor's self-description.
//
// On a reverse connection the accepting daemon sends the ClientHello (PROTOCOL.md
// §6), so the sensor cannot announce itself in the hello metadata — it answers
// with a ServerAccept and its identity rides in the accept's SessionID field.
// FormatSessionPrefix packs an identity into the SessionPrefix a sensor's
// ServerConfig carries; ParseSensorIdentity is what the daemon collector runs on
// the SessionID it reads back. Neither changes a byte of the wire format:
// SessionID is already a free-form string capped at MaxSessionIDLen.
type SensorIdentity struct {
	SensorID     string // stable sensor id (flag / SYNAPSE_SENSOR_ID / host-derived)
	Location     string // deployment label ("wan", "dc-1", …)
	AgentVersion string // synapse-sensor build version, for diagnostics
	OSArch       string // GOOS/GOARCH, for diagnostics
}

// sensorIDFieldSep separates the packed fields. It is stripped from every field
// value before packing so the split is unambiguous.
const sensorIDFieldSep = "|"

// maxSensorIDField bounds a single packed field so a hostile sensor cannot spend
// the whole SessionID budget on one value.
const maxSensorIDField = 48

// sensorPrefixBudget is how much of MaxSessionIDLen the packed prefix may use.
// Serve appends "-" + 16 hex characters (newSessionID); the slack covers that
// plus a little headroom.
const sensorPrefixBudget = MaxSessionIDLen - 24

// FormatSessionPrefix renders id as a compact, log-safe session-id prefix of the
// form "sensor_id|location|agent_version|os/arch". Trailing empty fields are
// dropped, every field is sanitised of the separator and control bytes and
// clipped to maxSensorIDField, and the whole result is clipped to
// sensorPrefixBudget. An all-empty identity yields "".
func FormatSessionPrefix(id SensorIdentity) string {
	fields := []string{
		sanitiseSensorField(id.SensorID),
		sanitiseSensorField(id.Location),
		sanitiseSensorField(id.AgentVersion),
		sanitiseSensorField(id.OSArch),
	}
	for len(fields) > 0 && fields[len(fields)-1] == "" {
		fields = fields[:len(fields)-1]
	}
	if len(fields) == 0 {
		return ""
	}
	out := strings.Join(fields, sensorIDFieldSep)
	if len(out) > sensorPrefixBudget {
		out = out[:sensorPrefixBudget]
	}
	return out
}

// ParseSensorIdentity recovers a SensorIdentity from a full session id. It
// strips the random "-<hex>" (or "-session") suffix newSessionID appends, then
// splits the remaining prefix on the field separator. A prefix with no
// separator is taken as a bare sensor id, so the plain "<sensor-id>-<hex>"
// session ids older sensors sent still parse.
func ParseSensorIdentity(sessionID string) SensorIdentity {
	prefix := stripSessionSuffix(sessionID)
	if prefix == "" {
		return SensorIdentity{}
	}
	parts := strings.Split(prefix, sensorIDFieldSep)
	id := SensorIdentity{SensorID: parts[0]}
	if len(parts) > 1 {
		id.Location = parts[1]
	}
	if len(parts) > 2 {
		id.AgentVersion = parts[2]
	}
	if len(parts) > 3 {
		id.OSArch = parts[3]
	}
	return id
}

// stripSessionSuffix removes a single trailing "-<16 lowercase hex>" or
// "-session" group, which is exactly what newSessionID appends to a prefix.
func stripSessionSuffix(s string) string {
	i := strings.LastIndexByte(s, '-')
	if i < 0 {
		return s
	}
	switch suffix := s[i+1:]; {
	case suffix == "session":
		return s[:i]
	case len(suffix) == 16 && isLowerHex(suffix):
		return s[:i]
	default:
		return s
	}
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return len(s) > 0
}

// sanitiseSensorField replaces the field separator and any control byte with
// '_', then clips the field to maxSensorIDField. The result is safe to embed in
// a log line and to split on the separator.
func sanitiseSensorField(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(v) && b.Len() < maxSensorIDField; i++ {
		c := v[i]
		if c < 0x20 || c == 0x7f || c == sensorIDFieldSep[0] {
			b.WriteByte('_')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
