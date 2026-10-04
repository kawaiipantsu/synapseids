package obs

// ObserveBehavior records schema-bounded neural output and rich-input coverage.
func (m *Metrics) ObserveBehavior(attack, application int, rich bool) {
	if m == nil {
		return
	}
	if attack >= 0 && attack < len(m.attacks) {
		m.attacks[attack].Add(1)
	}
	if application >= 0 && application < len(m.applications) {
		m.applications[application].Add(1)
	}
	if rich {
		m.rich.Add(1)
	} else {
		m.legacy.Add(1)
	}
}

// BehaviorSnapshot returns fixed-cardinality counters, never IP/domain labels.
func (m *Metrics) BehaviorSnapshot() (attacks [19]uint64, applications [14]uint64, rich, legacy uint64) {
	if m == nil {
		return
	}
	for i := range attacks {
		attacks[i] = m.attacks[i].Load()
	}
	for i := range applications {
		applications[i] = m.applications[i].Load()
	}
	return attacks, applications, m.rich.Load(), m.legacy.Load()
}
