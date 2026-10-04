package schema

import (
	"encoding/json"

	"github.com/kawaiipantsu/synapseids/schemas"
)

var behaviorV1 FeatureSchema
var attackV2, applicationV1 OutputSchema

func init() {
	if err := json.Unmarshal(schemas.TrafficBehaviorV1, &behaviorV1); err != nil {
		panic(err)
	}
	if err := json.Unmarshal(schemas.AttackClassesV2, &attackV2); err != nil {
		panic(err)
	}
	if err := json.Unmarshal(schemas.ApplicationClassesV1, &applicationV1); err != nil {
		panic(err)
	}
	if behaviorV1.InputSize != 160 || len(behaviorV1.Features) != 160 {
		panic("invalid behavior schema")
	}
	for i, f := range behaviorV1.Features {
		if f.Index != i {
			panic("invalid behavior index")
		}
	}
	for _, s := range []OutputSchema{attackV2, applicationV1} {
		if len(s.Classes) != s.OutputSize {
			panic("invalid output schema")
		}
		for i, c := range s.Classes {
			if c.Index != i {
				panic("invalid output index")
			}
		}
	}
}

// BehaviorV1 returns the temporal and protocol feature contract.
func BehaviorV1() FeatureSchema { return behaviorV1 }

// AttackV2 returns the detailed threat output contract.
func AttackV2() OutputSchema { return attackV2 }

// ApplicationV1 returns the independent application output contract.
func ApplicationV1() OutputSchema { return applicationV1 }

// FeaturesFor resolves a known immutable feature schema.
func FeaturesFor(id string) (FeatureSchema, bool) {
	switch id {
	case "flow-features-v1":
		return FlowFeaturesV1(), true
	case "traffic-behavior-v1":
		return BehaviorV1(), true
	}
	return FeatureSchema{}, false
}
