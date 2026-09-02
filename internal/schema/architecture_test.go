package schema

import "testing"

// arch is a locked-edge (48 in / 7 out) Architecture with the given hidden stack.
func arch(h ...HiddenLayer) Architecture {
	return Architecture{InputSize: 48, OutputSize: 7, Hidden: h}
}

// The hand-computed numbers here are the SAME ones asserted by the trainer's
// trainer/tests/test_architecture.py (test_parameter_count_48_64_32_7_by_hand and
// test_batchnorm_adds_two_params_per_unit) so the UI estimate agrees with what
// the trainer will report.
func TestArchitectureParameterMath_48_64_32_7(t *testing.T) {
	a := arch(HiddenLayer{Width: 64}, HiddenLayer{Width: 32})

	// Dense 48->64 : 48*64 + 64 = 3136
	// Dense 64->32 : 64*32 + 32 = 2080
	// Dense 32->7  : 32*7  + 7  =  231  → total 5447
	const wantParams = 3136 + 2080 + 231
	if wantParams != 5447 {
		t.Fatalf("hand arithmetic drifted: %d != 5447", wantParams)
	}
	if got := a.ParameterCount(); got != wantParams {
		t.Fatalf("ParameterCount() = %d, want %d", got, wantParams)
	}
	if got := a.ApproxBytes(); got != wantParams*4 {
		t.Fatalf("ApproxBytes() = %d, want %d", got, wantParams*4)
	}
	// rough FLOPs = 2*(48*64 + 64*32 + 32*7) = 10688
	const wantFLOPs = 2 * (48*64 + 64*32 + 32*7)
	if wantFLOPs != 10688 {
		t.Fatalf("hand arithmetic drifted: %d != 10688", wantFLOPs)
	}
	if got := a.RoughFLOPs(); got != wantFLOPs {
		t.Fatalf("RoughFLOPs() = %d, want %d", got, wantFLOPs)
	}
}

// aeArch is a locked-edge (48 in / 48 out) autoencoder Architecture — the
// flow-anomaly-v1 family (ADR 0037). The hand-computed numbers here match the
// trainer's trainer/tests/test_architecture.py autoencoder case.
func aeArch(h ...HiddenLayer) Architecture {
	return Architecture{InputSize: 48, OutputSize: 48, Hidden: h}
}

func TestArchitectureParameterMath_Autoencoder_48_32_16_32_48(t *testing.T) {
	a := aeArch(HiddenLayer{Width: 32}, HiddenLayer{Width: 16}, HiddenLayer{Width: 32})

	// Dense 48->32 : 48*32 + 32 = 1568
	// Dense 32->16 : 32*16 + 16 =  528
	// Dense 16->32 : 16*32 + 32 =  544
	// Dense 32->48 : 32*48 + 48 = 1584  → total 4224
	const wantParams = 1568 + 528 + 544 + 1584
	if wantParams != 4224 {
		t.Fatalf("hand arithmetic drifted: %d != 4224", wantParams)
	}
	if got := a.ParameterCount(); got != wantParams {
		t.Fatalf("ParameterCount() = %d, want %d", got, wantParams)
	}
	// rough FLOPs = 2*(48*32 + 32*16 + 16*32 + 32*48) = 8192
	const wantFLOPs = 2 * (48*32 + 32*16 + 16*32 + 32*48)
	if wantFLOPs != 8192 {
		t.Fatalf("hand arithmetic drifted: %d != 8192", wantFLOPs)
	}
	if got := a.RoughFLOPs(); got != wantFLOPs {
		t.Fatalf("RoughFLOPs() = %d, want %d", got, wantFLOPs)
	}
	if err := ValidateArchitectureForFamily(FamilyAnomalyV1, a); err != nil {
		t.Fatalf("autoencoder architecture rejected: %v", err)
	}
}

func TestArchitectureBatchNormAddsTwoParamsPerUnit(t *testing.T) {
	plain := arch(HiddenLayer{Width: 64}, HiddenLayer{Width: 32})
	bn := arch(HiddenLayer{Width: 64, BatchNorm: true}, HiddenLayer{Width: 32})

	if d := bn.ParameterCount() - plain.ParameterCount(); d != 2*64 {
		t.Fatalf("batchnorm delta = %d, want %d", d, 2*64)
	}
	if got := bn.ParameterCount(); got != 5575 { // 5447 + 2*64
		t.Fatalf("bn ParameterCount() = %d, want 5575", got)
	}
	// BatchNorm changes no Dense shapes, so FLOPs are unchanged.
	if plain.RoughFLOPs() != bn.RoughFLOPs() {
		t.Fatalf("batchnorm changed RoughFLOPs: %d -> %d", plain.RoughFLOPs(), bn.RoughFLOPs())
	}
}

func TestArchitectureLayerBreakdown(t *testing.T) {
	a := arch(HiddenLayer{Width: 64, BatchNorm: true}, HiddenLayer{Width: 32})
	rows := a.LayerBreakdown()

	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	sum := 0
	for _, r := range rows {
		sum += r.Params
	}
	if sum != a.ParameterCount() {
		t.Fatalf("breakdown sums to %d, ParameterCount() = %d", sum, a.ParameterCount())
	}
	if rows[0].In != 48 || rows[0].Out != 64 || rows[0].Params != 48*64+64+2*64 {
		t.Fatalf("row 0 = %+v", rows[0])
	}
	if rows[2].Name != "output" || rows[2].In != 32 || rows[2].Out != 7 || rows[2].Params != 32*7+7 {
		t.Fatalf("output row = %+v", rows[2])
	}
}

func TestValidateArchitectureHiddenStack(t *testing.T) {
	if err := ValidateArchitecture(arch(HiddenLayer{Width: 64, Activation: "relu"})); err != nil {
		t.Fatalf("valid hidden stack rejected: %v", err)
	}
	// An empty activation string defaults to relu, like the trainer.
	if err := ValidateArchitecture(arch(HiddenLayer{Width: 64})); err != nil {
		t.Fatalf("default activation rejected: %v", err)
	}
	// residual is fine when the previous width matches: input 48 -> 48.
	if err := ValidateArchitecture(arch(HiddenLayer{Width: 48, Activation: "relu", Residual: true})); err != nil {
		t.Fatalf("residual 48->48 rejected: %v", err)
	}
	// ...and mid-stack, 32 -> 32.
	if err := ValidateArchitecture(arch(
		HiddenLayer{Width: 32, Activation: "relu"},
		HiddenLayer{Width: 32, Activation: "relu", Residual: true},
	)); err != nil {
		t.Fatalf("residual 32->32 rejected: %v", err)
	}

	bad := map[string]Architecture{
		"zero width":              arch(HiddenLayer{Width: 0, Activation: "relu"}),
		"negative width":          arch(HiddenLayer{Width: -8, Activation: "relu"}),
		"dropout == 1":            arch(HiddenLayer{Width: 8, Activation: "relu", Dropout: 1}),
		"dropout negative":        arch(HiddenLayer{Width: 8, Activation: "relu", Dropout: -0.1}),
		"unknown activation":      arch(HiddenLayer{Width: 8, Activation: "gelu"}),
		"residual width mismatch": arch(HiddenLayer{Width: 64, Activation: "relu", Residual: true}),
	}
	for name, a := range bad {
		if err := ValidateArchitecture(a); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
}
