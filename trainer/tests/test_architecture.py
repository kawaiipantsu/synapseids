import pytest

from synapse_trainer.architecture import (
    ANOMALY_FAMILY,
    Architecture,
    ArchitectureError,
    HiddenLayer,
    default_architecture,
)


def test_parameter_count_48_64_32_7_by_hand():
    # Dense 48->64 : 48*64 + 64 = 3136
    # Dense 64->32 : 64*32 + 32 = 2080
    # Dense 32->7  : 32*7  + 7  =  231
    arch = Architecture(hidden=[HiddenLayer(64), HiddenLayer(32)])
    assert arch.parameter_count() == 3136 + 2080 + 231 == 5447
    assert arch.estimated_size_bytes() == 5447 * 4
    # rough FLOPs = 2*(48*64 + 64*32 + 32*7) = 10688
    assert arch.rough_flops() == 2 * (48 * 64 + 64 * 32 + 32 * 7) == 10688
    assert arch.widths() == [48, 64, 32, 7]


def test_batchnorm_adds_two_params_per_unit():
    plain = Architecture(hidden=[HiddenLayer(64), HiddenLayer(32)])
    bn = Architecture(hidden=[HiddenLayer(64, batchnorm=True), HiddenLayer(32)])
    assert bn.parameter_count() - plain.parameter_count() == 2 * 64


def test_locked_input_output():
    with pytest.raises(ArchitectureError):
        Architecture(hidden=[HiddenLayer(8)], input_size=56)
    with pytest.raises(ArchitectureError):
        Architecture(hidden=[HiddenLayer(8)], output_size=5)


def _ae(*widths: int) -> Architecture:
    return Architecture(
        hidden=[HiddenLayer(w) for w in widths],
        output_size=48,
        family=ANOMALY_FAMILY,
    )


def test_anomaly_family_locks_output_at_48():
    # The classifier family rejects a 48-wide output; the anomaly family requires it.
    with pytest.raises(ArchitectureError):
        Architecture(hidden=[HiddenLayer(16)], output_size=48)
    for bad in (7, 47, 49):
        with pytest.raises(ArchitectureError):
            Architecture(hidden=[HiddenLayer(16)], output_size=bad, family=ANOMALY_FAMILY)
    with pytest.raises(ArchitectureError):
        Architecture(hidden=[HiddenLayer(16)], output_size=48, family="flow-anomaly-v9")


def test_autoencoder_parameter_math_48_32_16_32_48_by_hand():
    # These are the SAME hand-computed numbers asserted by the Go mirror
    # internal/schema/architecture_test.go TestArchitectureParameterMath_Autoencoder_48_32_16_32_48.
    # Dense 48->32 : 48*32 + 32 = 1568
    # Dense 32->16 : 32*16 + 16 =  528
    # Dense 16->32 : 16*32 + 32 =  544
    # Dense 32->48 : 32*48 + 48 = 1584
    arch = _ae(32, 16, 32)
    assert arch.parameter_count() == 1568 + 528 + 544 + 1584 == 4224
    assert arch.rough_flops() == 2 * (48 * 32 + 32 * 16 + 16 * 32 + 32 * 48) == 8192
    assert arch.widths() == [48, 32, 16, 32, 48]
    assert arch.to_json()["output_size"] == 48
    assert "family" not in arch.to_json()  # family rides at the metadata top level


def test_default_architecture_per_family():
    assert default_architecture().output_size == 7
    ae = default_architecture(ANOMALY_FAMILY)
    assert ae.family == ANOMALY_FAMILY
    assert ae.widths() == [48, 32, 16, 32, 48]


def test_hidden_layer_validation():
    with pytest.raises(ArchitectureError):
        HiddenLayer(0)
    with pytest.raises(ArchitectureError):
        HiddenLayer(16, dropout=1.0)
    with pytest.raises(ArchitectureError):
        HiddenLayer(16, dropout=-0.1)
    with pytest.raises(ArchitectureError):
        HiddenLayer(16, activation="banana")


def test_residual_requires_matching_previous_width():
    # first hidden layer: previous width is the input (48), so residual needs width 48
    with pytest.raises(ArchitectureError):
        Architecture(hidden=[HiddenLayer(64, residual=True)])
    Architecture(hidden=[HiddenLayer(48, residual=True)])  # ok
    # mid-stack: 32 -> 32 residual is fine, 32 -> 16 residual is not
    Architecture(hidden=[HiddenLayer(32), HiddenLayer(32, residual=True)])
    with pytest.raises(ArchitectureError):
        Architecture(hidden=[HiddenLayer(32), HiddenLayer(16, residual=True)])


def test_json_round_trip():
    arch = default_architecture()
    again = Architecture.from_json(arch.to_json())
    assert again.to_json() == arch.to_json()
    assert again.parameter_count() == arch.parameter_count()

    d = arch.to_json()
    assert d["input_size"] == 48 and d["output_size"] == 7
    assert d["hidden"][0].keys() == {"width", "activation", "dropout", "batchnorm", "residual"}
    # metadata uses the identical shape
    assert arch.to_metadata_dict() == d

    hl = HiddenLayer(64, "gelu", dropout=0.25, batchnorm=True, residual=False)
    assert HiddenLayer.from_json(hl.to_json()).to_json() == hl.to_json()
