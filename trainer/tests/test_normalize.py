import numpy as np
import pytest

from synapse_trainer.normalize import Normalizer, NormalizerError, fit
from synapse_trainer.schema import FEATURE_NAMES, INPUT_SIZE


@pytest.fixture
def X():
    rng = np.random.default_rng(1337)
    # column 3 is deliberately constant, to exercise the degenerate guards
    A = rng.normal(loc=5.0, scale=3.0, size=(400, INPUT_SIZE))
    A[:, 3] = 2.0
    return A


def test_standard_transforms_to_zero_mean_unit_std(X):
    n = fit(X, "standard")
    Xt = n.transform(X)
    assert np.allclose(Xt.mean(axis=0), 0.0, atol=1e-9)
    # constant column stays finite (std floored), others ~1
    std = Xt.std(axis=0)
    assert np.all(np.isfinite(Xt))
    assert np.allclose(np.delete(std, 3), 1.0, atol=1e-6)


def test_minmax_in_unit_interval(X):
    n = fit(X, "minmax")
    Xt = n.transform(X)
    assert Xt.min() >= -1e-9
    assert Xt.max() <= 1.0 + 1e-9
    assert np.all(np.isfinite(Xt))


def test_identity_is_a_noop(X):
    n = fit(X, "identity")
    Xt = n.transform(X)
    assert np.array_equal(Xt, X)


def test_json_round_trip_reproduces_transform(X):
    for method in ("standard", "minmax", "identity"):
        n = fit(X, method)
        j = n.to_json()
        n2 = Normalizer.from_json(j)
        assert np.allclose(n2.transform(X), n.transform(X), atol=1e-12)
        assert n2.to_json() == j


def test_per_feature_has_48_ordered_named_entries(X):
    for method, keys in (
        ("standard", {"index", "name", "mean", "std"}),
        ("minmax", {"index", "name", "min", "max"}),
        ("identity", {"index", "name", "mean", "std"}),
    ):
        j = fit(X, method).to_json()
        assert j["method"] == method
        assert j["feature_schema"] == "flow-features-v1"
        pf = j["per_feature"]
        assert len(pf) == INPUT_SIZE
        assert [e["index"] for e in pf] == list(range(INPUT_SIZE))
        assert [e["name"] for e in pf] == FEATURE_NAMES
        for e in pf:
            assert set(e.keys()) == keys


def test_never_emits_degenerate_params(X):
    s = fit(X, "standard").to_json()
    assert all(e["std"] > 0 for e in s["per_feature"])
    m = fit(X, "minmax").to_json()
    assert all(e["max"] > e["min"] for e in m["per_feature"])


def test_wrong_width_rejected():
    with pytest.raises(NormalizerError):
        fit(np.zeros((10, 12)), "standard")
