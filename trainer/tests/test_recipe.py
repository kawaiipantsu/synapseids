import json
from pathlib import Path

import pytest

from synapse_trainer import recipe as R

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "recipe.json"


def _base(**over):
    d = {
        "datasets": [{"id": "a", "weight": 0.6}, {"id": "b", "weight": 0.4}],
        "split": {"train": 0.7, "val": 0.15, "test": 0.15},
    }
    d.update(over)
    return d


def test_defaults_are_filled_in():
    rc = R.from_dict({"datasets": [{"id": "only", "weight": 1.0}]})
    assert rc.optimizer == "adam"
    assert rc.lr == 1e-3
    assert rc.batch_size == 256
    assert rc.epochs == 50
    assert rc.scheduler == "cosine"
    assert rc.class_weighting == "balanced"
    assert rc.normalizer == "standard"
    assert rc.seed == 1337
    assert rc.split == {"train": 0.7, "val": 0.15, "test": 0.15}
    assert rc.early_stopping.patience == 8
    assert rc.early_stopping.metric == "val_loss"
    # a default hidden stack exists so inspect-arch works
    assert rc.architecture.parameter_count() > 0


def test_weight_sum_validation():
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(datasets=[{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.4}]))
    # ~1.0 within tolerance is fine
    R.from_dict(_base(datasets=[{"id": "a", "weight": 0.3333333}, {"id": "b", "weight": 0.6666667}]))


def test_split_sum_validation():
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(split={"train": 0.7, "val": 0.2, "test": 0.2}))
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(split={"train": 0.8, "val": 0.2}))  # missing test key


def test_rejects_bad_enums_and_numbers():
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(optimizer="lbfgs"))
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(scheduler="triangular"))
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(lr=0))
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(epochs=-1))
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(early_stopping={"patience": 3, "metric": "auc"}))


def test_empty_datasets_rejected():
    with pytest.raises(R.RecipeError):
        R.from_dict({"datasets": []})


def test_resolved_json_echoes_seed_split_and_datasets():
    rc = R.from_dict(_base(seed=99))
    j = rc.to_json()
    assert j["seed"] == 99
    assert j["split"] == {"train": 0.7, "val": 0.15, "test": 0.15}
    assert j["datasets"] == [{"id": "a", "weight": 0.6}, {"id": "b", "weight": 0.4}]
    assert j["architecture"]["input_size"] == 48
    assert j["architecture"]["output_size"] == 7
    # round-trips
    assert R.from_dict(j).to_json() == j


def test_example_recipe_parses():
    rc = R.load(EXAMPLE)
    assert rc.name == "flow-classifier-baseline"
    assert rc.dataset_ids == ["thugs/lab-attacks-2026-08", "hq-copenhagen/baseline-2026-08"]
    assert rc.architecture.widths() == [48, 64, 32, 7]
    assert rc.architecture.parameter_count() == 5575  # with the batchnorm on layer 0


# ---- reconstruction objective (ADR 0037) ---------------------------------


def test_objective_defaults_to_classification():
    rc = R.from_dict(_base())
    assert rc.objective == "classification"
    assert rc.architecture.family == "flow-classifier-v1"
    assert rc.to_json()["objective"] == "classification"


def test_reconstruction_objective_selects_the_anomaly_family():
    rc = R.from_dict(_base(objective="reconstruction"))
    assert rc.objective == "reconstruction"
    assert rc.architecture.family == "flow-anomaly-v1"
    assert rc.architecture.output_size == 48
    assert rc.architecture.widths() == [48, 32, 16, 32, 48]
    # class weighting has no meaning here — an unset value resolves to "none".
    assert rc.class_weighting == "none"
    j = rc.to_json()
    assert j["objective"] == "reconstruction"
    assert j["architecture"]["output_size"] == 48
    assert R.from_dict(j).to_json() == j


def test_reconstruction_rejects_class_weighting_and_wrong_es_metric():
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(objective="reconstruction", class_weighting="balanced"))
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(objective="reconstruction", early_stopping={"metric": "val_accuracy"}))


def test_rejects_unknown_objective():
    with pytest.raises(R.RecipeError):
        R.from_dict(_base(objective="ranking"))


def test_example_anomaly_recipe_parses():
    rc = R.load(Path(__file__).resolve().parents[1] / "examples" / "anomaly-recipe.json")
    assert rc.objective == "reconstruction"
    assert rc.architecture.family == "flow-anomaly-v1"
    assert rc.architecture.parameter_count() == 4224
