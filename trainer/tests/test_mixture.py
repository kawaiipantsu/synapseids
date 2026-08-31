"""Issue #34 — multi-dataset resolution, weighting, split-before-mix, warnings.

Every test here runs with numpy only: no torch, no scikit-learn.  ``Dataset.split``
stratifies when sklearn happens to be installed and falls back to a seeded
shuffle otherwise; nothing below depends on which path was taken.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np
import pytest

from synapse_trainer import mixture as mx
from synapse_trainer import recipe as rcp
from synapse_trainer import schema
from synapse_trainer.mixture import (
    DatasetIncompatible,
    DatasetResolutionError,
    MixtureError,
    apportion,
    build_mixture,
    format_plan,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
MULTI_RECIPE = EXAMPLES / "recipe.multi-dataset.json"
EXAMPLE_DATA = EXAMPLES / "data"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def write_dataset(path: Path, n: int = 60, seed: int = 0, labels=None, drop: str | None = None) -> Path:
    """Write a valid flow-features-v1 CSV with a unique per-row ``id`` column."""
    labels = labels or list(schema.CLASS_NAMES)
    rng = np.random.default_rng(seed)
    names = [c for c in schema.FEATURE_NAMES if c != drop]
    path.parent.mkdir(parents=True, exist_ok=True)
    tag = path.parent.name if path.name in ("dataset.csv", "data.csv") else path.stem
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id"] + names + ["label"])
        for i in range(n):
            w.writerow(
                [f"{tag}-{i:05d}"]
                + [f"{rng.uniform(0, 100):.4f}" for _ in names]
                + [labels[i % len(labels)]]
            )
    return path


def write_manifest(directory: Path, **over) -> Path:
    obj = {
        "id": over.pop("id", directory.name),
        "feature_schema": schema.FEATURE_SCHEMA,
        "output_schema": schema.OUTPUT_SCHEMA,
        "content_hash": "sha256:" + "ab" * 32,
    }
    obj.update(over)
    p = directory / "manifest.json"
    p.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    return p


def make_recipe(entries, *, seed: int = 1337, split=None, **over) -> rcp.Recipe:
    raw = {
        "name": "test-mix",
        "datasets": entries,
        "seed": seed,
        "split": split or {"train": 0.7, "val": 0.15, "test": 0.15},
    }
    raw.update(over)
    return rcp.from_dict(raw)


# ---------------------------------------------------------------------------
# 1. resolution — every documented fallback, in order
# ---------------------------------------------------------------------------


def test_resolves_flat_id_csv(tmp_path):
    write_dataset(tmp_path / "site" / "baseline.csv", n=20, seed=1)
    res = mx.resolve_dataset("site/baseline", tmp_path)
    assert res.csv_path == tmp_path / "site" / "baseline.csv"
    assert res.rule == "<data>/<id>.csv"


def test_resolves_id_dir_dataset_csv(tmp_path):
    write_dataset(tmp_path / "site" / "baseline" / "dataset.csv", n=20, seed=2)
    res = mx.resolve_dataset("site/baseline", tmp_path)
    assert res.rule == "<data>/<id>/dataset.csv"


def test_resolves_latest_version_dir_numerically(tmp_path):
    root = tmp_path / "site" / "baseline"
    for v in ("v2", "v9", "v10"):
        write_dataset(root / v / "dataset.csv", n=10, seed=3)
    res = mx.resolve_dataset("site/baseline", tmp_path)
    # natural sort: v10 beats v9, which a lexicographic sort would get wrong
    assert res.csv_path.parent.name == "v10"
    assert "latest version dir 'v10'" in res.rule


def test_resolves_any_single_csv_in_id_dir(tmp_path):
    write_dataset(tmp_path / "site" / "baseline" / "exported-flows.csv", n=10, seed=4)
    res = mx.resolve_dataset("site/baseline", tmp_path)
    assert res.rule == "<data>/<id>/*.csv"


def test_explicit_path_entry_wins_over_id(tmp_path):
    write_dataset(tmp_path / "site" / "baseline.csv", n=10, seed=5)
    pinned = write_dataset(tmp_path / "elsewhere" / "pinned.csv", n=10, seed=6)
    ref = rcp.DatasetRef(id="site/baseline", weight=1.0, path="elsewhere/pinned.csv")
    assert mx.resolve_dataset(ref, tmp_path).csv_path == pinned
    absolute = rcp.DatasetRef(id="site/baseline", weight=1.0, path=str(pinned))
    assert mx.resolve_dataset(absolute, tmp_path).csv_path == pinned


def test_missing_dataset_error_lists_every_path_tried(tmp_path):
    with pytest.raises(DatasetResolutionError) as exc:
        mx.resolve_dataset("site/nope", tmp_path)
    msg = str(exc.value)
    assert "site/nope.csv" in msg
    assert "site/nope/dataset.csv" in msg
    assert "latest version dir" in msg
    assert "site/nope/*.csv" in msg


def test_dataset_id_cannot_escape_the_data_root(tmp_path):
    with pytest.raises(DatasetResolutionError, match=r"\.\.'-free|relative"):
        mx.resolve_dataset("../secrets", tmp_path)


def test_manifest_supplies_content_hash(tmp_path):
    d = tmp_path / "site" / "baseline"
    write_dataset(d / "dataset.csv", n=20, seed=7)
    write_manifest(d, content_hash="sha256:" + "cd" * 32)
    res = mx.resolve_dataset("site/baseline", tmp_path)
    assert res.content_hash == "sha256:" + "cd" * 32


# ---------------------------------------------------------------------------
# 2. compatibility gate
# ---------------------------------------------------------------------------


def test_missing_feature_column_is_a_hard_error(tmp_path):
    write_dataset(tmp_path / "a.csv", n=20, seed=8)
    write_dataset(tmp_path / "b.csv", n=20, seed=9, drop="tcp_syn_count")
    recipe = make_recipe([{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.5}])
    with pytest.raises(MixtureError, match="tcp_syn_count"):
        build_mixture(recipe, tmp_path)


def test_manifest_declaring_a_foreign_schema_is_rejected(tmp_path):
    d = tmp_path / "b"
    write_dataset(tmp_path / "a.csv", n=20, seed=10)
    write_dataset(d / "dataset.csv", n=20, seed=11)
    write_manifest(d, feature_schema="flow-features-v2")
    recipe = make_recipe([{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.5}])
    with pytest.raises(DatasetIncompatible, match="flow-features-v2"):
        build_mixture(recipe, tmp_path)


def test_two_datasets_on_different_output_schemas_are_rejected(tmp_path):
    da, db = tmp_path / "a", tmp_path / "b"
    write_dataset(da / "dataset.csv", n=20, seed=12)
    write_dataset(db / "dataset.csv", n=20, seed=13)
    write_manifest(da, output_schema=schema.OUTPUT_SCHEMA)
    # a manifest that lies about the class contract must not be silently coerced
    write_manifest(db, output_schema="traffic-classes-v9")
    recipe = make_recipe([{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.5}])
    with pytest.raises(DatasetIncompatible):
        build_mixture(recipe, tmp_path)


# ---------------------------------------------------------------------------
# 3. weighting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "weights,total",
    [([0.7, 0.2, 0.1], 134), ([1 / 3, 1 / 3, 1 / 3], 100), ([0.5, 0.5], 7), ([1.0], 0)],
)
def test_apportion_sums_exactly(weights, total):
    got = apportion(weights, total)
    assert sum(got) == total
    assert all(g >= 0 for g in got)


def test_realised_weights_match_the_recipe_within_rounding(tmp_path):
    write_dataset(tmp_path / "big.csv", n=300, seed=20)
    write_dataset(tmp_path / "mid.csv", n=200, seed=21)
    write_dataset(tmp_path / "small.csv", n=100, seed=22)
    recipe = make_recipe(
        [
            {"id": "big", "weight": 0.7},
            {"id": "mid", "weight": 0.2},
            {"id": "small", "weight": 0.1},
        ]
    )
    m = build_mixture(recipe, tmp_path)
    target = m.target_train_rows
    assert sum(c.train_rows for c in m.components) == target == m.sizes()["train"]
    for c in m.components:
        # largest-remainder apportionment is off by at most one row
        assert abs(c.train_rows - c.weight * target) <= 1.0
        assert abs(c.effective_weight - c.weight) <= 1.0 / target + 1e-12


def test_upsamples_a_small_dataset_and_downsamples_a_large_one(tmp_path):
    write_dataset(tmp_path / "big.csv", n=400, seed=23)
    write_dataset(tmp_path / "tiny.csv", n=20, seed=24)
    recipe = make_recipe([{"id": "big", "weight": 0.3}, {"id": "tiny", "weight": 0.7}])
    m = build_mixture(recipe, tmp_path)
    by_id = {c.id: c for c in m.components}
    assert by_id["big"].resampling == "down"
    assert by_id["big"].duplicated_rows == 0
    assert by_id["tiny"].resampling == "up"
    assert by_id["tiny"].duplicated_rows > 0
    # up-sampling keeps every unique row at least once before duplicating any
    tiny_ids = [i for i in m.train_ids if i.startswith("tiny#")]
    assert len(set(tiny_ids)) == by_id["tiny"].split_sizes["train"]


def test_target_train_rows_override_is_honoured(tmp_path):
    write_dataset(tmp_path / "a.csv", n=50, seed=25)
    write_dataset(tmp_path / "b.csv", n=50, seed=26)
    recipe = make_recipe([{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.5}])
    m = build_mixture(recipe, tmp_path, target_train_rows=1000)
    assert m.sizes()["train"] == 1000


# ---------------------------------------------------------------------------
# 4. reproducibility
# ---------------------------------------------------------------------------


def _two_datasets(tmp_path):
    write_dataset(tmp_path / "a.csv", n=120, seed=30)
    write_dataset(tmp_path / "b.csv", n=80, seed=31)


def test_same_seed_gives_an_identical_mixture(tmp_path):
    _two_datasets(tmp_path)
    entries = [{"id": "a", "weight": 0.6}, {"id": "b", "weight": 0.4}]
    m1 = build_mixture(make_recipe(entries, seed=99), tmp_path)
    m2 = build_mixture(make_recipe(entries, seed=99), tmp_path)
    assert m1.train_ids == m2.train_ids
    assert m1.val_ids == m2.val_ids and m1.test_ids == m2.test_ids
    assert np.array_equal(m1.X_train, m2.X_train)
    assert np.array_equal(m1.y_train, m2.y_train)
    assert m1.to_json() == m2.to_json()


def test_a_different_seed_gives_a_different_mixture(tmp_path):
    _two_datasets(tmp_path)
    entries = [{"id": "a", "weight": 0.6}, {"id": "b", "weight": 0.4}]
    m1 = build_mixture(make_recipe(entries, seed=99), tmp_path)
    m2 = build_mixture(make_recipe(entries, seed=100), tmp_path)
    assert m1.train_ids != m2.train_ids
    assert set(m1.test_ids) != set(m2.test_ids)


def test_adding_a_dataset_does_not_reshuffle_the_others_splits(tmp_path):
    _two_datasets(tmp_path)
    write_dataset(tmp_path / "c.csv", n=40, seed=32)
    m1 = build_mixture(make_recipe([{"id": "a", "weight": 0.6}, {"id": "b", "weight": 0.4}]), tmp_path)
    m2 = build_mixture(
        make_recipe(
            [{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.3}, {"id": "c", "weight": 0.2}]
        ),
        tmp_path,
    )
    # per-dataset split seeds derive from (recipe seed, dataset id) only
    a_test_1 = {i for i in m1.test_ids if i.startswith("a#")}
    a_test_2 = {i for i in m2.test_ids if i.startswith("a#")}
    assert a_test_1 == a_test_2


def test_derive_seed_is_stable_and_id_specific():
    assert mx.derive_seed(1337, "split", "site/a") == mx.derive_seed(1337, "split", "site/a")
    assert mx.derive_seed(1337, "split", "site/a") != mx.derive_seed(1337, "split", "site/b")
    assert mx.derive_seed(1337, "split", "site/a") != mx.derive_seed(1338, "split", "site/a")
    assert mx.derive_seed(1337, "split", "site/a") != mx.derive_seed(1337, "mixture", "site/a")


# ---------------------------------------------------------------------------
# 5. the leakage rule — the correctness crux (PROJECT.md §14)
# ---------------------------------------------------------------------------


def test_no_leak_under_aggressive_upsampling(tmp_path):
    """Split-before-mix: no source row may appear on two sides of the split.

    ``tiny`` is up-sampled ~10x, which is exactly the situation that would
    duplicate rows across the boundary if the mixture were built first and split
    afterwards (see the companion test below).
    """
    write_dataset(tmp_path / "big.csv", n=400, seed=40)
    write_dataset(tmp_path / "tiny.csv", n=30, seed=41)
    recipe = make_recipe([{"id": "big", "weight": 0.1}, {"id": "tiny", "weight": 0.9}])
    m = build_mixture(recipe, tmp_path)

    tr, va, te = set(m.train_ids), set(m.val_ids), set(m.test_ids)
    assert tr and va and te
    assert tr.isdisjoint(va), sorted(tr & va)[:5]
    assert tr.isdisjoint(te), sorted(tr & te)[:5]
    assert va.isdisjoint(te), sorted(va & te)[:5]
    # and the up-sampling really did happen — otherwise the assertion is vacuous
    assert len(m.train_ids) > len(tr)
    assert {c.resampling for c in m.components} >= {"up"}
    # val/test are never resampled: no duplicates there at all
    assert len(m.val_ids) == len(va)
    assert len(m.test_ids) == len(te)


def test_naive_mix_then_split_would_leak(tmp_path):
    """Proof the leakage test above is not vacuous: the naive order *does* leak.

    This reproduces mix-then-split — resample the whole dataset first, split the
    mixture afterwards — and asserts the train/test row-id sets overlap.  If a
    future refactor swapped the order in :func:`build_mixture`, the previous
    test would fail exactly the way this one succeeds.
    """
    from synapse_trainer.dataset import load_csv

    write_dataset(tmp_path / "tiny.csv", n=30, seed=42)
    ds = load_csv(tmp_path / "tiny.csv")

    rng = np.random.default_rng(1337)
    # mix first: up-sample the *whole* dataset ~10x ...
    picks = np.concatenate(
        [np.arange(len(ds)), rng.choice(len(ds), size=9 * len(ds), replace=True)]
    )
    rng.shuffle(picks)
    # ... then split the mixture
    n = picks.size
    n_train = int(round(0.7 * n))
    n_val = int(round(0.15 * n))
    train_ids = {ds.ids[i] for i in picks[:n_train]}
    val_ids = {ds.ids[i] for i in picks[n_train : n_train + n_val]}
    test_ids = {ds.ids[i] for i in picks[n_train + n_val :]}

    assert train_ids & test_ids, "expected the naive order to leak — fixture too small?"
    assert train_ids & val_ids


def test_recorded_split_sizes_match_the_row_ids(tmp_path):
    _two_datasets(tmp_path)
    m = build_mixture(make_recipe([{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.5}]), tmp_path)
    sizes = m.sizes()
    assert sizes == {"train": len(m.train_ids), "val": len(m.val_ids), "test": len(m.test_ids)}
    assert sizes["train"] == m.X_train.shape[0] == m.y_train.size
    assert m.X_train.shape[1] == schema.INPUT_SIZE
    for c in m.components:
        assert sum(c.split_sizes.values()) == c.source_rows


# ---------------------------------------------------------------------------
# 6. warnings
# ---------------------------------------------------------------------------


def test_warns_on_a_dominant_class(tmp_path):
    write_dataset(tmp_path / "a.csv", n=200, seed=50, labels=["normal"] * 19 + ["scan"])
    m = build_mixture(make_recipe([{"id": "a", "weight": 1.0}]), tmp_path)
    assert any("of the training mixture" in w and "normal" in w for w in m.warnings)


def test_warns_on_a_class_absent_from_the_mixture(tmp_path):
    write_dataset(tmp_path / "a.csv", n=120, seed=51, labels=["normal", "scan"])
    m = build_mixture(make_recipe([{"id": "a", "weight": 1.0}]), tmp_path)
    assert any("dos_ddos" in w and "no rows" in w for w in m.warnings)


def test_warns_when_a_dataset_contributes_zero_rows(tmp_path):
    write_dataset(tmp_path / "a.csv", n=200, seed=52)
    write_dataset(tmp_path / "ignored.csv", n=50, seed=53)
    recipe = make_recipe([{"id": "a", "weight": 1.0}, {"id": "ignored", "weight": 0.0}])
    m = build_mixture(recipe, tmp_path)
    assert any("'ignored'" in w and "0 training rows" in w for w in m.warnings)
    by_id = {c.id: c for c in m.components}
    assert by_id["ignored"].train_rows == 0
    assert not any(i.startswith("ignored#") for i in m.train_ids)
    # ... but its val/test rows are still evaluated against
    assert any(i.startswith("ignored#") for i in m.test_ids + m.val_ids)


def test_warns_on_heavy_upsampling(tmp_path):
    write_dataset(tmp_path / "big.csv", n=500, seed=54)
    write_dataset(tmp_path / "tiny.csv", n=20, seed=55)
    m = build_mixture(
        make_recipe([{"id": "big", "weight": 0.2}, {"id": "tiny", "weight": 0.8}]), tmp_path
    )
    assert any("up-sampled" in w and "tiny" in w for w in m.warnings)


def test_empty_mixture_is_an_error(tmp_path):
    write_dataset(tmp_path / "a.csv", n=10, seed=56)
    recipe = make_recipe([{"id": "a", "weight": 1.0}])
    with pytest.raises(MixtureError, match="empty"):
        build_mixture(recipe, tmp_path, target_train_rows=0)


# ---------------------------------------------------------------------------
# 7. recorded provenance + the shipped example
# ---------------------------------------------------------------------------


def test_mixture_json_records_everything_a_bundle_needs(tmp_path):
    d = tmp_path / "site" / "baseline"
    write_dataset(d / "dataset.csv", n=100, seed=60)
    write_manifest(d, content_hash="sha256:" + "ef" * 32)
    write_dataset(tmp_path / "attacks.csv", n=60, seed=61)
    recipe = make_recipe(
        [{"id": "site/baseline", "weight": 0.8}, {"id": "attacks", "weight": 0.2}], seed=4242
    )
    m = build_mixture(recipe, tmp_path)
    j = m.to_json()

    assert j["strategy"] == mx.Mixture.STRATEGY
    assert j["split_before_mix"] is True
    assert j["resampled_splits"] == ["train"]
    assert j["seed"] == 4242
    assert j["sizes"] == m.sizes()
    assert set(j["label_counts"]) == {"train", "val", "test"}
    ids = [d_["id"] for d_ in j["datasets"]]
    assert ids == ["site/baseline", "attacks"]
    first = j["datasets"][0]
    assert first["content_hash"] == "sha256:" + "ef" * 32
    assert first["resolved_by"] == "<data>/<id>/dataset.csv"
    assert first["train_rows"] > 0 and first["effective_weight"] > 0
    assert first["split_seed"] == mx.derive_seed(4242, "split", "site/baseline")
    assert first["sample_seed"] == mx.derive_seed(4242, "mixture", "site/baseline")
    # a dataset without a manifest still appears, with a null hash
    assert j["datasets"][1]["content_hash"] is None
    # round-trips as JSON (it is written verbatim into training-recipe.json)
    assert json.loads(json.dumps(j))["sizes"] == m.sizes()

    sr = m.split_result()
    assert sr["seed"] == 4242
    assert set(sr["per_dataset"]) == {"site/baseline", "attacks"}
    assert sr["sizes"] == m.sizes()


def test_metadata_lists_every_contributing_dataset_id(tmp_path):
    from synapse_trainer.architecture import default_architecture
    from synapse_trainer.export import build_metadata, validate_metadata

    write_dataset(tmp_path / "a.csv", n=60, seed=62)
    write_dataset(tmp_path / "b.csv", n=60, seed=63)
    recipe = make_recipe([{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.5}])
    m = build_mixture(recipe, tmp_path)
    meta = build_metadata(
        name="test",
        arch=default_architecture(),
        training_dataset_ids=m.dataset_ids,
        model_hash="sha256:" + "00" * 32,
    )
    validate_metadata(meta)
    assert meta["training_dataset_ids"] == ["a", "b"]


def test_shipped_multi_dataset_example_resolves(tmp_path):
    recipe = rcp.load(MULTI_RECIPE)
    m = build_mixture(recipe, EXAMPLE_DATA)
    assert [c.id for c in m.components] == [
        "hq-copenhagen/baseline-2026-08",
        "thugs/lab-attacks-2026-08",
        "hq-copenhagen/reviewed-anomalies-2026-09",
    ]
    # the baseline resolves through the versioned layout, v10 not v9
    assert m.components[0].path.endswith("baseline-2026-08/v10/dataset.csv")
    assert all(c.content_hash and c.content_hash.startswith("sha256:") for c in m.components)
    assert set(m.train_ids).isdisjoint(m.test_ids)


def test_format_plan_is_readable(tmp_path):
    write_dataset(tmp_path / "a.csv", n=80, seed=64)
    write_dataset(tmp_path / "b.csv", n=40, seed=65)
    m = build_mixture(make_recipe([{"id": "a", "weight": 0.75}, {"id": "b", "weight": 0.25}]), tmp_path)
    text = format_plan(m, recipe_name="test-mix", data_root=str(tmp_path))
    assert "strategy:" in text and mx.Mixture.STRATEGY in text
    assert "TOTAL" in text
    for name in schema.CLASS_NAMES:
        assert name in text
    assert "warnings" in text
