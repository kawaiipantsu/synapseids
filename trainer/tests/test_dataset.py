import csv
from pathlib import Path

import numpy as np
import pytest

from synapse_trainer import schema
from synapse_trainer.dataset import DatasetError, load_csv

EXAMPLE_CSV = Path(__file__).resolve().parents[1] / "examples" / "dataset.sample.csv"


def _write_csv(path: Path, n=200, seed=0, shuffle_cols=False, drop=None):
    rng = np.random.default_rng(seed)
    names = list(schema.FEATURE_NAMES)
    if shuffle_cols:
        rng.shuffle(names)
    if drop:
        names = [c for c in names if c != drop]
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(names + ["label"])
        for i in range(n):
            row = {nm: float(rng.uniform(0, 10)) for nm in schema.FEATURE_NAMES}
            w.writerow([row[c] for c in names] + [schema.CLASS_NAMES[i % 7]])


def test_loads_example_csv():
    ds = load_csv(EXAMPLE_CSV)
    assert ds.X.shape[1] == 48
    assert len(ds) == ds.X.shape[0]
    schema.check_compatible(ds.meta())
    assert sum(ds.label_counts().values()) == len(ds)


def test_column_order_is_normalised_to_schema(tmp_path):
    p = tmp_path / "d.csv"
    _write_csv(p, shuffle_cols=True, seed=3)
    ds = load_csv(p)
    assert ds.X.shape == (200, 48)


def test_missing_feature_column_is_an_error(tmp_path):
    p = tmp_path / "d.csv"
    _write_csv(p, drop="syn_ack_ratio")
    with pytest.raises(DatasetError):
        load_csv(p)


def test_integer_and_name_labels_both_work(tmp_path):
    p = tmp_path / "d.csv"
    with p.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(list(schema.FEATURE_NAMES) + ["label"])
        w.writerow([0.0] * 48 + ["scan"])
        w.writerow([0.0] * 48 + ["1"])
    ds = load_csv(p)
    assert list(ds.y) == [1, 1]


def test_split_is_reproducible_and_disjoint(tmp_path):
    p = tmp_path / "d.csv"
    _write_csv(p, n=300, seed=7)
    ds = load_csv(p)

    s1 = ds.split(seed=42)
    s2 = ds.split(seed=42)
    assert np.array_equal(s1.train, s2.train)
    assert np.array_equal(s1.test, s2.test)

    all_idx = np.concatenate([s1.train, s1.val, s1.test])
    assert sorted(all_idx.tolist()) == list(range(len(ds)))  # a partition
    assert set(s1.train).isdisjoint(s1.test)  # no test leakage
    assert set(s1.train).isdisjoint(s1.val)
    assert set(s1.val).isdisjoint(s1.test)
    assert s1.seed == 42
    assert abs(s1.train.size / len(ds) - 0.7) < 0.05


def test_split_rejects_bad_fractions(tmp_path):
    p = tmp_path / "d.csv"
    _write_csv(p, n=50)
    ds = load_csv(p)
    with pytest.raises(DatasetError):
        ds.split(seed=1, train=0.7, val=0.2, test=0.2)
