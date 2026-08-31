"""Load and split a labelled ``flow-features-v1`` dataset from CSV — pure numpy.

CSV layout: the 48 ``flow-features-v1`` columns (by their frozen schema name, in
any order) plus a ``label`` column holding a ``traffic-classes-v1`` class name
or its integer id.  Extra columns are ignored; a missing feature column is an
error.

Splitting is reproducible and recorded (PROJECT.md §14, §28.8): stratified via
scikit-learn when it is importable, otherwise a single seeded shuffle.  Train /
val / test index sets are always disjoint — the test split never leaks into
training.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from .schema import (
    CLASS_NAMES,
    FEATURE_NAMES,
    FEATURE_SCHEMA,
    INPUT_SIZE,
    OUTPUT_SCHEMA,
    OUTPUT_SIZE,
    class_id,
)

try:  # optional; only used to stratify
    from sklearn.model_selection import train_test_split as _sk_split

    _HAVE_SKLEARN = True
except Exception:  # pragma: no cover - depends on the environment
    _sk_split = None
    _HAVE_SKLEARN = False


class DatasetError(ValueError):
    pass


@dataclass
class Split:
    """The outcome of :meth:`Dataset.split` — indices into the dataset rows."""

    train: np.ndarray
    val: np.ndarray
    test: np.ndarray
    seed: int
    stratified: bool
    fractions: dict[str, float]

    def sizes(self) -> dict[str, int]:
        return {
            "train": int(self.train.size),
            "val": int(self.val.size),
            "test": int(self.test.size),
        }

    def to_json(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "stratified": self.stratified,
            "fractions": dict(self.fractions),
            "sizes": self.sizes(),
        }


@dataclass
class Dataset:
    """Feature matrix ``X`` (n, 48) and integer label vector ``y`` (n,)."""

    X: np.ndarray
    y: np.ndarray
    ids: list[str] = field(default_factory=list)
    source: str | None = None

    def __post_init__(self) -> None:
        self.X = np.asarray(self.X, dtype=np.float64)
        self.y = np.asarray(self.y, dtype=np.int64)
        if self.X.ndim != 2 or self.X.shape[1] != INPUT_SIZE:
            raise DatasetError(f"X must be (n, {INPUT_SIZE}), got {self.X.shape}")
        if self.y.shape != (self.X.shape[0],):
            raise DatasetError(f"y must be ({self.X.shape[0]},), got {self.y.shape}")
        if self.y.size and (self.y.min() < 0 or self.y.max() >= OUTPUT_SIZE):
            raise DatasetError(f"labels must be in 0..{OUTPUT_SIZE - 1}")

    def __len__(self) -> int:
        return int(self.X.shape[0])

    # ---- metadata ------------------------------------------------------

    def label_counts(self) -> dict[str, int]:
        counts = {name: 0 for name in CLASS_NAMES}
        for cls, n in zip(*np.unique(self.y, return_counts=True)):
            counts[CLASS_NAMES[int(cls)]] = int(n)
        return counts

    def meta(self) -> dict[str, Any]:
        return {
            "feature_schema": FEATURE_SCHEMA,
            "output_schema": OUTPUT_SCHEMA,
            "feature_count": INPUT_SIZE,
            "output_size": OUTPUT_SIZE,
            "num_flows": len(self),
            "label_counts": self.label_counts(),
            "source": self.source,
        }

    # ---- splitting ---------------------------------------------------

    def split(
        self,
        seed: int,
        train: float = 0.7,
        val: float = 0.15,
        test: float = 0.15,
    ) -> Split:
        total = train + val + test
        if abs(total - 1.0) > 1e-6:
            raise DatasetError(f"split fractions must sum to 1.0, got {total:g}")
        n = len(self)
        if n == 0:
            raise DatasetError("cannot split an empty dataset")
        fractions = {"train": float(train), "val": float(val), "test": float(test)}

        if _HAVE_SKLEARN and n >= OUTPUT_SIZE:
            try:
                idx = np.arange(n)
                tr, rest = _sk_split(
                    idx, train_size=train, random_state=seed, stratify=self.y
                )
                rel = val / (val + test) if (val + test) > 0 else 0.0
                if rest.size == 0 or rel in (0.0, 1.0):
                    va, te = (rest, np.array([], dtype=int)) if rel >= 1.0 else (np.array([], dtype=int), rest)
                else:
                    va, te = _sk_split(
                        rest, train_size=rel, random_state=seed, stratify=self.y[rest]
                    )
                return Split(np.sort(tr), np.sort(va), np.sort(te), seed, True, fractions)
            except ValueError:
                # too few samples in some class to stratify — fall through
                pass

        rng = np.random.default_rng(seed)
        perm = rng.permutation(n)
        n_train = int(round(train * n))
        n_val = int(round(val * n))
        n_train = min(n_train, n)
        n_val = min(n_val, n - n_train)
        tr = perm[:n_train]
        va = perm[n_train : n_train + n_val]
        te = perm[n_train + n_val :]
        return Split(np.sort(tr), np.sort(va), np.sort(te), seed, False, fractions)

    def subset(self, idx: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        return self.X[idx], self.y[idx]


def _resolve_csv(path: str | Path) -> Path:
    p = Path(path)
    if p.is_dir():
        for cand in ("dataset.csv", "data.csv", "flows.csv"):
            if (p / cand).is_file():
                return p / cand
        csvs = sorted(p.glob("*.csv"))
        if not csvs:
            raise DatasetError(f"no *.csv found in directory {p}")
        return csvs[0]
    if not p.is_file():
        raise DatasetError(f"dataset path not found: {p}")
    return p


def load_csv(path: str | Path, *, id_column: str | None = None) -> Dataset:
    """Read a dataset CSV into a :class:`Dataset`."""
    csv_path = _resolve_csv(path)
    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise DatasetError(f"{csv_path} is empty") from exc
        header = [h.strip() for h in header]
        col = {name: i for i, name in enumerate(header)}

        missing = [name for name in FEATURE_NAMES if name not in col]
        if missing:
            raise DatasetError(
                f"{csv_path}: missing {len(missing)} feature column(s): {missing[:5]}"
                + (" ..." if len(missing) > 5 else "")
            )
        if "label" not in col:
            raise DatasetError(f"{csv_path}: missing required 'label' column")

        feat_idx = [col[name] for name in FEATURE_NAMES]
        label_idx = col["label"]
        id_idx = col[id_column] if id_column and id_column in col else col.get("id")

        rows_X: list[list[float]] = []
        rows_y: list[int] = []
        ids: list[str] = []
        for lineno, row in enumerate(reader, start=2):
            if not row or all(c.strip() == "" for c in row):
                continue
            if len(row) < len(header):
                raise DatasetError(f"{csv_path}:{lineno}: expected {len(header)} columns, got {len(row)}")
            try:
                rows_X.append([float(row[i]) for i in feat_idx])
            except ValueError as exc:
                raise DatasetError(f"{csv_path}:{lineno}: non-numeric feature value: {exc}") from exc
            rows_y.append(class_id(row[label_idx].strip()))
            ids.append(row[id_idx].strip() if id_idx is not None else f"{csv_path.stem}:{lineno}")

    if not rows_X:
        raise DatasetError(f"{csv_path}: no data rows")

    return Dataset(
        X=np.array(rows_X, dtype=np.float64),
        y=np.array(rows_y, dtype=np.int64),
        ids=ids,
        source=str(csv_path),
    )
