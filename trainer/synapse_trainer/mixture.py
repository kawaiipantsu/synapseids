"""Issue #34 — resolve a recipe's ``datasets[]`` into one weighted training mixture.

A recipe may combine several *compatible* datasets with relative weights
(PROJECT.md §14: "70% Copenhagen normal baseline / 20% known attack corpus /
10% manually reviewed local detections").  This module turns those references
into arrays that :mod:`synapse_trainer.train` can consume, and records exactly
what it did so the model stays traceable to its data (§14, §28.8, §28.9).

Pure numpy — no torch, no sklearn required (``Dataset.split`` stratifies with
scikit-learn when it happens to be installed and falls back to a seeded shuffle
otherwise; either way the choice is recorded).

Dataset resolution
------------------

For a recipe entry ``{"id": "hq-copenhagen/baseline-2026-08"}`` and a
``--data ROOT`` root, the first of these that exists wins:

1. the entry's explicit ``path`` — absolute, else relative to ``ROOT``, else
   relative to the current directory;
2. ``ROOT/<id>.csv``;
3. ``ROOT/<id>/dataset.csv``;
4. ``ROOT/<id>/<latest version dir>/dataset.csv`` — "latest" is the highest
   immediate subdirectory by a numeric-aware natural sort (``v2`` > ``v10`` is
   *wrong*, so ``v10`` wins), restricted to subdirectories that actually hold a
   readable CSV;
5. any single ``ROOT/<id>/*.csv`` (lexicographically first).

Nothing found is a hard :class:`DatasetResolutionError` that lists every path
tried.  A dataset id may contain ``/`` (it is a namespaced id, §14) but never
``..`` and is never absolute — a recipe must not read outside its data root.

If a ``manifest.json`` (or ``dataset.json``) sits next to the CSV it is read for
the §14 dataset metadata — most importantly the immutable ``content_hash``,
which is echoed into ``training-recipe.json``.  It is metadata only: the CSV is
still the source of truth for rows and labels.

Weighting
---------

Weights are the *relative contribution to the training mixture*, not decoration.
The strategy, in full:

* every dataset is split **first**, independently (see below);
* the training pool size is ``target_n = sum(len(train_i))`` over all datasets;
* each dataset's quota is ``n_i = round(w_i * target_n)``, apportioned by the
  largest-remainder method so ``sum(n_i) == target_n`` exactly, with no
  rounding drift and no dependence on iteration order;
* ``n_i <= len(train_i)`` → **down-sample** without replacement (no duplicates);
* ``n_i >  len(train_i)`` → **up-sample**: take every row once, then draw the
  remaining ``n_i - len(train_i)`` rows with replacement;
* the concatenated mixture is shuffled once.

Every random draw uses a generator seeded by :func:`derive_seed`, a SHA-256 of
the recipe seed, a fixed purpose tag and the dataset id.  The mixture is
therefore reproducible **from the recipe alone** (same seed + same ids + same
data → byte-identical mixture), and a dataset's sample does not shift when an
unrelated dataset is added to the recipe.

Split before mix — the leakage rule
-----------------------------------

Splitting happens per dataset *before* any resampling, and only the train
portions are mixed.  The order matters for correctness, not tidiness: mixing
first and splitting after would let up-sampling place two copies of one source
row on both sides of the split boundary, leaking test rows into training
(§14 "never leak the test split into training").  Because a row is assigned to
exactly one of train/val/test inside its own dataset and only the train side is
ever duplicated, the three row-id sets are provably disjoint —
``tests/test_mixture.py::test_no_leak_under_aggressive_upsampling`` asserts it.

Validation and test sets are plain unions of the per-dataset val/test splits:
they are **never** resampled and never contain a duplicated row, so early
stopping and the reported test metrics measure natural data.  Weighting shapes
what the model learns from, not what it is judged on.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from . import schema
from .dataset import Dataset, DatasetError, load_csv
from .recipe import DatasetRef, Recipe
from .schema import CLASS_NAMES, OUTPUT_SIZE, SchemaMismatch

#: A class holding more than this share of the training mixture is flagged.
DOMINANT_CLASS_FRACTION = 0.90
#: A class with fewer than this many training rows is flagged.
MIN_CLASS_ROWS = 10
#: Duplicating a dataset by more than this factor is flagged.
HEAVY_UPSAMPLE_FACTOR = 3.0

_CSV_NAMES = ("dataset.csv", "data.csv", "flows.csv")
_MANIFEST_NAMES = ("manifest.json", "dataset.json")


class MixtureError(ValueError):
    """A recipe's datasets cannot be combined into a training mixture."""


class DatasetResolutionError(MixtureError):
    """A recipe dataset id could not be resolved to a CSV on disk."""


class DatasetIncompatible(MixtureError):
    """Two datasets in one recipe disagree on a frozen contract."""


# ---------------------------------------------------------------------------
# deterministic seeding
# ---------------------------------------------------------------------------


def derive_seed(seed: int, *parts: str) -> int:
    """A stable 32-bit sub-seed for ``seed`` and a purpose/dataset tag.

    Deterministic across processes, platforms and Python versions (``hash()`` is
    not), and independent of how many datasets the recipe has, so adding a
    dataset never reshuffles the others (PROJECT.md §28.8).
    """
    h = hashlib.sha256(("%d" % int(seed) + "\x00" + "\x00".join(parts)).encode("utf-8"))
    return int.from_bytes(h.digest()[:4], "big") % (2**31 - 1)


def _natural_key(name: str) -> tuple:
    """Sort key where ``v10`` > ``v9`` and ``2026-09`` > ``2026-08``."""
    return tuple(
        (1, int(tok)) if tok.isdigit() else (0, tok)
        for tok in re.split(r"(\d+)", name)
        if tok != ""
    )


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------


def _dir_csv(d: Path) -> Path | None:
    for cand in _CSV_NAMES:
        if (d / cand).is_file():
            return d / cand
    csvs = sorted(d.glob("*.csv"))
    return csvs[0] if csvs else None


def _version_dirs(d: Path) -> list[Path]:
    if not d.is_dir():
        return []
    subs = [p for p in d.iterdir() if p.is_dir() and _dir_csv(p) is not None]
    return sorted(subs, key=lambda p: _natural_key(p.name), reverse=True)


@dataclass
class Resolution:
    """Where a dataset id was found, and by which rule."""

    id: str
    csv_path: Path
    rule: str
    manifest_path: Path | None = None
    manifest: dict[str, Any] = field(default_factory=dict)
    tried: list[str] = field(default_factory=list)

    @property
    def content_hash(self) -> str | None:
        for key in ("content_hash", "contentHash", "hash", "version"):
            v = self.manifest.get(key)
            if isinstance(v, str) and v:
                return v
        return None


def _read_manifest(csv_path: Path, root: Path, dataset_id: str) -> tuple[Path | None, dict[str, Any]]:
    import json

    candidates = [csv_path.parent / n for n in _MANIFEST_NAMES]
    # flat layout: ROOT/<id>.csv next to ROOT/<id>.manifest.json
    candidates.append(csv_path.with_suffix(".manifest.json"))
    candidates.append(root / f"{dataset_id}.manifest.json")
    for c in candidates:
        if c.is_file():
            try:
                obj = json.loads(c.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise MixtureError(f"{c}: manifest is not valid JSON: {exc}") from exc
            if isinstance(obj, dict):
                return c, obj
    return None, {}


def resolve_dataset(ref: DatasetRef | str, data_root: str | Path, *, path: str | None = None) -> Resolution:
    """Locate the CSV backing one recipe dataset entry.

    ``path`` (an entry's explicit override) wins; otherwise the documented
    ``<root>/<id>`` fallbacks are tried in order.  Raises
    :class:`DatasetResolutionError` listing every candidate on failure.
    """
    dataset_id = ref if isinstance(ref, str) else ref.id
    explicit = path if path is not None else getattr(ref, "path", None)
    root = Path(data_root)
    tried: list[str] = []

    if ".." in Path(dataset_id).parts or Path(dataset_id).is_absolute():
        raise DatasetResolutionError(
            f"dataset id {dataset_id!r} must be a relative, '..'-free path under the data root"
        )

    def _found(p: Path, rule: str) -> Resolution:
        mpath, manifest = _read_manifest(p, root, dataset_id)
        return Resolution(
            id=dataset_id, csv_path=p, rule=rule, manifest_path=mpath, manifest=manifest, tried=tried
        )

    if explicit:
        for base, rule in ((root, "path (relative to --data)"), (Path.cwd(), "path (relative to cwd)")):
            p = Path(explicit)
            p = p if p.is_absolute() else base / p
            tried.append(str(p))
            if p.is_file():
                return _found(p, "explicit path" if p.is_absolute() else rule)
            if p.is_dir():
                inner = _dir_csv(p)
                if inner is not None:
                    return _found(inner, rule)
            if Path(explicit).is_absolute():
                break
        raise DatasetResolutionError(
            f"dataset {dataset_id!r}: explicit path {explicit!r} not found; tried:\n  "
            + "\n  ".join(tried)
        )

    flat = root / f"{dataset_id}.csv"
    tried.append(str(flat))
    if flat.is_file():
        return _found(flat, "<data>/<id>.csv")

    ddir = root / dataset_id
    canonical = ddir / "dataset.csv"
    tried.append(str(canonical))
    if canonical.is_file():
        return _found(canonical, "<data>/<id>/dataset.csv")

    versions = _version_dirs(ddir)
    if versions:
        latest = versions[0]
        inner = _dir_csv(latest)
        tried.append(str(latest / "dataset.csv"))
        if inner is not None:
            return _found(inner, f"<data>/<id>/<latest version dir '{latest.name}'>")
    else:
        tried.append(str(ddir / "<latest version dir>" / "dataset.csv"))

    tried.append(str(ddir / "*.csv"))
    if ddir.is_dir():
        inner = _dir_csv(ddir)
        if inner is not None:
            return _found(inner, "<data>/<id>/*.csv")

    raise DatasetResolutionError(
        f"dataset {dataset_id!r} not found under data root {root}; tried:\n  " + "\n  ".join(tried)
    )


# ---------------------------------------------------------------------------
# compatibility gate
# ---------------------------------------------------------------------------


def check_mutually_compatible(metas: Iterable[tuple[str, dict[str, Any]]]) -> None:
    """Every dataset must agree with the frozen contracts *and* with each other.

    A mismatch is a hard, named error: columns are never dropped, reordered or
    coerced to make two datasets fit (PROJECT.md §5.4, §8, §28.5-6).
    """
    seen: dict[str, tuple[str, str]] = {}
    for dataset_id, meta in metas:
        try:
            schema.check_compatible(meta)
        except SchemaMismatch as exc:
            raise DatasetIncompatible(f"dataset {dataset_id!r}: {exc}") from exc
        for key in ("feature_schema", "output_schema"):
            val = meta.get(key)
            if val is None:
                continue
            if key in seen and seen[key][1] != val:
                other_id, other_val = seen[key]
                raise DatasetIncompatible(
                    f"dataset {dataset_id!r} has {key}={val!r} but {other_id!r} has {other_val!r}; "
                    "a recipe may only combine datasets on the same frozen schema"
                )
            seen[key] = (dataset_id, val)


# ---------------------------------------------------------------------------
# apportionment
# ---------------------------------------------------------------------------


def apportion(weights: list[float], total: int) -> list[int]:
    """Largest-remainder apportionment of ``total`` rows across ``weights``.

    ``sum(result) == total`` exactly (when ``total >= 0`` and the weights are
    non-negative and not all zero), and the result depends only on the inputs —
    ties break towards the earlier entry, so it is order-stable, not RNG-driven.
    """
    if total <= 0 or not weights:
        return [0] * len(weights)
    wsum = float(sum(weights))
    if wsum <= 0:
        return [0] * len(weights)
    exact = [total * (w / wsum) for w in weights]
    floors = [int(x) for x in exact]
    remainder = total - sum(floors)
    if remainder > 0:
        order = sorted(range(len(weights)), key=lambda i: (-(exact[i] - floors[i]), i))
        for i in order[:remainder]:
            floors[i] += 1
    return floors


def _resample_indices(n_pool: int, quota: int, rng: np.random.Generator) -> tuple[np.ndarray, str, int]:
    """Indices into a train pool of ``n_pool`` rows realising ``quota`` rows."""
    if n_pool == 0 or quota <= 0:
        return np.array([], dtype=np.int64), "none", 0
    if quota <= n_pool:
        idx = rng.choice(n_pool, size=quota, replace=False)
        return np.sort(idx), ("none" if quota == n_pool else "down"), 0
    extra = quota - n_pool
    idx = np.concatenate([np.arange(n_pool, dtype=np.int64), rng.choice(n_pool, size=extra, replace=True)])
    return idx, "up", int(extra)


# ---------------------------------------------------------------------------
# result types
# ---------------------------------------------------------------------------


def label_counts(y: np.ndarray) -> dict[str, int]:
    counts = {name: 0 for name in CLASS_NAMES}
    if y.size:
        for cls, n in zip(*np.unique(np.asarray(y, dtype=np.int64), return_counts=True)):
            counts[CLASS_NAMES[int(cls)]] = int(n)
    return counts


@dataclass
class Component:
    """One dataset's realised contribution to the mixture."""

    id: str
    weight: float
    path: str
    rule: str
    content_hash: str | None
    source_rows: int
    split_sizes: dict[str, int]
    stratified: bool
    split_seed: int
    sample_seed: int
    train_rows: int
    effective_weight: float
    resampling: str
    duplicated_rows: int
    label_counts: dict[str, int]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "weight": float(self.weight),
            "effective_weight": float(self.effective_weight),
            "path": self.path,
            "resolved_by": self.rule,
            "content_hash": self.content_hash,
            "source_rows": int(self.source_rows),
            "split_sizes": dict(self.split_sizes),
            "stratified": bool(self.stratified),
            "split_seed": int(self.split_seed),
            "sample_seed": int(self.sample_seed),
            "train_rows": int(self.train_rows),
            "resampling": self.resampling,
            "duplicated_rows": int(self.duplicated_rows),
            "train_label_counts": dict(self.label_counts),
        }


@dataclass
class Mixture:
    """The combined, split, weighted training data plus its full provenance."""

    X_train: np.ndarray
    y_train: np.ndarray
    X_val: np.ndarray
    y_val: np.ndarray
    X_test: np.ndarray
    y_test: np.ndarray
    train_ids: list[str]
    val_ids: list[str]
    test_ids: list[str]
    components: list[Component]
    seed: int
    fractions: dict[str, float]
    target_train_rows: int
    warnings: list[str]
    #: The class ids the train partition was restricted to (after the split), or
    #: None when unfiltered. Val/test are never filtered.
    train_label_filter: list[int] | None = None
    #: How many train rows the filter dropped, before weighting/resampling.
    dropped_pre_weight_train_rows: int = 0

    #: Named so a future change of strategy is visible in every old bundle.
    STRATEGY = "split-per-dataset-then-weighted-resample-train/v1"

    def sizes(self) -> dict[str, int]:
        return {
            "train": int(self.X_train.shape[0]),
            "val": int(self.X_val.shape[0]),
            "test": int(self.X_test.shape[0]),
        }

    def label_counts(self) -> dict[str, dict[str, int]]:
        return {
            "train": label_counts(self.y_train),
            "val": label_counts(self.y_val),
            "test": label_counts(self.y_test),
        }

    @property
    def dataset_ids(self) -> list[str]:
        return [c.id for c in self.components]

    def to_json(self) -> dict[str, Any]:
        """The ``mixture`` block recorded in ``training-recipe.json`` (§14, §28.9)."""
        return {
            "strategy": self.STRATEGY,
            "seed": int(self.seed),
            "split_before_mix": True,
            "resampled_splits": ["train"],
            "train_label_filter": self.train_label_filter,
            "dropped_pre_weight_train_rows": int(self.dropped_pre_weight_train_rows),
            "fractions": {k: float(v) for k, v in self.fractions.items()},
            "target_train_rows": int(self.target_train_rows),
            "sizes": self.sizes(),
            "label_counts": self.label_counts(),
            "datasets": [c.to_json() for c in self.components],
            "warnings": list(self.warnings),
        }

    def split_result(self) -> dict[str, Any]:
        """The ``split_result`` block: what went where, per dataset and overall."""
        return {
            "seed": int(self.seed),
            "fractions": {k: float(v) for k, v in self.fractions.items()},
            "sizes": self.sizes(),
            "stratified": all(c.stratified for c in self.components) if self.components else False,
            "label_counts": self.label_counts(),
            "per_dataset": {
                c.id: {
                    "source_rows": c.source_rows,
                    "split_sizes": dict(c.split_sizes),
                    "train_rows_after_weighting": c.train_rows,
                    "stratified": c.stratified,
                    "seed": c.split_seed,
                }
                for c in self.components
            },
        }


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def _warnings_for(
    components: list[Component],
    y_train: np.ndarray,
    sizes: dict[str, int],
    *,
    label_filtered: bool = False,
) -> list[str]:
    warns: list[str] = []
    for c in components:
        if c.train_rows == 0 and not label_filtered:
            warns.append(
                f"dataset {c.id!r} contributes 0 training rows "
                f"(weight={c.weight:g}, {c.source_rows} source rows) — it will not affect the model"
            )
        elif c.resampling == "up":
            pool = c.split_sizes["train"]
            factor = c.train_rows / pool if pool else float("inf")
            if factor >= HEAVY_UPSAMPLE_FACTOR:
                warns.append(
                    f"dataset {c.id!r} is up-sampled {factor:.1f}x "
                    f"({pool} unique training rows duplicated to {c.train_rows}) — "
                    "the model may overfit its rows"
                )
    n = int(y_train.size)
    counts = label_counts(y_train)
    # A label-filtered mixture (the autoencoder's NORMAL-only train pool) is
    # single-class by design, so the class-mix warnings below do not apply.
    if not label_filtered:
        if n:
            top_class, top_n = max(counts.items(), key=lambda kv: kv[1])
            if top_n / n > DOMINANT_CLASS_FRACTION:
                warns.append(
                    f"class {top_class!r} is {100.0 * top_n / n:.1f}% of the training mixture — "
                    "severely imbalanced; consider re-weighting the datasets"
                )
        for name, cnt in counts.items():
            if cnt == 0:
                warns.append(
                    f"class {name!r} has no rows in the training mixture — "
                    f"the model cannot learn it but still emits {OUTPUT_SIZE} scores"
                )
            elif cnt < MIN_CLASS_ROWS:
                warns.append(
                    f"class {name!r} has only {cnt} training row(s) (< {MIN_CLASS_ROWS}) — "
                    "metrics for it will not be meaningful"
                )
    for split in ("val", "test"):
        if sizes[split] == 0:
            warns.append(f"the {split} split is empty — no {split} metrics will be produced")
    return warns


def build_mixture(
    recipe: Recipe,
    data_root: str | Path,
    *,
    target_train_rows: int | None = None,
    train_label_filter: set[int] | frozenset[int] | None = None,
    loader=load_csv,
) -> Mixture:
    """Resolve, load, split and weight every dataset in ``recipe``.

    Order is deliberate and load-bearing: **resolve → load → check → split each
    dataset → weight/resample only the train portions → concatenate**.  See the
    module docstring for why splitting must precede mixing.

    ``train_label_filter``, when given, restricts the **train** partition to rows
    whose class id is in the set — applied *after* the per-dataset split, so
    validation and test keep every class (the autoencoder trains on NORMAL only
    but its threshold is measured against held-out attack traffic; ADR 0037).
    """
    root = Path(data_root)
    if not root.exists():
        raise DatasetResolutionError(f"data root does not exist: {root}")

    if root.is_file():
        # Single-dataset convenience: `--data some/dataset.csv` still works, but
        # only when the recipe names exactly one dataset — a mixture needs a root.
        if len(recipe.datasets) != 1:
            raise DatasetResolutionError(
                f"--data {root} is a file but the recipe combines {len(recipe.datasets)} datasets; "
                "point --data at the directory the dataset ids resolve under"
            )
        resolutions = [
            resolve_dataset(recipe.datasets[0], root.parent, path=str(root.name))
        ]
    else:
        resolutions = [resolve_dataset(ref, root) for ref in recipe.datasets]

    datasets: list[Dataset] = []
    for ref, res in zip(recipe.datasets, resolutions):
        try:
            ds = loader(res.csv_path)
        except DatasetError as exc:
            raise MixtureError(f"dataset {ref.id!r} ({res.csv_path}): {exc}") from exc
        datasets.append(ds)

    metas: list[tuple[str, dict[str, Any]]] = []
    for ref, res, ds in zip(recipe.datasets, resolutions, datasets):
        metas.append((ref.id, ds.meta()))
        if res.manifest:
            metas.append((f"{ref.id} (manifest {res.manifest_path.name})", res.manifest))
    check_mutually_compatible(metas)

    # ---- 1. split each dataset on its own, before anything is mixed -------
    fr = {k: float(recipe.split[k]) for k in ("train", "val", "test")}
    per_split = []
    for ref, ds in zip(recipe.datasets, datasets):
        split_seed = derive_seed(recipe.seed, "split", ref.id)
        try:
            sp = ds.split(split_seed, train=fr["train"], val=fr["val"], test=fr["test"])
        except DatasetError as exc:
            raise MixtureError(f"dataset {ref.id!r}: {exc}") from exc
        per_split.append(sp)

    # ---- 1b. NORMAL-only (or any) train filter, applied after the split --
    train_idx = [np.asarray(sp.train, dtype=np.int64) for sp in per_split]
    dropped_pre_weight = 0
    if train_label_filter is not None:
        keep = np.array(sorted(int(c) for c in train_label_filter), dtype=np.int64)
        for k, ds in enumerate(datasets):
            ti = train_idx[k]
            mask = np.isin(ds.y[ti], keep)
            dropped_pre_weight += int((~mask).sum())
            train_idx[k] = ti[mask]
        if all(ti.size == 0 for ti in train_idx):
            raise MixtureError(
                "train_label_filter removed every training row — no dataset has a row "
                f"with a class id in {sorted(int(c) for c in train_label_filter)}"
            )

    # ---- 2. apportion the training pool by weight ------------------------
    train_pool = [int(ti.size) for ti in train_idx]
    total_train = int(sum(train_pool))
    target = int(target_train_rows) if target_train_rows is not None else total_train
    quotas = apportion([float(r.weight) for r in recipe.datasets], target)

    # ---- 3. resample only the train side ---------------------------------
    Xtr_parts, ytr_parts, tr_ids = [], [], []
    Xva_parts, yva_parts, va_ids = [], [], []
    Xte_parts, yte_parts, te_ids = [], [], []
    components: list[Component] = []

    for k, (ref, res, ds, sp, quota) in enumerate(
        zip(recipe.datasets, resolutions, datasets, per_split, quotas)
    ):
        ti = train_idx[k]
        sample_seed = derive_seed(recipe.seed, "mixture", ref.id)
        rng = np.random.default_rng(sample_seed)
        pick, mode, dupes = _resample_indices(int(ti.size), quota, rng)
        rows = ti[pick] if pick.size else np.array([], dtype=np.int64)

        Xtr_parts.append(ds.X[rows])
        ytr_parts.append(ds.y[rows])
        tr_ids.extend(_row_ids(ds, ref.id, rows))

        Xva_parts.append(ds.X[sp.val])
        yva_parts.append(ds.y[sp.val])
        va_ids.extend(_row_ids(ds, ref.id, sp.val))

        Xte_parts.append(ds.X[sp.test])
        yte_parts.append(ds.y[sp.test])
        te_ids.extend(_row_ids(ds, ref.id, sp.test))

        components.append(
            Component(
                id=ref.id,
                weight=float(ref.weight),
                path=str(res.csv_path),
                rule=res.rule,
                content_hash=res.content_hash,
                source_rows=len(ds),
                split_sizes=sp.sizes(),
                stratified=bool(sp.stratified),
                split_seed=int(sp.seed),
                sample_seed=int(sample_seed),
                train_rows=int(rows.size),
                effective_weight=(float(rows.size) / target) if target else 0.0,
                resampling=mode,
                duplicated_rows=dupes,
                label_counts=label_counts(ds.y[rows]),
            )
        )

    X_train = _stack(Xtr_parts)
    y_train = _stack1(ytr_parts)
    X_val = _stack(Xva_parts)
    y_val = _stack1(yva_parts)
    X_test = _stack(Xte_parts)
    y_test = _stack1(yte_parts)

    # ---- 4. one deterministic shuffle so datasets are not fed in blocks --
    if y_train.size:
        rng = np.random.default_rng(derive_seed(recipe.seed, "shuffle"))
        perm = rng.permutation(y_train.size)
        X_train, y_train = X_train[perm], y_train[perm]
        tr_ids = [tr_ids[i] for i in perm]

    if y_train.size == 0:
        raise MixtureError(
            "the training mixture is empty — every dataset contributed 0 rows "
            "(check the dataset weights and split.train)"
        )

    sizes = {"train": int(y_train.size), "val": int(y_val.size), "test": int(y_test.size)}
    return Mixture(
        X_train=X_train,
        y_train=y_train,
        X_val=X_val,
        y_val=y_val,
        X_test=X_test,
        y_test=y_test,
        train_ids=tr_ids,
        val_ids=va_ids,
        test_ids=te_ids,
        components=components,
        seed=int(recipe.seed),
        fractions=fr,
        target_train_rows=target,
        warnings=_warnings_for(
            components, y_train, sizes, label_filtered=train_label_filter is not None
        ),
        train_label_filter=(
            sorted(int(c) for c in train_label_filter)
            if train_label_filter is not None
            else None
        ),
        dropped_pre_weight_train_rows=int(dropped_pre_weight),
    )


def _row_ids(ds: Dataset, dataset_id: str, rows: np.ndarray) -> list[str]:
    """Stable ``<dataset id>#<row id>`` labels — the leakage test's evidence."""
    out = []
    for i in np.asarray(rows, dtype=np.int64).tolist():
        rid = ds.ids[i] if i < len(ds.ids) else str(i)
        out.append(f"{dataset_id}#{rid}")
    return out


def _stack(parts: list[np.ndarray]) -> np.ndarray:
    parts = [p for p in parts if p.size]
    if not parts:
        return np.zeros((0, schema.INPUT_SIZE), dtype=np.float64)
    return np.concatenate(parts, axis=0)


def _stack1(parts: list[np.ndarray]) -> np.ndarray:
    parts = [p for p in parts if p.size]
    if not parts:
        return np.zeros((0,), dtype=np.int64)
    return np.concatenate(parts, axis=0)


# ---------------------------------------------------------------------------
# human-readable plan (used by `inspect-recipe` and `train --dry-run`)
# ---------------------------------------------------------------------------


def format_plan(mixture: Mixture, *, recipe_name: str | None = None, data_root: str | None = None) -> str:
    """Render the mixture plan an operator reads before burning a training run."""
    lines: list[str] = []
    if recipe_name:
        lines.append(f"recipe:            {recipe_name}")
    if data_root:
        lines.append(f"data root:         {data_root}")
    lines.append(f"strategy:          {Mixture.STRATEGY}")
    lines.append(f"seed:              {mixture.seed}")
    fr = mixture.fractions
    lines.append(
        "split:             "
        f"train={fr['train']:g} val={fr['val']:g} test={fr['test']:g} (applied per dataset, before mixing)"
    )
    lines.append("")

    w_id = max([len("dataset"), len("TOTAL")] + [len(c.id) for c in mixture.components])
    head = (
        f"{'dataset':<{w_id}} {'w':>6} {'eff':>6} {'rows':>7} "
        f"{'train':>7} {'val':>6} {'test':>6}  resample"
    )
    lines.append(head)
    lines.append("-" * len(head))
    for c in mixture.components:
        resample = c.resampling
        if c.resampling == "up":
            resample = f"up (+{c.duplicated_rows} dup)"
        elif c.resampling == "down":
            resample = f"down (-{c.split_sizes['train'] - c.train_rows})"
        lines.append(
            f"{c.id:<{w_id}} {c.weight:>6.3f} {c.effective_weight:>6.3f} {c.source_rows:>7} "
            f"{c.train_rows:>7} {c.split_sizes['val']:>6} {c.split_sizes['test']:>6}  {resample}"
        )
    sizes = mixture.sizes()
    lines.append("-" * len(head))
    lines.append(
        f"{'TOTAL':<{w_id}} {sum(c.weight for c in mixture.components):>6.3f} "
        f"{sum(c.effective_weight for c in mixture.components):>6.3f} "
        f"{sum(c.source_rows for c in mixture.components):>7} "
        f"{sizes['train']:>7} {sizes['val']:>6} {sizes['test']:>6}"
    )
    lines.append("")

    for c in mixture.components:
        lines.append(f"  {c.id}")
        lines.append(f"    path:          {c.path}   [{c.rule}]")
        lines.append(f"    content_hash:  {c.content_hash or '(none — no manifest)'}")
        lines.append(f"    split seed:    {c.split_seed} (stratified={c.stratified})")
    lines.append("")

    counts = mixture.label_counts()
    width = max(len(n) for n in CLASS_NAMES)
    lines.append(f"{'class':<{width}} {'train':>8} {'%':>7} {'val':>7} {'test':>7}")
    lines.append("-" * (width + 32))
    ntr = max(1, sizes["train"])
    for name in CLASS_NAMES:
        lines.append(
            f"{name:<{width}} {counts['train'][name]:>8} "
            f"{100.0 * counts['train'][name] / ntr:>6.1f}% "
            f"{counts['val'][name]:>7} {counts['test'][name]:>7}"
        )
    lines.append("")

    if mixture.warnings:
        lines.append(f"warnings ({len(mixture.warnings)}):")
        for w in mixture.warnings:
            lines.append(f"  ! {w}")
    else:
        lines.append("warnings: none")
    return "\n".join(lines)
