"""Parse and validate a ``training-recipe.json`` input.

Shape (all fields except ``datasets`` have defaults)::

    {
      "name": "flow-classifier-baseline",
      "datasets": [ {"id": "thugs/lab-attacks-2026-08", "weight": 0.7,
                     "path": "optional/explicit.csv"}, ... ],
      "architecture": { "hidden": [ {"width": 64, "activation": "relu",
                                     "dropout": 0.3, "batchnorm": true, "residual": false} ] },
      "normalizer": "standard",
      "optimizer": "adam", "lr": 1e-3, "batch_size": 256, "epochs": 50,
      "early_stopping": {"patience": 8, "metric": "val_loss"},
      "class_weighting": "balanced", "scheduler": "cosine", "seed": 1337,
      "split": {"train": 0.7, "val": 0.15, "test": 0.15}
    }

Dataset ``weight`` values must sum to ~1.0 and ``split`` values must sum to
~1.0.  The *resolved* recipe (defaults filled in) is what gets echoed into the
bundle as ``training-recipe.json`` (PROJECT.md §9, §11, §14, §28.9).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .architecture import (
    ANOMALY_FAMILY,
    CLASSIFIER_FAMILY,
    FAMILY_OUTPUT,
    Architecture,
    HiddenLayer,
    default_architecture,
)

# "classification" trains the flow-classifier-v1 supervised MLP; "reconstruction"
# trains the flow-anomaly-v1 autoencoder on NORMAL traffic only (ADR 0037).
OBJECTIVES = frozenset({"classification", "reconstruction"})
_OBJECTIVE_FAMILY = {
    "classification": CLASSIFIER_FAMILY,
    "reconstruction": ANOMALY_FAMILY,
}

OPTIMIZERS = frozenset({"adam", "adamw", "sgd", "rmsprop"})
SCHEDULERS = frozenset({"none", "cosine", "step", "plateau"})
CLASS_WEIGHTINGS = frozenset({"none", "balanced"})
ES_METRICS = frozenset({"val_loss", "val_accuracy", "val_macro_f1"})
NORMALIZERS = frozenset({"standard", "minmax", "identity"})

_TOL = 1e-6

DEFAULTS: dict[str, Any] = {
    "optimizer": "adam",
    "lr": 1e-3,
    "batch_size": 256,
    "epochs": 50,
    "early_stopping": {"patience": 8, "metric": "val_loss"},
    "class_weighting": "balanced",
    "scheduler": "cosine",
    "normalizer": "standard",
    "seed": 1337,
    "split": {"train": 0.7, "val": 0.15, "test": 0.15},
}


class RecipeError(ValueError):
    pass


@dataclass
class DatasetRef:
    """One entry of ``recipe.datasets``.

    ``path`` is an optional escape hatch that pins this dataset to an exact CSV
    (or a directory holding one) instead of resolving ``id`` under ``--data``;
    see :mod:`synapse_trainer.mixture` for the full resolution order.
    """

    id: str
    weight: float = 1.0
    path: str | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "weight": float(self.weight)}
        if self.path:
            out["path"] = str(self.path)
        return out


@dataclass
class EarlyStopping:
    patience: int = 8
    metric: str = "val_loss"

    def __post_init__(self) -> None:
        self.patience = int(self.patience)
        self.metric = str(self.metric).lower()
        if self.patience < 0:
            raise RecipeError(f"early_stopping.patience must be >= 0, got {self.patience}")
        if self.metric not in ES_METRICS:
            raise RecipeError(
                f"early_stopping.metric {self.metric!r} not one of {sorted(ES_METRICS)}"
            )

    @property
    def mode(self) -> str:
        return "min" if self.metric.endswith("loss") else "max"

    def to_json(self) -> dict[str, Any]:
        return {"patience": self.patience, "metric": self.metric}


@dataclass
class Recipe:
    datasets: list[DatasetRef]
    architecture: Architecture = field(default_factory=default_architecture)
    name: str = "flow-classifier"
    objective: str = "classification"
    optimizer: str = DEFAULTS["optimizer"]
    lr: float = DEFAULTS["lr"]
    batch_size: int = DEFAULTS["batch_size"]
    epochs: int = DEFAULTS["epochs"]
    early_stopping: EarlyStopping = field(default_factory=EarlyStopping)
    class_weighting: str = DEFAULTS["class_weighting"]
    scheduler: str = DEFAULTS["scheduler"]
    normalizer: str = DEFAULTS["normalizer"]
    seed: int = DEFAULTS["seed"]
    split: dict[str, float] = field(default_factory=lambda: dict(DEFAULTS["split"]))

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not self.datasets:
            raise RecipeError("recipe needs at least one dataset")
        wsum = sum(d.weight for d in self.datasets)
        if abs(wsum - 1.0) > _TOL:
            raise RecipeError(f"dataset weights must sum to 1.0, got {wsum:g}")
        for d in self.datasets:
            if d.weight < 0:
                raise RecipeError(f"dataset {d.id!r} has negative weight {d.weight}")
            if not d.id:
                raise RecipeError("every dataset needs a non-empty id")
        # Duplicate ids would collide in the mixture's per-dataset RNG derivation
        # and make the recorded provenance ambiguous (PROJECT.md §14, §28.9).
        ids = [d.id for d in self.datasets]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise RecipeError(f"duplicate dataset id(s) in recipe: {dupes}")

        self.objective = str(self.objective or "classification").lower()
        if self.objective not in OBJECTIVES:
            raise RecipeError(f"objective {self.objective!r} not one of {sorted(OBJECTIVES)}")
        want_family = _OBJECTIVE_FAMILY[self.objective]
        if self.architecture.family != want_family:
            raise RecipeError(
                f"objective {self.objective!r} needs a {want_family!r} architecture, "
                f"got {self.architecture.family!r}"
            )
        if self.objective == "reconstruction":
            if self.class_weighting not in (None, "", "none"):
                raise RecipeError(
                    "class_weighting has no meaning for objective 'reconstruction' (there are "
                    "no class labels in the loss); set it to 'none' or omit it"
                )
            if self.early_stopping.metric != "val_loss":
                raise RecipeError(
                    "objective 'reconstruction' only supports early_stopping.metric "
                    f"'val_loss' (the MSE); got {self.early_stopping.metric!r}"
                )

        self.optimizer = str(self.optimizer).lower()
        if self.optimizer not in OPTIMIZERS:
            raise RecipeError(f"optimizer {self.optimizer!r} not one of {sorted(OPTIMIZERS)}")
        self.scheduler = str(self.scheduler or "none").lower()
        if self.scheduler not in SCHEDULERS:
            raise RecipeError(f"scheduler {self.scheduler!r} not one of {sorted(SCHEDULERS)}")
        self.class_weighting = str(self.class_weighting or "none").lower()
        if self.class_weighting not in CLASS_WEIGHTINGS:
            raise RecipeError(
                f"class_weighting {self.class_weighting!r} not one of {sorted(CLASS_WEIGHTINGS)}"
            )
        self.normalizer = str(self.normalizer or "standard").lower()
        if self.normalizer not in NORMALIZERS:
            raise RecipeError(f"normalizer {self.normalizer!r} not one of {sorted(NORMALIZERS)}")

        self.lr = float(self.lr)
        self.batch_size = int(self.batch_size)
        self.epochs = int(self.epochs)
        self.seed = int(self.seed)
        if self.lr <= 0:
            raise RecipeError(f"lr must be > 0, got {self.lr}")
        if self.batch_size <= 0:
            raise RecipeError(f"batch_size must be > 0, got {self.batch_size}")
        if self.epochs <= 0:
            raise RecipeError(f"epochs must be > 0, got {self.epochs}")

        keys = set(self.split)
        if keys != {"train", "val", "test"}:
            raise RecipeError(f"split needs exactly train/val/test keys, got {sorted(keys)}")
        ssum = sum(self.split.values())
        if abs(ssum - 1.0) > _TOL:
            raise RecipeError(f"split fractions must sum to 1.0, got {ssum:g}")
        for k, v in self.split.items():
            if v < 0:
                raise RecipeError(f"split.{k} must be >= 0, got {v}")
        if self.split["train"] <= 0:
            raise RecipeError("split.train must be > 0")

    # ---- serialisation ----------------------------------------------

    @property
    def dataset_ids(self) -> list[str]:
        return [d.id for d in self.datasets]

    def to_json(self) -> dict[str, Any]:
        """The fully-resolved recipe (defaults materialised)."""
        return {
            "name": self.name,
            "objective": self.objective,
            "datasets": [d.to_json() for d in self.datasets],
            "architecture": self.architecture.to_json(),
            "normalizer": self.normalizer,
            "optimizer": self.optimizer,
            "lr": self.lr,
            "batch_size": self.batch_size,
            "epochs": self.epochs,
            "early_stopping": self.early_stopping.to_json(),
            "class_weighting": self.class_weighting,
            "scheduler": self.scheduler,
            "seed": self.seed,
            "split": {k: float(self.split[k]) for k in ("train", "val", "test")},
        }

    def dumps(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_json(), indent=indent)


def _architecture_from(raw: dict[str, Any], objective: str = "classification") -> Architecture:
    family = _OBJECTIVE_FAMILY.get(objective, CLASSIFIER_FAMILY)
    arch = raw.get("architecture")
    hidden = None
    if isinstance(arch, dict) and "hidden" in arch:
        hidden = arch["hidden"]
    elif "hidden" in raw:
        hidden = raw["hidden"]
    if hidden is None:
        return default_architecture(family)
    return Architecture(
        hidden=[HiddenLayer.from_json(h) for h in hidden],
        output_size=FAMILY_OUTPUT[family],
        family=family,
    )


def from_dict(raw: dict[str, Any]) -> Recipe:
    if not isinstance(raw, dict):
        raise RecipeError("recipe must be a JSON object")
    ds_raw = raw.get("datasets")
    if not isinstance(ds_raw, list) or not ds_raw:
        raise RecipeError("recipe.datasets must be a non-empty list")
    datasets = []
    for d in ds_raw:
        if isinstance(d, str):
            datasets.append(DatasetRef(id=d, weight=1.0 / len(ds_raw)))
        elif isinstance(d, dict):
            if "id" not in d:
                raise RecipeError(f"dataset entry needs an 'id': {d!r}")
            path = d.get("path")
            datasets.append(
                DatasetRef(
                    id=str(d["id"]),
                    weight=float(d.get("weight", 1.0 / len(ds_raw))),
                    path=str(path) if path else None,
                )
            )
        else:
            raise RecipeError(f"bad dataset entry: {d!r}")

    es_raw = raw.get("early_stopping", DEFAULTS["early_stopping"])
    early = EarlyStopping(
        patience=es_raw.get("patience", 8),
        metric=es_raw.get("metric", "val_loss"),
    )

    split = dict(DEFAULTS["split"])
    split.update(raw.get("split", {}))

    objective = str(raw.get("objective", "classification") or "classification").lower()
    # A reconstruction recipe has no class labels in the loss, so the default
    # "balanced" class weighting is inert — treat an unset value as "none".
    default_cw = "none" if objective == "reconstruction" else DEFAULTS["class_weighting"]

    return Recipe(
        datasets=datasets,
        architecture=_architecture_from(raw, objective),
        name=str(raw.get("name", "flow-classifier")),
        objective=objective,
        optimizer=raw.get("optimizer", DEFAULTS["optimizer"]),
        lr=raw.get("lr", DEFAULTS["lr"]),
        batch_size=raw.get("batch_size", DEFAULTS["batch_size"]),
        epochs=raw.get("epochs", DEFAULTS["epochs"]),
        early_stopping=early,
        class_weighting=raw.get("class_weighting", default_cw),
        scheduler=raw.get("scheduler", DEFAULTS["scheduler"]),
        normalizer=raw.get("normalizer", DEFAULTS["normalizer"]),
        seed=raw.get("seed", DEFAULTS["seed"]),
        split=split,
    )


def loads(text: str) -> Recipe:
    return from_dict(json.loads(text))


def load(path: str | Path) -> Recipe:
    return loads(Path(path).read_text(encoding="utf-8"))
