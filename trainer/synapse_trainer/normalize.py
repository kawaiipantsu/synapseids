"""Per-model feature normalizer — pure numpy, no torch.

Normalization is a *per-model* concern (PROJECT.md §8, §11): the Go daemon feeds
the heuristic raw features, and applies each trained model's own
``normalizer.json`` before inference.  This module fits that file.

Emitted JSON (the exact contract the Go bundle-gate validates):

``standard``::

    {
      "method": "standard",
      "feature_schema": "flow-features-v1",
      "per_feature": [ {"index": 0, "name": "flow_duration", "mean": 0.0, "std": 1.0}, ... 48 ]
    }

``minmax`` swaps the stat keys for ``"min"`` / ``"max"``.

``identity`` is a genuine no-op; it still writes 48 ordered ``per_feature``
entries in ``standard`` form (``mean`` 0.0 / ``std`` 1.0) so a consumer that
always applies ``(x - mean) / std`` also gets identity.

Guards: ``std`` is floored at ``1e-9`` and a degenerate ``min == max`` column
gets ``max = min + 1e-9`` — the file never carries ``std <= 0`` or ``min >= max``.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from .schema import FEATURE_NAMES, FEATURE_SCHEMA, INPUT_SIZE

METHODS = ("standard", "minmax", "identity")
_STD_FLOOR = 1e-9
_SPAN_FLOOR = 1e-9


class NormalizerError(ValueError):
    pass


def _as_2d(X: Any) -> np.ndarray:
    arr = np.asarray(X, dtype=np.float64)
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    if arr.ndim != 2:
        raise NormalizerError(f"expected a 2-D array, got shape {arr.shape}")
    if arr.shape[1] != INPUT_SIZE:
        raise NormalizerError(
            f"expected {INPUT_SIZE} feature columns ({FEATURE_SCHEMA}), got {arr.shape[1]}"
        )
    return arr


class Normalizer:
    """Fitted feature scaler for one of :data:`METHODS`."""

    def __init__(self, method: str = "standard") -> None:
        method = str(method).lower()
        if method not in METHODS:
            raise NormalizerError(f"unknown method {method!r}; expected one of {METHODS}")
        self.method = method
        # standard / identity
        self.mean_: np.ndarray | None = None
        self.std_: np.ndarray | None = None
        # minmax
        self.min_: np.ndarray | None = None
        self.max_: np.ndarray | None = None
        self._fitted = False

    # ---- fitting ---------------------------------------------------------

    def fit(self, X: Any, method: str | None = None) -> "Normalizer":
        if method is not None:
            method = str(method).lower()
            if method not in METHODS:
                raise NormalizerError(f"unknown method {method!r}; expected one of {METHODS}")
            self.method = method
        arr = _as_2d(X)

        if self.method == "standard":
            self.mean_ = arr.mean(axis=0)
            self.std_ = np.maximum(arr.std(axis=0), _STD_FLOOR)
        elif self.method == "minmax":
            self.min_ = arr.min(axis=0)
            mx = arr.max(axis=0)
            self.max_ = np.where(mx <= self.min_ + _SPAN_FLOOR, self.min_ + _SPAN_FLOOR, mx)
        else:  # identity
            self.mean_ = np.zeros(INPUT_SIZE, dtype=np.float64)
            self.std_ = np.ones(INPUT_SIZE, dtype=np.float64)

        self._fitted = True
        return self

    @classmethod
    def fit_new(cls, X: Any, method: str = "standard") -> "Normalizer":
        return cls(method).fit(X)

    def fit_transform(self, X: Any, method: str | None = None) -> np.ndarray:
        return self.fit(X, method).transform(X)

    # ---- applying ------------------------------------------------------

    def transform(self, X: Any) -> np.ndarray:
        if not self._fitted:
            raise NormalizerError("transform() called before fit()/from_json()")
        arr = _as_2d(X)
        if self.method == "minmax":
            return (arr - self.min_) / (self.max_ - self.min_)
        if self.method == "identity":
            return arr.copy()
        return (arr - self.mean_) / self.std_

    def inverse_transform(self, X: Any) -> np.ndarray:
        if not self._fitted:
            raise NormalizerError("inverse_transform() called before fit()/from_json()")
        arr = _as_2d(X)
        if self.method == "minmax":
            return arr * (self.max_ - self.min_) + self.min_
        if self.method == "identity":
            return arr.copy()
        return arr * self.std_ + self.mean_

    # ---- serialisation ------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        if not self._fitted:
            raise NormalizerError("to_json() called before fit()")
        per_feature: list[dict[str, Any]] = []
        for i, name in enumerate(FEATURE_NAMES):
            entry: dict[str, Any] = {"index": i, "name": name}
            if self.method == "minmax":
                entry["min"] = float(self.min_[i])
                entry["max"] = float(self.max_[i])
            else:  # standard and identity both use mean/std form
                entry["mean"] = float(self.mean_[i])
                entry["std"] = float(self.std_[i])
            per_feature.append(entry)
        return {
            "method": self.method,
            "feature_schema": FEATURE_SCHEMA,
            "per_feature": per_feature,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Normalizer":
        method = str(d.get("method", "standard")).lower()
        obj = cls(method)
        fs = d.get("feature_schema")
        if fs is not None and fs != FEATURE_SCHEMA:
            raise NormalizerError(
                f"normalizer feature_schema={fs!r} but this trainer builds {FEATURE_SCHEMA!r}"
            )
        pf = d.get("per_feature", [])
        if len(pf) != INPUT_SIZE:
            raise NormalizerError(
                f"per_feature must have exactly {INPUT_SIZE} entries, got {len(pf)}"
            )
        pf = sorted(pf, key=lambda e: e["index"])
        if [e["index"] for e in pf] != list(range(INPUT_SIZE)):
            raise NormalizerError("per_feature indices are not 0..47 in order")

        if method == "minmax":
            obj.min_ = np.array([float(e["min"]) for e in pf], dtype=np.float64)
            mx = np.array([float(e["max"]) for e in pf], dtype=np.float64)
            obj.max_ = np.where(mx <= obj.min_ + _SPAN_FLOOR, obj.min_ + _SPAN_FLOOR, mx)
        else:
            obj.mean_ = np.array([float(e.get("mean", 0.0)) for e in pf], dtype=np.float64)
            obj.std_ = np.maximum(
                np.array([float(e.get("std", 1.0)) for e in pf], dtype=np.float64), _STD_FLOOR
            )
        obj._fitted = True
        return obj


def fit(X: Any, method: str = "standard") -> Normalizer:
    """Convenience: fit and return a :class:`Normalizer` in one call."""
    return Normalizer.fit_new(X, method)
