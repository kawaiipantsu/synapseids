"""Issue #23 — write the deployable model bundle.

::

    out_dir/model.onnx            torch.onnx.export, opset 17, fixed batch 1,
                                  input  "features" [1, 48]
                                  output "scores"   [1, 7]  (softmax included)
    out_dir/metadata.json         the contract the Go daemon's bundle-gate validates
    out_dir/normalizer.json       Normalizer.to_json()
    out_dir/metrics.json          accuracy / macro_f1 / val_loss / per_class / confusion / test
    out_dir/training-recipe.json  the resolved recipe (seed, split, dataset ids + weights)

``model_hash`` is ``"sha256:"`` + the lowercase hex digest of the bytes actually
written to ``model.onnx`` (read back from disk).

The JSON builders (:func:`build_metadata`, :func:`build_metrics_json`,
:func:`build_recipe_json`, :func:`write_bundle_json`) do **not** import torch, so
the non-torch test path can exercise the full bundle layout against a dummy
``model.onnx`` blob.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__ as _TRAINER_VERSION
from .architecture import Architecture
from .schema import FEATURE_SCHEMA, INPUT_SIZE, OUTPUT_SCHEMA, OUTPUT_SIZE

FAMILY = "flow-classifier-v1"
MODEL_VERSION = "1"
ONNX_OPSET = 17
ONNX_INPUT_NAME = "features"
ONNX_OUTPUT_NAME = "scores"

BUNDLE_FILES = (
    "model.onnx",
    "metadata.json",
    "normalizer.json",
    "metrics.json",
    "training-recipe.json",
)

# Order matters: this is the key order the Go bundle-gate diffs against.
METADATA_KEYS = (
    "model_id",
    "name",
    "version",
    "family",
    "feature_schema",
    "input_size",
    "output_schema",
    "output_size",
    "architecture",
    "training_dataset_ids",
    "created_at",
    "trainer_version",
    "parameter_count",
    "model_hash",
)


class ExportError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# hashing / time
# --------------------------------------------------------------------------


def sha256_file(path: str | Path) -> str:
    """``"sha256:"`` + lowercase hex of a file's raw bytes."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def make_model_id(name_hint: str | None = None, when: datetime | None = None) -> str:
    when = when or _utc_now()
    return f"{FAMILY}-{when.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}"


def rfc3339_utc(when: datetime | None = None) -> str:
    return (when or _utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# JSON builders (torch-free)
# --------------------------------------------------------------------------


def build_metadata(
    *,
    name: str,
    arch: Architecture,
    training_dataset_ids: list[str],
    model_hash: str,
    parameter_count: int | None = None,
    trainer_version: str | None = None,
    created_at: str | None = None,
    model_id: str | None = None,
    version: str = MODEL_VERSION,
) -> dict[str, Any]:
    """The exact ``metadata.json`` object (key order == :data:`METADATA_KEYS`)."""
    when = _utc_now()
    if not model_hash.startswith("sha256:"):
        raise ExportError(f"model_hash must be 'sha256:<hex>', got {model_hash!r}")
    meta = {
        "model_id": model_id or make_model_id(name, when),
        "name": str(name),
        "version": str(version),
        "family": FAMILY,
        "feature_schema": FEATURE_SCHEMA,
        "input_size": INPUT_SIZE,
        "output_schema": OUTPUT_SCHEMA,
        "output_size": OUTPUT_SIZE,
        "architecture": arch.to_json(),
        "training_dataset_ids": list(training_dataset_ids),
        "created_at": created_at or rfc3339_utc(when),
        "trainer_version": trainer_version or _TRAINER_VERSION,
        "parameter_count": int(
            parameter_count if parameter_count is not None else arch.parameter_count()
        ),
        "model_hash": model_hash,
    }
    # guarantee canonical key order
    return {k: meta[k] for k in METADATA_KEYS}


def build_metrics_json(metrics: dict[str, Any]) -> dict[str, Any]:
    """Normalise a training metrics dict into the ``metrics.json`` contract."""
    per_class = metrics.get("per_class", [])
    out: dict[str, Any] = {
        "accuracy": float(metrics.get("accuracy", 0.0)),
        "macro_f1": float(metrics.get("macro_f1", 0.0)),
        "macro_precision": float(metrics.get("macro_precision", 0.0)),
        "macro_recall": float(metrics.get("macro_recall", 0.0)),
        "train_loss": _opt_float(metrics.get("train_loss")),
        "val_loss": _opt_float(metrics.get("val_loss")),
        "per_class": [
            {
                "class": str(pc["class"]),
                "precision": float(pc["precision"]),
                "recall": float(pc["recall"]),
                "f1": float(pc["f1"]),
                "support": int(pc["support"]),
            }
            for pc in per_class
        ],
        "confusion": [[int(x) for x in row] for row in metrics.get("confusion", [])],
    }
    test = metrics.get("test")
    if isinstance(test, dict):
        out["test"] = {
            "accuracy": float(test.get("accuracy", 0.0)),
            "macro_f1": float(test.get("macro_f1", 0.0)),
            "loss": _opt_float(test.get("loss")),
            "per_class": [
                {
                    "class": str(pc["class"]),
                    "precision": float(pc["precision"]),
                    "recall": float(pc["recall"]),
                    "f1": float(pc["f1"]),
                    "support": int(pc["support"]),
                }
                for pc in test.get("per_class", [])
            ],
            "confusion": [[int(x) for x in row] for row in test.get("confusion", [])],
        }
    else:
        out["test"] = None
    return out


def build_recipe_json(recipe: Any) -> dict[str, Any]:
    """Echo the resolved recipe (``Recipe`` instance or an already-dict)."""
    if hasattr(recipe, "to_json"):
        return recipe.to_json()
    if isinstance(recipe, dict):
        return recipe
    raise ExportError(f"cannot serialise recipe of type {type(recipe)!r}")


def _opt_float(v: Any) -> float | None:
    return None if v is None else float(v)


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def write_bundle_json(
    out_dir: str | Path,
    *,
    metadata: dict[str, Any],
    normalizer_json: dict[str, Any],
    metrics_json: dict[str, Any],
    recipe_json: dict[str, Any],
) -> dict[str, str]:
    """Write the four JSON files; return ``{name: path}``.  Does not touch model.onnx."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "metadata.json": out / "metadata.json",
        "normalizer.json": out / "normalizer.json",
        "metrics.json": out / "metrics.json",
        "training-recipe.json": out / "training-recipe.json",
    }
    _write_json(paths["metadata.json"], metadata)
    _write_json(paths["normalizer.json"], normalizer_json)
    _write_json(paths["metrics.json"], metrics_json)
    _write_json(paths["training-recipe.json"], recipe_json)
    return {k: str(v) for k, v in paths.items()}


def validate_metadata(meta: dict[str, Any]) -> None:
    """Local mirror of what the Go bundle-gate checks — fail early, on our side."""
    for key in METADATA_KEYS:
        if key not in meta:
            raise ExportError(f"metadata.json missing required key: {key}")
    if list(meta.keys()) != list(METADATA_KEYS):
        raise ExportError(f"metadata.json key order drift: {list(meta.keys())}")
    checks = {
        "family": FAMILY,
        "feature_schema": FEATURE_SCHEMA,
        "input_size": INPUT_SIZE,
        "output_schema": OUTPUT_SCHEMA,
        "output_size": OUTPUT_SIZE,
        "version": MODEL_VERSION,
    }
    for k, want in checks.items():
        if meta[k] != want:
            raise ExportError(f"metadata.json {k}={meta[k]!r}, expected {want!r}")
    if not isinstance(meta["parameter_count"], int) or meta["parameter_count"] <= 0:
        raise ExportError("metadata.json parameter_count must be a positive int")
    if not str(meta["model_hash"]).startswith("sha256:"):
        raise ExportError("metadata.json model_hash must start with 'sha256:'")
    if not isinstance(meta["training_dataset_ids"], list) or not meta["training_dataset_ids"]:
        raise ExportError("metadata.json training_dataset_ids must be a non-empty list")
    arch = meta["architecture"]
    if arch.get("input_size") != INPUT_SIZE or arch.get("output_size") != OUTPUT_SIZE:
        raise ExportError("metadata.json architecture input/output size mismatch")


# --------------------------------------------------------------------------
# ONNX export (torch)
# --------------------------------------------------------------------------


def export_onnx(model: Any, path: str | Path) -> Path:
    """Write ``model`` (an ``nn.Module`` emitting logits) to ONNX with softmax."""
    try:
        import torch
        from torch import nn
    except Exception as exc:  # pragma: no cover - env dependent
        raise ExportError(
            "PyTorch is required to export ONNX; pip install -r trainer/requirements.txt"
        ) from exc

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    class _WithSoftmax(nn.Module):
        def __init__(self, inner: nn.Module) -> None:
            super().__init__()
            self.inner = inner
            self.softmax = nn.Softmax(dim=1)

        def forward(self, x):
            return self.softmax(self.inner(x))

    wrapped = _WithSoftmax(model)
    wrapped.eval()
    dummy = torch.zeros(1, INPUT_SIZE, dtype=torch.float32)
    torch.onnx.export(
        wrapped,
        dummy,
        str(path),
        opset_version=ONNX_OPSET,
        input_names=[ONNX_INPUT_NAME],
        output_names=[ONNX_OUTPUT_NAME],
        dynamic_axes=None,  # fixed batch = 1
        do_constant_folding=True,
    )
    return path


def export_bundle(
    model: Any,
    arch: Architecture,
    normalizer: Any,
    metrics: dict[str, Any],
    recipe: Any,
    dataset_ids: list[str],
    out_dir: str | Path,
    *,
    name: str | None = None,
    trainer_version: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Write all five bundle files.  Returns ``{"dir", "files", "metadata"}``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    onnx_path = out / "model.onnx"
    export_onnx(model, onnx_path)
    model_hash = sha256_file(onnx_path)  # hash the bytes actually written

    resolved_recipe = build_recipe_json(recipe)
    model_name = name or resolved_recipe.get("name") or "flow-classifier"
    ids = list(dataset_ids) or [d["id"] for d in resolved_recipe.get("datasets", [])]

    metadata = build_metadata(
        name=model_name,
        arch=arch,
        training_dataset_ids=ids,
        model_hash=model_hash,
        parameter_count=arch.parameter_count(),
        trainer_version=trainer_version,
        created_at=created_at,
    )
    validate_metadata(metadata)

    files = write_bundle_json(
        out,
        metadata=metadata,
        normalizer_json=normalizer.to_json() if hasattr(normalizer, "to_json") else normalizer,
        metrics_json=build_metrics_json(metrics),
        recipe_json=resolved_recipe,
    )
    files["model.onnx"] = str(onnx_path)

    missing = [f for f in BUNDLE_FILES if not (out / f).is_file()]
    if missing:
        raise ExportError(f"bundle incomplete, missing: {missing}")

    return {"dir": str(out), "files": files, "metadata": metadata}
