"""Read the repo's frozen data contracts and expose them as Python constants.

``flow-features-v1`` (48 features) and ``traffic-classes-v1`` (7 classes) are
immutable, ordered contracts (PROJECT.md §8, §9, §28.5-6; ADR 0002).  The trainer
must train against *exactly* the vector the Go daemon extracts, so it reads the
same JSON the daemon embeds — it never hard-codes the list.

Resolution order for the ``schemas/`` directory:

1. ``$SYNAPSE_SCHEMA_DIR`` if set (must contain ``features/`` and ``outputs/``);
2. the repo root inferred from this file's location (``trainer/synapse_trainer``
   → repo root ``schemas/``);
3. a ``schemas/`` directory found by walking up from the current directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

FEATURE_SCHEMA = "flow-features-v1"
OUTPUT_SCHEMA = "traffic-classes-v1"


class SchemaNotFound(RuntimeError):
    """The frozen schema JSON could not be located on disk."""


class SchemaMismatch(ValueError):
    """A dataset's declared schema is incompatible with this trainer build."""


def _candidate_dirs() -> list[Path]:
    cands: list[Path] = []
    env = os.environ.get("SYNAPSE_SCHEMA_DIR")
    if env:
        cands.append(Path(env).expanduser())
    here = Path(__file__).resolve()
    # trainer/synapse_trainer/schema.py -> parents[2] == repo root
    for up in (2, 3, 4):
        if len(here.parents) > up:
            cands.append(here.parents[up] / "schemas")
    for base in (Path.cwd(), *Path.cwd().parents):
        cands.append(base / "schemas")
    return cands


def find_schema_dir() -> Path:
    """Return the directory that holds ``features/`` and ``outputs/``."""
    for c in _candidate_dirs():
        if (c / "features" / f"{FEATURE_SCHEMA}.json").is_file():
            return c
    raise SchemaNotFound(
        "could not locate the frozen schemas/ directory; set $SYNAPSE_SCHEMA_DIR "
        "to the directory containing features/flow-features-v1.json and "
        "outputs/traffic-classes-v1.json"
    )


def _load(name: str, subdir: str) -> dict[str, Any]:
    path = find_schema_dir() / subdir / f"{name}.json"
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


_FEATURES_DOC = _load(FEATURE_SCHEMA, "features")
_CLASSES_DOC = _load(OUTPUT_SCHEMA, "outputs")

# ---- derived constants -------------------------------------------------------

_FEATURES = sorted(_FEATURES_DOC["features"], key=lambda f: f["index"])
_CLASSES = sorted(_CLASSES_DOC["classes"], key=lambda c: c["index"])

FEATURE_NAMES: list[str] = [f["name"] for f in _FEATURES]
CLASS_NAMES: list[str] = [c["name"] for c in _CLASSES]

INPUT_SIZE: int = int(_FEATURES_DOC["input_size"])
OUTPUT_SIZE: int = int(_CLASSES_DOC["output_size"])

# Fail loudly at import time on any drift between the JSON's own count fields and
# its arrays — the same invariant internal/schema enforces in Go (ADR 0002).
if len(FEATURE_NAMES) != INPUT_SIZE:
    raise SchemaMismatch(
        f"{FEATURE_SCHEMA}: input_size={INPUT_SIZE} but {len(FEATURE_NAMES)} features listed"
    )
if [f["index"] for f in _FEATURES] != list(range(INPUT_SIZE)):
    raise SchemaMismatch(f"{FEATURE_SCHEMA}: feature indices are not 0..{INPUT_SIZE - 1} in order")
if len(CLASS_NAMES) != OUTPUT_SIZE:
    raise SchemaMismatch(
        f"{OUTPUT_SCHEMA}: output_size={OUTPUT_SIZE} but {len(CLASS_NAMES)} classes listed"
    )
if [c["index"] for c in _CLASSES] != list(range(OUTPUT_SIZE)):
    raise SchemaMismatch(f"{OUTPUT_SCHEMA}: class indices are not 0..{OUTPUT_SIZE - 1} in order")

DEFAULT_MISSING: float = float(_FEATURES_DOC.get("default_missing", 0.0))


def feature_index(name: str) -> int:
    """Return the frozen column index of a feature, or raise ``KeyError``."""
    try:
        return FEATURE_NAMES.index(name)
    except ValueError as exc:  # pragma: no cover - trivial
        raise KeyError(f"unknown flow-features-v1 feature: {name!r}") from exc


def class_id(label: str | int) -> int:
    """Map a class name or an integer id to its ``traffic-classes-v1`` index."""
    if isinstance(label, (int,)) or (isinstance(label, str) and label.strip().lstrip("-").isdigit()):
        idx = int(label)
        if not 0 <= idx < OUTPUT_SIZE:
            raise SchemaMismatch(f"class id {idx} out of range 0..{OUTPUT_SIZE - 1}")
        return idx
    try:
        return CLASS_NAMES.index(str(label).strip())
    except ValueError as exc:
        raise SchemaMismatch(
            f"unknown traffic-classes-v1 label {label!r}; expected one of {CLASS_NAMES} or 0..{OUTPUT_SIZE - 1}"
        ) from exc


def check_compatible(dataset_meta: dict[str, Any]) -> None:
    """Raise :class:`SchemaMismatch` if a dataset is not trainable by this build.

    Checks the declared ``feature_schema`` / ``output_schema`` names and, when
    the meta carries a column count under any of ``feature_count`` /
    ``input_size`` / ``num_features`` / ``feature_names`` / ``columns``, that it
    equals :data:`INPUT_SIZE`.  Likewise for the class count when present
    (PROJECT.md §5.4, §25).
    """
    fs = dataset_meta.get("feature_schema")
    if fs is not None and fs != FEATURE_SCHEMA:
        raise SchemaMismatch(
            f"dataset feature_schema={fs!r} but this trainer builds {FEATURE_SCHEMA!r}"
        )
    os_ = dataset_meta.get("output_schema")
    if os_ is not None and os_ != OUTPUT_SCHEMA:
        raise SchemaMismatch(
            f"dataset output_schema={os_!r} but this trainer builds {OUTPUT_SCHEMA!r}"
        )

    count = None
    for key in ("feature_count", "input_size", "num_features"):
        if key in dataset_meta and dataset_meta[key] is not None:
            count = int(dataset_meta[key])
            break
    if count is None:
        for key in ("feature_names", "columns"):
            seq = dataset_meta.get(key)
            if seq is not None:
                # a "columns" list may legitimately include the label column
                count = len([c for c in seq if c != "label"])
                break
    if count is not None and count != INPUT_SIZE:
        raise SchemaMismatch(
            f"dataset has {count} feature columns but {FEATURE_SCHEMA} needs exactly {INPUT_SIZE}"
        )

    nclasses = None
    for key in ("output_size", "num_classes", "class_count"):
        if key in dataset_meta and dataset_meta[key] is not None:
            nclasses = int(dataset_meta[key])
            break
    if nclasses is not None and nclasses != OUTPUT_SIZE:
        raise SchemaMismatch(
            f"dataset declares {nclasses} classes but {OUTPUT_SCHEMA} locks {OUTPUT_SIZE}"
        )
