"""Configurable hidden architecture for a locked-edge MLP family.

The input layer is always 48.  The output layer is locked per family (PROJECT.md
§10, §28.6, ADR 0037): 7 for ``flow-classifier-v1`` (the supervised classifier),
48 for ``flow-anomaly-v1`` (the reconstruction autoencoder).  Only the hidden
stack is editable.  This module is the compute half of the Architecture Builder
(issue #22): parameter count, fp32 size and a rough FLOP estimate, with no torch
dependency so the daemon-less ``inspect-arch`` CLI and the UI can both call it.

Parameter-count model (matches a plain PyTorch MLP built by :mod:`train`):

* Dense layer ``prev -> width``            : ``prev * width + width``   (weight + bias)
* BatchNorm1d(width) when ``batchnorm``    : ``2 * width``              (gamma + beta;
  running mean/var are buffers, not parameters)
* activation / dropout / residual add-on   : 0 trainable parameters
* output Dense ``last_hidden -> 7``        : ``last_hidden * 7 + 7``

``rough_flops`` counts inference multiply-accumulates as ``2 * in * out`` per
Dense layer (the dominant term; activations and norm are ignored).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .schema import INPUT_SIZE, OUTPUT_SIZE

LOCKED_INPUT = INPUT_SIZE
LOCKED_OUTPUT = OUTPUT_SIZE

CLASSIFIER_FAMILY = "flow-classifier-v1"
ANOMALY_FAMILY = "flow-anomaly-v1"

# The locked output width per model family. flow-anomaly-v1 reconstructs the
# 48-value feature vector, so its output equals the input (ADR 0037).
FAMILY_OUTPUT: dict[str, int] = {
    CLASSIFIER_FAMILY: OUTPUT_SIZE,
    ANOMALY_FAMILY: INPUT_SIZE,
}

ACTIVATIONS = frozenset(
    {"relu", "leaky_relu", "gelu", "elu", "selu", "tanh", "sigmoid", "identity"}
)


class ArchitectureError(ValueError):
    """An architecture or a hidden layer is invalid."""


@dataclass
class HiddenLayer:
    """One hidden block: Dense -> [BatchNorm] -> activation -> [Dropout]."""

    width: int
    activation: str = "relu"
    dropout: float = 0.0
    batchnorm: bool = False
    residual: bool = False

    def __post_init__(self) -> None:
        self.width = int(self.width)
        self.activation = str(self.activation).lower()
        self.dropout = float(self.dropout)
        self.batchnorm = bool(self.batchnorm)
        self.residual = bool(self.residual)
        if self.width <= 0:
            raise ArchitectureError(f"hidden width must be > 0, got {self.width}")
        if not 0.0 <= self.dropout < 1.0:
            raise ArchitectureError(
                f"dropout must be in [0, 1), got {self.dropout}"
            )
        if self.activation not in ACTIVATIONS:
            raise ArchitectureError(
                f"unknown activation {self.activation!r}; expected one of {sorted(ACTIVATIONS)}"
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "width": self.width,
            "activation": self.activation,
            "dropout": self.dropout,
            "batchnorm": self.batchnorm,
            "residual": self.residual,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "HiddenLayer":
        return cls(
            width=d["width"],
            activation=d.get("activation", "relu"),
            dropout=d.get("dropout", 0.0),
            batchnorm=d.get("batchnorm", False),
            residual=d.get("residual", False),
        )


@dataclass
class Architecture:
    """A locked-edge MLP (48 in, family-locked out) with a configurable hidden stack.

    ``family`` selects the locked output width (see :data:`FAMILY_OUTPUT`); it
    defaults to ``flow-classifier-v1`` and is intentionally *not* emitted by
    :meth:`to_json` — the metadata bundle carries ``family`` at the top level and
    the Go ``schema.Architecture`` has no such field.
    """

    hidden: list[HiddenLayer] = field(default_factory=list)
    input_size: int = LOCKED_INPUT
    output_size: int = LOCKED_OUTPUT
    family: str = CLASSIFIER_FAMILY

    def __post_init__(self) -> None:
        self.family = str(self.family or CLASSIFIER_FAMILY)
        if self.family not in FAMILY_OUTPUT:
            raise ArchitectureError(
                f"unknown model family {self.family!r}; expected one of {sorted(FAMILY_OUTPUT)}"
            )
        locked_output = FAMILY_OUTPUT[self.family]
        if self.input_size != LOCKED_INPUT:
            raise ArchitectureError(
                f"input_size is locked at {LOCKED_INPUT} for {self.family}, got {self.input_size}"
            )
        if self.output_size != locked_output:
            raise ArchitectureError(
                f"output_size is locked at {locked_output} for {self.family}, got {self.output_size}"
            )
        self.hidden = [
            h if isinstance(h, HiddenLayer) else HiddenLayer.from_json(h) for h in self.hidden
        ]
        self._validate()

    def _validate(self) -> None:
        prev = self.input_size
        for i, layer in enumerate(self.hidden):
            if layer.residual and prev != layer.width:
                raise ArchitectureError(
                    f"hidden[{i}] has residual=true but the previous width ({prev}) "
                    f"!= this width ({layer.width}); a residual skip needs matching widths"
                )
            prev = layer.width

    # ---- sizing ------------------------------------------------------------

    def widths(self) -> list[int]:
        """Full layer sizing, input .. output inclusive."""
        return [self.input_size, *(h.width for h in self.hidden), self.output_size]

    def parameter_count(self) -> int:
        total = 0
        prev = self.input_size
        for layer in self.hidden:
            total += prev * layer.width + layer.width  # Dense weight + bias
            if layer.batchnorm:
                total += 2 * layer.width  # gamma + beta
            prev = layer.width
        total += prev * self.output_size + self.output_size  # output Dense
        return int(total)

    def estimated_size_bytes(self) -> int:
        """Raw fp32 parameter storage (4 bytes each)."""
        return self.parameter_count() * 4

    def rough_flops(self) -> int:
        """Approx multiply-accumulate FLOPs for one forward pass (batch 1)."""
        flops = 0
        prev = self.input_size
        for layer in self.hidden:
            flops += 2 * prev * layer.width
            prev = layer.width
        flops += 2 * prev * self.output_size
        return int(flops)

    # ---- serialisation ---------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "input_size": self.input_size,
            "output_size": self.output_size,
            "hidden": [h.to_json() for h in self.hidden],
        }

    # ``metadata.json`` uses the identical shape; kept as an explicit alias so
    # the contract is greppable from export.py.
    to_metadata_dict = to_json

    @classmethod
    def from_json(
        cls, d: dict[str, Any], *, family: str = CLASSIFIER_FAMILY
    ) -> "Architecture":
        fam = str(d.get("family") or family or CLASSIFIER_FAMILY)
        return cls(
            hidden=[HiddenLayer.from_json(h) for h in d.get("hidden", [])],
            input_size=int(d.get("input_size", LOCKED_INPUT)),
            output_size=int(d.get("output_size", FAMILY_OUTPUT.get(fam, LOCKED_OUTPUT))),
            family=fam,
        )

    def summary(self) -> str:
        rows = [f"INPUT {self.input_size} [LOCKED]"]
        for h in self.hidden:
            bits = [f"Dense {h.width}", h.activation.upper()]
            if h.batchnorm:
                bits.append("BatchNorm")
            if h.dropout > 0:
                bits.append(f"Dropout {h.dropout:g}")
            if h.residual:
                bits.append("Residual")
            rows.append(" / ".join(bits))
        rows.append(f"OUTPUT {self.output_size} [LOCKED]")
        return "\n    |\n".join(rows)


def default_architecture(family: str = CLASSIFIER_FAMILY) -> Architecture:
    """A small, sane starting net for a family.

    ``flow-classifier-v1``: ``48 -> 64 -> 32 -> 7``.
    ``flow-anomaly-v1``: a symmetric ``48 -> 32 -> 16 -> 32 -> 48`` autoencoder.
    """
    if family == ANOMALY_FAMILY:
        return Architecture(
            hidden=[
                HiddenLayer(32, "relu"),
                HiddenLayer(16, "relu"),
                HiddenLayer(32, "relu"),
            ],
            output_size=FAMILY_OUTPUT[ANOMALY_FAMILY],
            family=ANOMALY_FAMILY,
        )
    return Architecture(
        hidden=[
            HiddenLayer(64, "relu", dropout=0.3, batchnorm=True),
            HiddenLayer(32, "relu", dropout=0.2),
        ]
    )


def loads(text: str) -> Architecture:
    return Architecture.from_json(json.loads(text))


def dumps(arch: Architecture, *, indent: int | None = 2) -> str:
    return json.dumps(arch.to_json(), indent=indent)
