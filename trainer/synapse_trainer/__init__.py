"""synapse-trainer — the SynapseIDS Phase 2 offline training service.

Turns a labelled ``flow-features-v1`` dataset into a deployable model bundle
(``model.onnx`` + ``metadata.json`` + ``normalizer.json`` + ``metrics.json`` +
``training-recipe.json``) that the Go daemon validates and runs (PROJECT.md
§5.4, §10, §11).

Heavy, optional dependencies (``torch``, ``onnx``, ``onnxruntime``) are imported
lazily and behind guards, so this package — and every module that does not
actually train or export an ONNX graph — imports and runs with only ``numpy``
present.  See ``trainer/README.md`` and ``docs/adr/0007``.
"""

from __future__ import annotations

__all__ = ["__version__"]

# Version of the *trainer*, not of the SynapseIDS repo.  Written verbatim into
# every bundle's ``metadata.json`` as ``trainer_version`` (PROJECT.md §11).
__version__ = "0.1.0"
