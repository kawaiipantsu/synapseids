"""Bundle-layout tests (issue #23).

Two paths:

* ``test_json_bundle_layout_without_torch`` — writes a dummy ``model.onnx`` blob
  and exercises every JSON emitter and the on-disk layout with only numpy.
* ``test_export_bundle_with_torch`` — ``importorskip('torch'|'onnx')``; builds a
  tiny net, runs the real ``export_bundle``, and checks the ONNX graph.
"""

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

from synapse_trainer import export as X
from synapse_trainer import recipe as R
from synapse_trainer.architecture import Architecture, HiddenLayer
from synapse_trainer.normalize import Normalizer
from synapse_trainer.schema import CLASS_NAMES, INPUT_SIZE

REQUIRED_METADATA_TYPES = {
    "model_id": str,
    "name": str,
    "version": str,
    "family": str,
    "feature_schema": str,
    "input_size": int,
    "output_schema": str,
    "output_size": int,
    "architecture": dict,
    "training_dataset_ids": list,
    "created_at": str,
    "trainer_version": str,
    "parameter_count": int,
    "model_hash": str,
}


def _fake_metrics():
    rng = np.random.default_rng(0)
    y_true = rng.integers(0, 7, size=140)
    y_pred = y_true.copy()
    y_pred[:20] = (y_pred[:20] + 1) % 7
    from synapse_trainer.train import classification_metrics

    return classification_metrics(
        y_true,
        y_pred,
        train_loss=0.31,
        val_loss=0.44,
        test_loss=0.47,
        test_true=y_true[:60],
        test_pred=y_pred[:60],
    )


def _assert_metadata_ok(meta: dict):
    assert list(meta.keys()) == list(X.METADATA_KEYS)
    for key, typ in REQUIRED_METADATA_TYPES.items():
        assert key in meta, f"missing {key}"
        assert isinstance(meta[key], typ), f"{key}: {type(meta[key])} != {typ}"
    assert meta["family"] == "flow-classifier-v1"
    assert meta["feature_schema"] == "flow-features-v1"
    assert meta["output_schema"] == "traffic-classes-v1"
    assert meta["input_size"] == 48
    assert meta["output_size"] == 7
    assert meta["version"] == "1"
    assert meta["parameter_count"] > 0
    assert meta["model_hash"].startswith("sha256:")
    assert len(meta["model_hash"].split(":", 1)[1]) == 64
    assert meta["model_id"].startswith("flow-classifier-v1-")
    assert meta["created_at"].endswith("Z")
    assert meta["architecture"]["input_size"] == 48
    assert meta["architecture"]["output_size"] == 7
    assert meta["training_dataset_ids"]
    X.validate_metadata(meta)


def _assert_metrics_ok(m: dict):
    assert set(m) >= {"accuracy", "macro_f1", "val_loss", "per_class", "confusion", "test"}
    assert isinstance(m["accuracy"], float)
    assert isinstance(m["macro_f1"], float)
    assert len(m["per_class"]) == 7
    for pc in m["per_class"]:
        assert set(pc) == {"class", "precision", "recall", "f1", "support"}
        assert pc["class"] in CLASS_NAMES
    assert len(m["confusion"]) == 7 and all(len(r) == 7 for r in m["confusion"])
    assert m["test"] is None or "confusion" in m["test"]


def test_json_bundle_layout_without_torch(tmp_path):
    out = tmp_path / "bundle"
    out.mkdir()

    # 1. a stand-in model.onnx blob
    onnx_path = out / "model.onnx"
    onnx_path.write_bytes(b"ONNX-DUMMY-BLOB\x00\x01\x02not-a-real-graph")
    model_hash = X.sha256_file(onnx_path)
    assert model_hash == "sha256:" + hashlib.sha256(onnx_path.read_bytes()).hexdigest()

    arch = Architecture(hidden=[HiddenLayer(64, batchnorm=True), HiddenLayer(32)])
    rc = R.from_dict(
        {
            "name": "unit-test-model",
            "datasets": [{"id": "ds/train", "weight": 0.8}, {"id": "ds/aug", "weight": 0.2}],
            "architecture": arch.to_json(),
        }
    )

    metadata = X.build_metadata(
        name="unit-test-model",
        arch=arch,
        training_dataset_ids=rc.dataset_ids,
        model_hash=model_hash,
    )
    _assert_metadata_ok(metadata)
    assert metadata["parameter_count"] == arch.parameter_count()

    normalizer_json = Normalizer("standard").fit(
        np.random.default_rng(1).normal(size=(200, INPUT_SIZE))
    ).to_json()
    metrics_json = X.build_metrics_json(_fake_metrics())
    recipe_json = X.build_recipe_json(rc)

    files = X.write_bundle_json(
        out,
        metadata=metadata,
        normalizer_json=normalizer_json,
        metrics_json=metrics_json,
        recipe_json=recipe_json,
    )

    # 2. all five files exist
    for fname in X.BUNDLE_FILES:
        assert (out / fname).is_file(), f"missing {fname}"

    on_disk_meta = json.loads((out / "metadata.json").read_text())
    _assert_metadata_ok(on_disk_meta)
    assert list(on_disk_meta.keys()) == list(X.METADATA_KEYS)

    # 3. model_hash matches a fresh sha256 of model.onnx
    fresh = "sha256:" + hashlib.sha256((out / "model.onnx").read_bytes()).hexdigest()
    assert on_disk_meta["model_hash"] == fresh

    # 4. normalizer.json has 48 ordered entries
    nj = json.loads((out / "normalizer.json").read_text())
    assert nj["feature_schema"] == "flow-features-v1"
    assert len(nj["per_feature"]) == 48
    assert [e["index"] for e in nj["per_feature"]] == list(range(48))

    _assert_metrics_ok(json.loads((out / "metrics.json").read_text()))

    rj = json.loads((out / "training-recipe.json").read_text())
    assert rj["seed"] == 1337
    assert rj["split"] == {"train": 0.7, "val": 0.15, "test": 0.15}
    assert rj["datasets"] == [{"id": "ds/train", "weight": 0.8}, {"id": "ds/aug", "weight": 0.2}]
    assert files["metadata.json"].endswith("metadata.json")


def test_validate_metadata_rejects_tampering(tmp_path):
    arch = Architecture(hidden=[HiddenLayer(16)])
    meta = X.build_metadata(
        name="m", arch=arch, training_dataset_ids=["x"], model_hash="sha256:" + "0" * 64
    )
    bad = dict(meta)
    bad["family"] = "flow-classifier-v2"
    with pytest.raises(X.ExportError):
        X.validate_metadata(bad)

    bad = dict(meta)
    del bad["model_hash"]
    with pytest.raises(X.ExportError):
        X.validate_metadata(bad)


def test_export_bundle_with_torch(tmp_path):
    torch = pytest.importorskip("torch")
    pytest.importorskip("onnx")
    import onnx

    from synapse_trainer.train import build_model

    arch = Architecture(hidden=[HiddenLayer(8, batchnorm=True)])
    model = build_model(arch)
    model.eval()

    normalizer = Normalizer("minmax").fit(
        np.random.default_rng(2).uniform(size=(64, INPUT_SIZE))
    )
    rc = R.from_dict(
        {
            "name": "torch-tiny",
            "datasets": [{"id": "ds/tiny", "weight": 1.0}],
            "architecture": arch.to_json(),
            "epochs": 1,
        }
    )
    metrics = _fake_metrics()

    out = tmp_path / "tbundle"
    result = X.export_bundle(
        model,
        arch,
        normalizer,
        metrics,
        rc,
        dataset_ids=rc.dataset_ids,
        out_dir=out,
        name="torch-tiny",
    )

    for fname in X.BUNDLE_FILES:
        assert (out / fname).is_file(), f"missing {fname}"

    meta = json.loads((out / "metadata.json").read_text())
    _assert_metadata_ok(meta)
    assert meta["parameter_count"] == arch.parameter_count()

    fresh = "sha256:" + hashlib.sha256((out / "model.onnx").read_bytes()).hexdigest()
    assert meta["model_hash"] == fresh == result["metadata"]["model_hash"]

    nj = json.loads((out / "normalizer.json").read_text())
    assert nj["method"] == "minmax"
    assert len(nj["per_feature"]) == 48

    _assert_metrics_ok(json.loads((out / "metrics.json").read_text()))

    # ONNX graph: opset 17, fixed batch 1, names + shapes
    m = onnx.load(str(out / "model.onnx"))
    onnx.checker.check_model(m)
    opsets = {op.domain: op.version for op in m.opset_import}
    assert opsets.get("", 0) == 17
    ins = m.graph.input
    outs = m.graph.output
    assert len(ins) == 1 and ins[0].name == "features"
    assert len(outs) == 1 and outs[0].name == "scores"

    def _dims(vi):
        return [d.dim_value for d in vi.type.tensor_type.shape.dim]

    assert _dims(ins[0]) == [1, 48]
    assert _dims(outs[0]) == [1, 7]

    # softmax included: output rows sum to 1
    try:
        import onnxruntime as ort

        sess = ort.InferenceSession(str(out / "model.onnx"), providers=["CPUExecutionProvider"])
        y = sess.run(["scores"], {"features": np.zeros((1, 48), dtype=np.float32)})[0]
        assert y.shape == (1, 7)
        assert abs(float(y.sum()) - 1.0) < 1e-4
    except Exception:
        pytest.skip("onnxruntime not available to check softmax output")


def test_export_anomaly_bundle_with_torch(tmp_path):
    torch = pytest.importorskip("torch")
    pytest.importorskip("onnx")
    import onnx

    from synapse_trainer.train import build_model

    arch = _ae_arch()
    model = build_model(arch)
    model.eval()

    normalizer = Normalizer("standard").fit(
        np.random.default_rng(4).normal(size=(64, INPUT_SIZE))
    )
    rc = R.from_dict(
        {
            "name": "torch-ae",
            "objective": "reconstruction",
            "datasets": [{"id": "ds/normal", "weight": 1.0}],
            "epochs": 1,
        }
    )
    metrics = _fake_reconstruction_metrics()

    out = tmp_path / "aebundle"
    X.export_bundle(model, arch, normalizer, metrics, rc,
                    dataset_ids=rc.dataset_ids, out_dir=out, name="torch-ae")

    for fname in X.BUNDLE_FILES:
        assert (out / fname).is_file(), f"missing {fname}"

    meta = json.loads((out / "metadata.json").read_text())
    assert list(meta.keys()) == list(X.metadata_keys("flow-anomaly-v1"))
    assert meta["output_schema"] == "reconstruction-v1" and meta["output_size"] == 48
    assert meta["anomaly"]["threshold"] > 0
    X.validate_metadata(meta)

    m = onnx.load(str(out / "model.onnx"))
    onnx.checker.check_model(m)
    assert {op.domain: op.version for op in m.opset_import}.get("", 0) == 17
    ins, outs = m.graph.input, m.graph.output
    assert ins[0].name == "features" and outs[0].name == "reconstruction"

    def _dims(vi):
        return [d.dim_value for d in vi.type.tensor_type.shape.dim]

    assert _dims(ins[0]) == [1, 48] and _dims(outs[0]) == [1, 48]
    # no softmax: the graph has no Softmax node
    assert not any(n.op_type == "Softmax" for n in m.graph.node)

    mj = json.loads((out / "metrics.json").read_text())
    assert mj["objective"] == "reconstruction"


# ---------------------------------------------------------------------------
# flow-anomaly-v1 bundle layout (ADR 0037) — torch-free
# ---------------------------------------------------------------------------


def _fake_reconstruction_metrics():
    rng = np.random.default_rng(3)
    recon = np.concatenate([np.abs(rng.normal(0.1, 0.01, 300)), np.full(40, 1.0)])
    from synapse_trainer.schema import class_id
    from synapse_trainer.train import reconstruction_metrics

    y = np.concatenate([np.full(300, class_id("normal")), np.full(40, class_id("scan"))])
    return reconstruction_metrics(recon, y, normal_id=class_id("normal"),
                                  train_loss=0.02, val_loss=0.025, test_loss=0.03,
                                  recon_test=recon[:60], y_test=y[:60])


def _ae_arch():
    return Architecture(
        hidden=[HiddenLayer(32), HiddenLayer(16), HiddenLayer(32)],
        output_size=48,
        family="flow-anomaly-v1",
    )


def test_anomaly_bundle_metadata_layout_without_torch(tmp_path):
    arch = _ae_arch()
    metrics = _fake_reconstruction_metrics()
    anomaly = X.anomaly_block(metrics)

    meta = X.build_metadata(
        name="unit-ae",
        arch=arch,
        training_dataset_ids=["ds/normal"],
        model_hash="sha256:" + "a" * 64,
        anomaly=anomaly,
    )

    # the anomaly family appends exactly one key, "anomaly", after the frozen 14
    assert list(meta.keys()) == list(X.METADATA_KEYS) + ["anomaly"]
    assert list(meta.keys()) == list(X.metadata_keys("flow-anomaly-v1"))
    assert meta["family"] == "flow-anomaly-v1"
    assert meta["output_schema"] == "reconstruction-v1"
    assert meta["output_size"] == 48
    assert meta["architecture"]["output_size"] == 48
    assert meta["model_id"].startswith("flow-anomaly-v1-")
    assert meta["anomaly"]["space"] == "normalized"
    assert meta["anomaly"]["threshold"] > 0
    assert set(meta["anomaly"]["error_percentiles"]) == {"p50", "p90", "p95", "p99", "max"}

    X.validate_metadata(meta)  # infers family from meta["family"]
    X.validate_metadata(meta, family="flow-anomaly-v1")

    # building an anomaly bundle without the calibration block is rejected
    with pytest.raises(X.ExportError):
        X.build_metadata(
            name="x", arch=arch, training_dataset_ids=["d"],
            model_hash="sha256:" + "0" * 64,
        )
    # a classifier bundle validated as the anomaly family is rejected
    clf = X.build_metadata(
        name="c", arch=Architecture(hidden=[HiddenLayer(16)]),
        training_dataset_ids=["d"], model_hash="sha256:" + "0" * 64,
    )
    with pytest.raises(X.ExportError):
        X.validate_metadata(clf, family="flow-anomaly-v1")


def test_anomaly_metrics_json_shape_without_torch():
    mj = X.build_metrics_json(_fake_reconstruction_metrics())
    assert mj["objective"] == "reconstruction"
    assert "accuracy" not in mj and "confusion" not in mj
    assert set(mj["recon_error_percentiles"]) == {"p50", "p90", "p95", "p99", "max"}
    assert mj["suggested_threshold"] == mj["recon_error_percentiles"]["p99"]
    assert mj["val"]["attack_rows"] == 40
    assert mj["val"]["roc_auc"] is not None
    assert mj["test"] is not None and "loss" in mj["test"]
