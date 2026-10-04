import pytest
from synapse_trainer.workbench import temporal_split, safe_id, evaluate, Network
import torch


def test_conversations_never_cross_partitions_and_embargo():
    rows = []
    for i in range(100):
        for _ in range(2):
            rows.append(dict(group="capture", conversation=str(i), time=i * 10))
    splits, info = temporal_split(rows)
    sets = [{rows[i]["conversation"] for i in part} for part in splits]
    assert all(sets) and not sets[0] & sets[1] and not sets[1] & sets[2]
    assert info["purged_rows"] > 0
    assert len(splits[0]) + len(splits[1]) + len(splits[2]) + info["purged_rows"] == len(rows)


def test_absent_classes_are_masked_and_metrics_report_support():
    net = Network(64, 4, {0, 2})
    logits = net(torch.zeros(3, 160))
    scores = torch.softmax(logits, 1)
    assert torch.all(scores[:, [1, 3]] == 0)
    metrics = evaluate(
        logits.detach(), torch.tensor([0, 2, 2]), ["normal", "scan", "botnet", "unknown"], {0, 2}
    )
    assert len(metrics["confusion"]) == 4
    assert metrics["per_class"][1]["trained"] is False
    assert sum(x["support"] for x in metrics["per_class"]) == 3


def test_paths_cannot_escape():
    with pytest.raises(ValueError):
        safe_id("../secret")


def test_bounded_training_exports_onnx_coverage_and_progress(tmp_path):
    import hashlib
    import json
    from pathlib import Path
    import numpy as np
    import onnxruntime as ort
    from synapse_trainer.workbench import train

    corpora = tmp_path / "corpora"
    corpora.mkdir()
    rows = []
    for i in range(200):
        rows.append(
            dict(
                values=[float(i % 2), float(i)] + [0.0] * 158,
                label="normal" if i % 2 else "scan",
                group="synthetic-test",
                conversation=str(i),
                time=i * 10,
            )
        )
    data = "".join(json.dumps(row) + "\n" for row in rows).encode()
    (corpora / "sample.jsonl").write_bytes(data)
    (corpora / "sample.json").write_text(
        json.dumps(
            dict(
                id="sample",
                task="attack",
                rows=len(rows),
                digest="sha256:" + hashlib.sha256(data).hexdigest(),
            )
        )
    )
    request = dict(
        task="attack",
        corpora=["sample"],
        max_rows=1000,
        width=64,
        epochs=2,
        false_positive_cost=2,
        missed_attack_cost=2,
    )
    progress = []
    result = train(
        tmp_path,
        tmp_path / "models",
        Path(__file__).resolve().parents[2] / "schemas",
        request,
        progress.append,
        lambda: False,
        "test-candidate",
    )
    assert result["supported_classes"] == ["normal", "scan"]
    assert result["samples_test"] > 5
    assert result["split"]["purged_rows"] > 0
    assert len(progress) == 2 and progress[-1]["lr"] == 0.001
    assert progress[-1]["batches"] == progress[-1]["batches_total"]
    bundle = tmp_path / "models" / "test-candidate"
    normalizer = json.loads((bundle / "normalizer.json").read_text())
    assert normalizer["transform"] == "signed_log1p" and normalizer["clip"] == 8
    assert len(normalizer["per_feature"]) == 160
    assert normalizer["per_feature"][1]["mean"] < np.log1p(100)
    session = ort.InferenceSession(str(bundle / "model.onnx"), providers=["CPUExecutionProvider"])
    scores = session.run(None, {"features": np.zeros((1, 160), dtype=np.float32)})[0]
    assert scores.shape == (1, 19) and abs(scores.sum() - 1) < 1e-6
    assert np.all(scores[0, 2:] == 0)

    (corpora / "sample.jsonl").write_bytes(data + b"\n")
    with pytest.raises((ValueError, json.JSONDecodeError)):
        train(
            tmp_path,
            tmp_path / "models",
            Path(__file__).resolve().parents[2] / "schemas",
            request,
            progress.append,
            lambda: False,
            "tampered-candidate",
        )
    assert not (tmp_path / "models" / "tampered-candidate").exists()
