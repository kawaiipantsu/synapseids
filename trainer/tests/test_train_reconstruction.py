"""Autoencoder (reconstruction) metrics — the torch-free half of ADR 0037.

``reconstruction_metrics`` and ``_roc_auc`` are numpy-only, so they run in the
no-torch CI job exactly like the classification metrics do.
"""

from __future__ import annotations

import numpy as np
import pytest

from synapse_trainer import schema
from synapse_trainer.train import _roc_auc, reconstruction_metrics

NORMAL = schema.class_id("normal")
SCAN = schema.class_id("scan")


def test_roc_auc_matches_the_rank_sum_identity():
    # perfectly separable: every positive scores above every negative -> AUC 1
    scores = np.array([0.1, 0.2, 0.3, 0.9, 1.0])
    pos = np.array([False, False, False, True, True])
    assert _roc_auc(scores, pos) == pytest.approx(1.0)
    # reversed -> AUC 0
    assert _roc_auc(-scores, pos) == pytest.approx(0.0)
    # a coin flip on interleaved ties sits at 0.5
    s = np.array([1.0, 1.0, 1.0, 1.0])
    assert _roc_auc(s, np.array([True, False, True, False])) == pytest.approx(0.5)
    # no positives or no negatives -> undefined
    assert _roc_auc(scores, np.zeros(5, dtype=bool)) is None


def test_reconstruction_metrics_percentiles_threshold_and_separation():
    rng = np.random.default_rng(0)
    # NORMAL rows: small error ~0.1; attack rows: large error ~1.0
    normal_err = np.abs(rng.normal(0.1, 0.01, size=400))
    attack_err = np.abs(rng.normal(1.0, 0.05, size=60))
    recon = np.concatenate([normal_err, attack_err])
    y = np.concatenate([np.full(400, NORMAL), np.full(60, SCAN)])

    m = reconstruction_metrics(recon, y, normal_id=NORMAL, train_loss=0.01, val_loss=0.012)

    assert m["objective"] == "reconstruction"
    pct = m["recon_error_percentiles"]
    # percentiles are measured over the NORMAL rows only, so they sit near 0.1
    assert 0.08 < pct["p50"] < 0.12
    assert pct["p99"] < 0.2
    assert m["suggested_threshold"] == pct["p99"]
    assert m["threshold_percentile"] == "p99"

    sep = m["val"]
    assert sep["normal_rows"] == 400 and sep["attack_rows"] == 60
    # the two clusters are cleanly separated
    assert sep["roc_auc"] > 0.99
    assert sep["tpr_at_threshold"] == pytest.approx(1.0)
    assert sep["fpr_at_threshold"] < 0.05


def test_reconstruction_metrics_without_attack_rows_still_gives_a_threshold():
    recon = np.abs(np.random.default_rng(1).normal(0.2, 0.02, size=100))
    y = np.full(100, NORMAL)
    m = reconstruction_metrics(recon, y, normal_id=NORMAL)
    assert m["suggested_threshold"] > 0
    assert m["val"]["roc_auc"] is None  # nothing to separate
    assert "tpr_at_threshold" not in m["val"]


def test_reconstruction_metrics_carries_a_test_block():
    recon_v = np.abs(np.random.default_rng(2).normal(0.1, 0.01, size=50))
    y_v = np.full(50, NORMAL)
    recon_t = np.concatenate([np.full(20, 0.1), np.full(10, 2.0)])
    y_t = np.concatenate([np.full(20, NORMAL), np.full(10, SCAN)])
    m = reconstruction_metrics(
        recon_v, y_v, normal_id=NORMAL, test_loss=0.5, recon_test=recon_t, y_test=y_t
    )
    assert m["test"]["attack_rows"] == 10
    assert m["test"]["loss"] == 0.5
    assert m["test"]["roc_auc"] == pytest.approx(1.0)
