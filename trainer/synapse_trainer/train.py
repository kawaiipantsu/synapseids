"""Build and train the MLP described by an :class:`~.architecture.Architecture`.

``torch`` is imported behind a guard: this module imports with only numpy
present, and everything that does not actually run a forward/backward pass
(``confusion_and_prf``, ``classification_metrics``) works without it.  Anything
that needs torch raises a clear :class:`TrainingUnavailable` instead.

The ``X_train`` / ``y_train`` handed in are the **combined, weighted** training
mixture and ``X_val`` / ``y_val`` the merged validation set that
:func:`synapse_trainer.mixture.build_mixture` produced from every dataset in the
recipe — this module never loads or splits data itself, so the "split each
dataset before mixing" guarantee cannot be bypassed here (PROJECT.md §14).

``train_iter`` is a generator that yields one progress dict per epoch and a
final ``{"event": "done", "metrics": {...}}``; ``run_training`` drains it,
optionally POSTing each dict as a JSON line to a ``progress_url`` (a no-op when
unset), and returns ``(model, metrics)`` (PROJECT.md §10, §19.8, §28.8).
"""

from __future__ import annotations

import json
import random
import time
import urllib.request
from typing import Any, Iterator

import numpy as np

from .architecture import Architecture
from .recipe import Recipe
from .schema import CLASS_NAMES, OUTPUT_SIZE, class_id

try:  # heavy, optional
    import torch
    from torch import nn

    _HAVE_TORCH = True
except Exception:  # pragma: no cover - depends on the environment
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]
    _HAVE_TORCH = False


class TrainingUnavailable(RuntimeError):
    """Raised when a torch-only code path is reached without torch installed."""

    def __init__(self) -> None:
        super().__init__(
            "PyTorch is not installed; run `pip install -r trainer/requirements.txt` "
            "(or `pip install -e trainer/`) to train or export models"
        )


def have_torch() -> bool:
    return _HAVE_TORCH


# --------------------------------------------------------------------------
# Pure-numpy metrics (no torch needed)
# --------------------------------------------------------------------------


def confusion_and_prf(
    y_true: Any, y_pred: Any, num_classes: int = OUTPUT_SIZE
) -> dict[str, Any]:
    """Confusion matrix + per-class precision/recall/F1/support + macro means."""
    yt = np.asarray(y_true, dtype=np.int64).ravel()
    yp = np.asarray(y_pred, dtype=np.int64).ravel()
    if yt.shape != yp.shape:
        raise ValueError(f"y_true {yt.shape} vs y_pred {yp.shape}")
    k = int(num_classes)
    cm = np.zeros((k, k), dtype=np.int64)
    for t, p in zip(yt, yp):
        cm[t, p] += 1

    support = cm.sum(axis=1)
    pred_pos = cm.sum(axis=0)
    tp = np.diag(cm).astype(np.float64)
    precision = np.divide(tp, pred_pos, out=np.zeros(k), where=pred_pos > 0)
    recall = np.divide(tp, support, out=np.zeros(k), where=support > 0)
    denom = precision + recall
    f1 = np.divide(2 * precision * recall, denom, out=np.zeros(k), where=denom > 0)

    accuracy = float(tp.sum() / cm.sum()) if cm.sum() else 0.0
    return {
        "accuracy": accuracy,
        "macro_precision": float(precision.mean()),
        "macro_recall": float(recall.mean()),
        "macro_f1": float(f1.mean()),
        "per_class": [
            {
                "class": CLASS_NAMES[i] if i < len(CLASS_NAMES) else str(i),
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
                "support": int(support[i]),
            }
            for i in range(k)
        ],
        "confusion": cm.tolist(),
    }


def classification_metrics(
    y_true: Any,
    y_pred: Any,
    *,
    train_loss: float | None = None,
    val_loss: float | None = None,
    test_loss: float | None = None,
    test_true: Any = None,
    test_pred: Any = None,
) -> dict[str, Any]:
    """Assemble the metrics dict the bundle's ``metrics.json`` is built from."""
    m = confusion_and_prf(y_true, y_pred)
    m["train_loss"] = train_loss
    m["val_loss"] = val_loss
    m["test_loss"] = test_loss
    if test_true is not None and test_pred is not None:
        t = confusion_and_prf(test_true, test_pred)
        m["test"] = {
            "accuracy": t["accuracy"],
            "macro_f1": t["macro_f1"],
            "macro_precision": t["macro_precision"],
            "macro_recall": t["macro_recall"],
            "loss": test_loss,
            "per_class": t["per_class"],
            "confusion": t["confusion"],
        }
    return m


_RECON_PCTS = (50, 90, 95, 99)


def _roc_auc(scores: np.ndarray, positive: np.ndarray) -> float | None:
    """ROC-AUC via the rank-sum (Mann–Whitney) identity. numpy only."""
    pos = scores[positive]
    neg = scores[~positive]
    if pos.size == 0 or neg.size == 0:
        return None
    order = np.argsort(np.concatenate([neg, pos]), kind="mergesort")
    ranks = np.empty(order.size, dtype=np.float64)
    ranks[order] = np.arange(1, order.size + 1)
    # average ties
    allv = np.concatenate([neg, pos])
    sv = allv[order]
    i = 0
    while i < sv.size:
        j = i
        while j + 1 < sv.size and sv[j + 1] == sv[i]:
            j += 1
        if j > i:
            ranks[order[i : j + 1]] = (i + 1 + j + 1) / 2.0
        i = j + 1
    rank_pos_sum = ranks[neg.size :].sum()
    auc = (rank_pos_sum - pos.size * (pos.size + 1) / 2.0) / (pos.size * neg.size)
    return float(auc)


def reconstruction_metrics(
    recon_val: Any,
    y_val: Any,
    *,
    normal_id: int,
    train_loss: float | None = None,
    val_loss: float | None = None,
    test_loss: float | None = None,
    recon_test: Any = None,
    y_test: Any = None,
) -> dict[str, Any]:
    """Assemble the ``metrics.json`` body for a reconstruction (autoencoder) run.

    ``recon_*`` are per-row reconstruction errors (mean squared error in the
    model's normalized input space). Percentiles and the suggested threshold are
    measured over the **NORMAL** rows only; separation metrics (ROC-AUC, and
    TPR/FPR at the threshold) use the attack rows the split kept.
    """
    rv = np.asarray(recon_val, dtype=np.float64).ravel()
    yv = np.asarray(y_val, dtype=np.int64).ravel()
    normal_mask = yv == int(normal_id)
    normal_err = rv[normal_mask]
    if normal_err.size == 0:  # degenerate: no NORMAL rows in validation
        normal_err = rv

    pcts = {f"p{p}": float(np.percentile(normal_err, p)) for p in _RECON_PCTS}
    pcts["max"] = float(normal_err.max()) if normal_err.size else 0.0
    threshold = pcts["p99"]

    def _separation(err: np.ndarray, y: np.ndarray) -> dict[str, Any]:
        attack = y != int(normal_id)
        out: dict[str, Any] = {
            "rows": int(err.size),
            "normal_rows": int((~attack).sum()),
            "attack_rows": int(attack.sum()),
            "mean_error": float(err.mean()) if err.size else 0.0,
        }
        out["roc_auc"] = _roc_auc(err, attack)
        if attack.any() and (~attack).any():
            flagged = err >= threshold
            out["tpr_at_threshold"] = float((flagged & attack).sum() / attack.sum())
            out["fpr_at_threshold"] = float((flagged & ~attack).sum() / (~attack).sum())
        return out

    m: dict[str, Any] = {
        "objective": "reconstruction",
        "recon_error_percentiles": pcts,
        "suggested_threshold": threshold,
        "threshold_percentile": "p99",
        "train_loss": train_loss,
        "val_loss": val_loss,
        "test_loss": test_loss,
        "val": _separation(rv, yv),
    }
    if recon_test is not None and y_test is not None:
        rt = np.asarray(recon_test, dtype=np.float64).ravel()
        yt = np.asarray(y_test, dtype=np.int64).ravel()
        if rt.size:
            m["test"] = {"loss": test_loss, **_separation(rt, yt)}
    return m


# --------------------------------------------------------------------------
# Torch model
# --------------------------------------------------------------------------

_ACT = {}
if _HAVE_TORCH:
    _ACT = {
        "relu": nn.ReLU,
        "leaky_relu": nn.LeakyReLU,
        "gelu": nn.GELU,
        "elu": nn.ELU,
        "selu": nn.SELU,
        "tanh": nn.Tanh,
        "sigmoid": nn.Sigmoid,
        "identity": nn.Identity,
    }


if _HAVE_TORCH:

    class _ResidualBlock(nn.Module):
        def __init__(self, inner: "nn.Module") -> None:
            super().__init__()
            self.inner = inner

        def forward(self, x):  # noqa: D401
            return self.inner(x) + x

    class MLP(nn.Module):
        """Plain feed-forward net; logits out (no softmax — that is added at export)."""

        def __init__(self, arch: Architecture) -> None:
            super().__init__()
            layers: list[nn.Module] = []
            prev = arch.input_size
            for h in arch.hidden:
                block: list[nn.Module] = [nn.Linear(prev, h.width)]
                if h.batchnorm:
                    block.append(nn.BatchNorm1d(h.width))
                block.append(_ACT.get(h.activation, nn.ReLU)())
                if h.dropout > 0:
                    block.append(nn.Dropout(h.dropout))
                seq = nn.Sequential(*block)
                layers.append(_ResidualBlock(seq) if h.residual and prev == h.width else seq)
                prev = h.width
            layers.append(nn.Linear(prev, arch.output_size))
            self.net = nn.Sequential(*layers)

        def forward(self, x):  # noqa: D401
            return self.net(x)


def build_model(arch: Architecture) -> "nn.Module":
    if not _HAVE_TORCH:
        raise TrainingUnavailable()
    return MLP(arch)


# --------------------------------------------------------------------------
# Training loop
# --------------------------------------------------------------------------


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed % (2**32))
    if _HAVE_TORCH:
        torch.manual_seed(seed)


def _make_optimizer(name: str, params, lr: float):
    name = name.lower()
    if name == "adam":
        return torch.optim.Adam(params, lr=lr)
    if name == "adamw":
        return torch.optim.AdamW(params, lr=lr)
    if name == "sgd":
        return torch.optim.SGD(params, lr=lr, momentum=0.9)
    if name == "rmsprop":
        return torch.optim.RMSprop(params, lr=lr)
    raise TrainingUnavailable()


def _make_scheduler(name: str, opt, epochs: int):
    name = (name or "none").lower()
    if name == "cosine":
        return torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(epochs, 1))
    if name == "step":
        return torch.optim.lr_scheduler.StepLR(opt, step_size=max(epochs // 3, 1), gamma=0.1)
    if name == "plateau":
        return torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="min", patience=2)
    return None


def _class_weights(y: np.ndarray, mode: str):
    if mode != "balanced":
        return None
    counts = np.bincount(y, minlength=OUTPUT_SIZE).astype(np.float64)
    counts[counts == 0] = 1.0
    w = y.size / (OUTPUT_SIZE * counts)
    return torch.tensor(w, dtype=torch.float32)


def train_iter(
    arch: Architecture,
    recipe: Recipe,
    X_train: Any,
    y_train: Any,
    X_val: Any,
    y_val: Any,
    X_test: Any = None,
    y_test: Any = None,
    *,
    model: "nn.Module | None" = None,
) -> Iterator[dict[str, Any]]:
    """Yield a progress dict per epoch, then a final ``{"event": "done", ...}``."""
    if not _HAVE_TORCH:
        raise TrainingUnavailable()

    is_recon = recipe.objective == "reconstruction"

    seed_everything(recipe.seed)
    Xtr = torch.tensor(np.asarray(X_train), dtype=torch.float32)
    Xva = torch.tensor(np.asarray(X_val), dtype=torch.float32)
    # Supervised: long class ids. Reconstruction: the loss target is the input
    # itself, but the class ids ride along for the held-out threshold evaluation.
    ytr = torch.tensor(np.asarray(y_train), dtype=torch.long)
    yva = torch.tensor(np.asarray(y_val), dtype=torch.long)
    tgt_tr = Xtr if is_recon else ytr
    tgt_va = Xva if is_recon else yva
    has_test = X_test is not None and y_test is not None
    if has_test:
        Xte = torch.tensor(np.asarray(X_test), dtype=torch.float32)
        yte = torch.tensor(np.asarray(y_test), dtype=torch.long)
        tgt_te = Xte if is_recon else yte

    model = model or build_model(arch)
    opt = _make_optimizer(recipe.optimizer, model.parameters(), recipe.lr)
    sched = _make_scheduler(recipe.scheduler, opt, recipe.epochs)
    if is_recon:
        loss_fn = nn.MSELoss()
    else:
        loss_fn = nn.CrossEntropyLoss(
            weight=_class_weights(np.asarray(y_train), recipe.class_weighting)
        )

    n = Xtr.shape[0]
    bs = max(1, min(recipe.batch_size, n))
    batches_total = (n + bs - 1) // bs
    device = "cuda" if (_HAVE_TORCH and torch.cuda.is_available()) else "cpu"
    es = recipe.early_stopping
    best_metric = float("inf") if es.mode == "min" else float("-inf")
    best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
    bad_epochs = 0
    started = time.monotonic()

    def _eval(X, tgt):
        model.eval()
        with torch.no_grad():
            out = model(X)
            loss = float(loss_fn(out, tgt).item())
            if is_recon:
                # per-row mean squared reconstruction error
                per_row = ((out - X) ** 2).mean(dim=1)
                return loss, None, per_row.cpu().numpy()
            pred = out.argmax(dim=1)
            acc = float((pred == tgt).float().mean().item())
        return loss, acc, pred.cpu().numpy()

    for epoch in range(1, recipe.epochs + 1):
        model.train()
        perm = torch.randperm(n)
        running = 0.0
        batches_done = 0
        for start in range(0, n, bs):
            idx = perm[start : start + bs]
            xb, tb = Xtr[idx], tgt_tr[idx]
            if xb.shape[0] < 2:  # BatchNorm needs >1 row
                continue
            opt.zero_grad()
            out = model(xb)
            loss = loss_fn(out, tb)
            loss.backward()
            opt.step()
            running += float(loss.item()) * xb.shape[0]
            batches_done += 1

        train_loss = running / max(n, 1)
        val_loss, val_acc, val_out = _eval(Xva, tgt_va)
        val_prf = (
            None if is_recon else confusion_and_prf(yva.cpu().numpy(), val_out)
        )

        if sched is not None:
            if isinstance(sched, torch.optim.lr_scheduler.ReduceLROnPlateau):
                sched.step(val_loss)
            else:
                sched.step()

        # A reconstruction run's early-stopping metric is validated to be
        # val_loss (= MSE); classification allows accuracy / macro-F1 too.
        current = val_loss if is_recon else {
            "val_loss": val_loss,
            "val_accuracy": val_acc,
            "val_macro_f1": val_prf["macro_f1"],
        }[es.metric]
        improved = current < best_metric if es.mode == "min" else current > best_metric
        if improved:
            best_metric = current
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            bad_epochs = 0
        else:
            bad_epochs += 1

        # One progress dict per epoch (PROJECT.md §19.8; ADR 0019). Field names
        # are stable: the daemon stores each dict verbatim and the SPA reads
        # these keys. `val_*` are this epoch's validation metrics; the richer
        # per-class table and confusion matrix ride the final "done" dict.
        msg = {
            "event": "epoch",
            "status": "running",
            "epoch": epoch,
            "epochs": recipe.epochs,
            "batches": batches_done,
            "batches_total": batches_total,
            "train_loss": train_loss,
            "val_loss": val_loss,
            "lr": float(opt.param_groups[0]["lr"]),
            "elapsed_s": time.monotonic() - started,
            "device": device,
            "early_stop_bad_epochs": bad_epochs,
        }
        if is_recon:
            msg["objective"] = "reconstruction"
            msg["val_recon_error"] = val_loss
        else:
            msg["accuracy"] = val_acc
            msg["val_accuracy"] = val_acc  # kept: older readers
            msg["val_macro_precision"] = val_prf["macro_precision"]
            msg["val_macro_recall"] = val_prf["macro_recall"]
            msg["val_macro_f1"] = val_prf["macro_f1"]
        yield msg

        if es.patience and bad_epochs >= es.patience:
            break

    model.load_state_dict(best_state)

    final_train_loss, _, _ = _eval(Xtr, tgt_tr)
    val_loss, _, val_out = _eval(Xva, tgt_va)
    test_loss = None
    test_out = None
    if has_test and Xte.shape[0]:
        test_loss, _, test_out = _eval(Xte, tgt_te)

    if is_recon:
        metrics = reconstruction_metrics(
            val_out,
            yva.cpu().numpy(),
            normal_id=class_id("normal"),
            train_loss=final_train_loss,
            val_loss=val_loss,
            test_loss=test_loss,
            recon_test=test_out,
            y_test=(yte.cpu().numpy() if (has_test and Xte.shape[0]) else None),
        )
    else:
        metrics = classification_metrics(
            yva.cpu().numpy(),
            val_out,
            train_loss=final_train_loss,
            val_loss=val_loss,
            test_loss=test_loss,
            test_true=(yte.cpu().numpy() if (has_test and Xte.shape[0]) else None),
            test_pred=test_out,
        )
    metrics["epochs_run"] = epoch
    metrics["parameter_count"] = arch.parameter_count()
    metrics["elapsed_s"] = time.monotonic() - started
    metrics["device"] = device
    # The daemon stores this "metrics" object verbatim as the run's `final`
    # block: it already carries accuracy, macro precision/recall/F1, the
    # per-class table, the confusion matrix and the held-out `test` metrics
    # (see classification_metrics / confusion_and_prf).
    yield {"event": "done", "metrics": metrics}


def _post_progress(url: str | None, obj: dict[str, Any]) -> None:
    """POST one progress dict as a JSON line.  No-op when ``url`` is falsy."""
    if not url:
        return
    try:
        data = (json.dumps(obj) + "\n").encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(req, timeout=2).close()  # noqa: S310 - operator-supplied URL
    except Exception:  # telemetry must never break training
        pass


def run_training(
    arch: Architecture,
    recipe: Recipe,
    X_train: Any,
    y_train: Any,
    X_val: Any,
    y_val: Any,
    X_test: Any = None,
    y_test: Any = None,
    *,
    progress_url: str | None = None,
    on_epoch=None,
) -> tuple["nn.Module", dict[str, Any]]:
    """Drain :func:`train_iter`, streaming progress, and return ``(model, metrics)``."""
    if not _HAVE_TORCH:
        raise TrainingUnavailable()
    model = build_model(arch)
    metrics: dict[str, Any] = {}
    gen = train_iter(
        arch, recipe, X_train, y_train, X_val, y_val, X_test, y_test, model=model
    )
    for msg in gen:
        _post_progress(progress_url, msg)
        if callable(on_epoch):
            on_epoch(msg)
        if msg.get("event") == "done":
            metrics = msg["metrics"]
    return model, metrics
