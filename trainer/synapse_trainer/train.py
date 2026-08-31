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
from .schema import CLASS_NAMES, OUTPUT_SIZE

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

    seed_everything(recipe.seed)
    Xtr = torch.tensor(np.asarray(X_train), dtype=torch.float32)
    ytr = torch.tensor(np.asarray(y_train), dtype=torch.long)
    Xva = torch.tensor(np.asarray(X_val), dtype=torch.float32)
    yva = torch.tensor(np.asarray(y_val), dtype=torch.long)
    has_test = X_test is not None and y_test is not None
    if has_test:
        Xte = torch.tensor(np.asarray(X_test), dtype=torch.float32)
        yte = torch.tensor(np.asarray(y_test), dtype=torch.long)

    model = model or build_model(arch)
    opt = _make_optimizer(recipe.optimizer, model.parameters(), recipe.lr)
    sched = _make_scheduler(recipe.scheduler, opt, recipe.epochs)
    loss_fn = nn.CrossEntropyLoss(weight=_class_weights(np.asarray(y_train), recipe.class_weighting))

    n = Xtr.shape[0]
    bs = max(1, min(recipe.batch_size, n))
    es = recipe.early_stopping
    best_metric = float("inf") if es.mode == "min" else float("-inf")
    best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
    bad_epochs = 0
    started = time.monotonic()

    def _eval(X, y):
        model.eval()
        with torch.no_grad():
            logits = model(X)
            loss = float(loss_fn(logits, y).item())
            pred = logits.argmax(dim=1)
            acc = float((pred == y).float().mean().item())
        return loss, acc, pred.cpu().numpy()

    for epoch in range(1, recipe.epochs + 1):
        model.train()
        perm = torch.randperm(n)
        running = 0.0
        for start in range(0, n, bs):
            idx = perm[start : start + bs]
            xb, yb = Xtr[idx], ytr[idx]
            if xb.shape[0] < 2:  # BatchNorm needs >1 row
                continue
            opt.zero_grad()
            out = model(xb)
            loss = loss_fn(out, yb)
            loss.backward()
            opt.step()
            running += float(loss.item()) * xb.shape[0]

        train_loss = running / max(n, 1)
        val_loss, val_acc, val_pred = _eval(Xva, yva)
        val_prf = confusion_and_prf(yva.cpu().numpy(), val_pred)

        if sched is not None:
            if isinstance(sched, torch.optim.lr_scheduler.ReduceLROnPlateau):
                sched.step(val_loss)
            else:
                sched.step()

        current = {
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

        yield {
            "event": "epoch",
            "epoch": epoch,
            "epochs": recipe.epochs,
            "train_loss": train_loss,
            "val_loss": val_loss,
            "val_accuracy": val_acc,
            "val_macro_f1": val_prf["macro_f1"],
            "lr": float(opt.param_groups[0]["lr"]),
            "elapsed_s": time.monotonic() - started,
            "early_stop_bad_epochs": bad_epochs,
        }

        if es.patience and bad_epochs >= es.patience:
            break

    model.load_state_dict(best_state)

    final_train_loss, _, _ = _eval(Xtr, ytr)
    val_loss, _, val_pred = _eval(Xva, yva)
    test_true = test_pred = None
    test_loss = None
    if has_test and Xte.shape[0]:
        test_loss, _, test_pred = _eval(Xte, yte)
        test_true = yte.cpu().numpy()

    metrics = classification_metrics(
        yva.cpu().numpy(),
        val_pred,
        train_loss=final_train_loss,
        val_loss=val_loss,
        test_loss=test_loss,
        test_true=test_true,
        test_pred=test_pred,
    )
    metrics["epochs_run"] = epoch
    metrics["parameter_count"] = arch.parameter_count()
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
