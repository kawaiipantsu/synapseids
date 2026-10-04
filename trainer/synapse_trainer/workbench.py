"""External, bounded training worker. Run with --help; never imported by the daemon."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

import numpy as np
import torch
from torch import nn

VERSION = "workbench-1"
SAFE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$")


def atomic_json(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
        json.dump(value, f, indent=2, allow_nan=False)
        f.flush()
        os.fsync(f.fileno())
        temp = f.name
    os.replace(temp, path)


def safe_id(value):
    if not SAFE.fullmatch(value):
        raise ValueError("Invalid artifact identity")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, url, token_file=None):
        self.url = url.rstrip("/")
        self.token = Path(token_file).read_text().strip() if token_file else ""
        self.opener = urllib.request.build_opener(NoRedirect)

    def post(self, path, data=None):
        headers = {"Content-Type": "application/json", "User-Agent": "SynapseIDS-Training-Worker/1"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(
            self.url + "/api/v1/" + path, json.dumps(data or {}, allow_nan=False).encode(), headers
        )
        with self.opener.open(req, timeout=20) as response:
            body = response.read(2 << 20)
            return json.loads(body) if body else None


def prepare(root, extractor, capture, label, task, name, corpus_id=None, official_labels=None):
    """Extract only offline; arguments are a list and never interpreted by a shell."""
    root = Path(root)
    target = root / "corpora"
    target.mkdir(parents=True, exist_ok=True)
    identity = safe_id(
        corpus_id or ("capture-" + hashlib.sha256(Path(capture).read_bytes()).hexdigest()[:20])
    )
    args = [str(extractor), "--pcap", str(capture), "--max-rows", "100000"]
    args += ["--ctu-labels", str(official_labels)] if official_labels else ["--label", label]
    counts, groups = collections.Counter(), set()
    temp = target / (identity + ".partial")
    try:
        with temp.open("wb") as f:
            os.chmod(temp, 0o600)
            result = subprocess.run(
                args, stdout=f, stderr=subprocess.PIPE, timeout=330, check=False
            )
        if result.returncode:
            raise ValueError("PCAP extraction failed; check the capture format and labels")
        h = hashlib.sha256()
        with temp.open("rb") as f:
            for line in f:
                h.update(line)
                row = json.loads(line)
                counts[row["label"]] += 1
                groups.add(row["group"])
        if not counts:
            raise ValueError("No supported flows matched the provided labels")
        os.replace(temp, target / (identity + ".jsonl"))
        manifest = dict(
            id=identity,
            name=name or identity,
            task=task,
            rows=sum(counts.values()),
            classes=dict(counts),
            groups=len(groups),
            digest="sha256:" + h.hexdigest(),
            source=(
                "Official CTU oriented flow labels"
                if official_labels
                else "Operator supplied capture-wide label"
            ),
            limitations=(
                "CTU botnet-origin labels describe infected-host traffic, not proof that every individual connection is an attack."
                if official_labels
                else "Every flow receives the selected label. Use only captures whose contents you have verified."
            ),
        )
        atomic_json(target / (identity + ".json"), manifest)
        return identity
    finally:
        temp.unlink(missing_ok=True)


def temporal_split(rows):
    """Chronological conversation groups per capture, with a 60-second embargo.

    Small (<5 minute) captures use intact conversations without an embargo and
    explicitly report this limitation. Never split snapshots of one conversation.
    """
    by_capture = collections.defaultdict(list)
    for i, r in enumerate(rows):
        by_capture[r["group"]].append(i)
    splits = [[], [], []]
    purged = 0
    small = 0
    for indices in by_capture.values():
        times = {}
        for i in indices:
            r = rows[i]
            times[r["conversation"]] = min(times.get(r["conversation"], float("inf")), r["time"])
        ordered = sorted(times, key=lambda key: (times[key], key))
        if len(ordered) < 5:
            # Entire tiny captures train only. They cannot manufacture validation.
            splits[0].extend(indices)
            small += 1
            continue
        n = len(ordered)
        first, second = max(1, int(n * 0.6)), max(2, int(n * 0.8))
        boundaries = [times[ordered[first]], times[ordered[second]]]
        span = max(times.values()) - min(times.values())
        embargo = 60 if span >= 300 else 0
        small += int(not embargo)
        assignment = {
            key: 0 if j < first else 1 if j < second else 2 for j, key in enumerate(ordered)
        }
        for i in indices:
            row = rows[i]
            if embargo and any(abs(row["time"] - b) < embargo for b in boundaries):
                purged += 1
                continue
            splits[assignment[row["conversation"]]].append(i)
    return splits, dict(
        method="chronological conversations within each capture",
        embargo_seconds=60,
        embargo_exempt_small_captures=small,
        purged_rows=purged,
        limitation="Same-capture temporal evaluation; not an independent-site or independent-capture benchmark.",
    )


def evaluate(logits, targets, names, supported):
    guess = logits.argmax(1).numpy()
    truth = targets.numpy()
    cm = np.zeros((len(names), len(names)), dtype=np.int64)
    np.add.at(cm, (truth, guess), 1)
    per = {}
    for i, name in enumerate(names):
        precision = float(cm[i, i] / max(1, cm[:, i].sum()))
        recall = float(cm[i, i] / max(1, cm[i].sum()))
        per[name] = dict(
            precision=precision,
            recall=recall,
            f1=2 * precision * recall / max(1e-12, precision + recall),
            support=int(cm[i].sum()),
            trained=i in supported,
        )
    present = [p for p in per.values() if p["support"] > 0]
    return dict(
        accuracy=float((guess == truth).mean()),
        macro_precision=float(np.mean([p["precision"] for p in present])),
        macro_recall=float(np.mean([p["recall"] for p in present])),
        macro_f1=float(np.mean([p["f1"] for p in present])),
        confusion=cm.tolist(),
        per_class=[dict(**p, **{"class": n}) for n, p in per.items()],
        class_names=names,
        samples=len(truth),
    )


class Network(nn.Module):
    def __init__(self, width, count, supported):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(160, width),
            nn.ReLU(),
            nn.Linear(width, width // 2),
            nn.ReLU(),
            nn.Linear(width // 2, count),
        )
        mask = torch.full((count,), -10000.0)
        mask[list(supported)] = 0
        self.register_buffer("coverage_mask", mask)

    def forward(self, x):
        return self.layers(x) + self.coverage_mask


class Probabilities(nn.Module):
    def __init__(self, network):
        super().__init__()
        self.network = network

    def forward(self, x):
        return torch.softmax(self.network(x), dim=1)


def train(root, model_root, schemas, request, progress, cancelled, candidate_id):
    torch.set_num_threads(4)
    torch.manual_seed(42)
    np.random.seed(42)
    torch.use_deterministic_algorithms(True)
    start = time.monotonic()
    out_schema = json.loads(
        (
            schemas
            / "outputs"
            / (
                "attack-classes-v2.json"
                if request["task"] == "attack"
                else "application-classes-v1.json"
            )
        ).read_text()
    )
    feature_schema = json.loads((schemas / "features/traffic-behavior-v1.json").read_text())
    names = [c["name"] for c in out_schema["classes"]]
    rows, manifests = [], []
    limit = request["max_rows"]
    # A deterministic per-corpus quota prevents the first large capture from
    # consuming all rows and hiding subsequent sources. Evenly sample each file.
    for identity in request["corpora"]:
        safe_id(identity)
        manifest = json.loads((root / "corpora" / (identity + ".json")).read_text())
        path = root / "corpora" / (identity + ".jsonl")
        if path.stat().st_size > 512 << 20:
            raise ValueError("Prepared corpus exceeds 512 MiB")
        digest = hashlib.sha256()
        samples = []
        with path.open("rb") as f:
            for index, line in enumerate(f):
                if index >= 100000:
                    raise ValueError("Corpus exceeds 100000 rows")
                digest.update(line)
                r = json.loads(line)
                if (
                    len(r["values"]) != 160
                    or r["label"] not in names
                    or not all(np.isfinite(r["values"]))
                ):
                    raise ValueError("Invalid corpus schema or label")
                samples.append(r)
        if "sha256:" + digest.hexdigest() != manifest["digest"]:
            raise ValueError("Corpus digest changed; prepare a new version")
        quota = max(1, limit // len(request["corpora"]))
        if len(samples) > quota:
            samples = [samples[i] for i in np.linspace(0, len(samples) - 1, quota, dtype=int)]
        rows.extend(samples)
        manifests.append(manifest)
    unique = {}
    for row in rows:
        key = (row["group"], row["conversation"], row["time"])
        if key in unique and unique[key]["label"] != row["label"]:
            raise ValueError(
                "Conflicting labels for the same conversation; select one reviewed corpus version"
            )
        unique[key] = row
    rows = list(unique.values())
    indices, split_info = temporal_split(rows)
    if any(len(part) < 5 for part in indices):
        raise ValueError(
            "Need at least five independent conversations in each train/validation/test partition; add larger labeled captures"
        )
    x = np.asarray([r["values"] for r in rows], dtype=np.float64)
    y = torch.tensor([names.index(r["label"]) for r in rows], dtype=torch.long)
    train_idx, val_idx, test_idx = indices
    x = np.sign(x) * np.log1p(np.abs(x))
    mean, std = x[train_idx].mean(0), x[train_idx].std(0)
    std[std < 1e-9] = 1
    x = torch.tensor(np.clip((x - mean) / std, -8, 8), dtype=torch.float32)
    class_counts = collections.Counter(y[train_idx].tolist())
    supported = {i for i, n in class_counts.items() if n >= 5}
    train_idx = [i for i in train_idx if int(y[i]) in supported]
    if len(supported) < 2:
        raise ValueError("Training needs at least two labeled classes")
    if request["task"] == "attack" and 0 not in supported:
        raise ValueError("Threat training requires normal examples as well as attacks")
    model = Network(request["width"], len(names), supported)
    counts = torch.bincount(y[train_idx], minlength=len(names)).float()
    weights = (len(train_idx) / (max(1, len(supported)) * counts.clamp(min=1))).clamp(max=20)
    if request["task"] == "attack":
        weights[0] *= request["false_positive_cost"]
        weights[1:] *= request["missed_attack_cost"]
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=0.0001)
    loss_fn = nn.CrossEntropyLoss(weight=weights)
    best_loss, best = float("inf"), None
    for epoch in range(1, request["epochs"] + 1):
        if cancelled():
            raise ValueError("Job cancelled or worker lease lost")
        model.train()
        order = torch.tensor(train_idx)[torch.randperm(len(train_idx))]
        losses = []
        for batch in order.split(256):
            if cancelled():
                raise ValueError("Job cancelled or worker lease lost")
            optimizer.zero_grad()
            loss = loss_fn(model(x[batch]), y[batch])
            if not torch.isfinite(loss):
                raise ValueError("Non-finite training loss")
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 5)
            optimizer.step()
            losses.append(float(loss.detach()))
        model.eval()
        with torch.no_grad():
            logits = model(x[val_idx])
            val_loss = float(loss_fn(logits, y[val_idx]))
            metrics = evaluate(logits, y[val_idx], names, supported)
        if val_loss < best_loss:
            best_loss, best = val_loss, {
                k: v.detach().clone() for k, v in model.state_dict().items()
            }
        progress(
            dict(
                event="epoch",
                epoch=epoch,
                epochs_total=request["epochs"],
                train_loss=float(np.mean(losses)),
                val_loss=val_loss,
                val_accuracy=metrics["accuracy"],
                val_macro_f1=metrics["macro_f1"],
                val_macro_precision=metrics["macro_precision"],
                val_macro_recall=metrics["macro_recall"],
                lr=float(optimizer.param_groups[0]["lr"]),
                batches=len(losses),
                batches_total=(len(train_idx) + 255) // 256,
                elapsed_s=time.monotonic() - start,
                device="cpu",
                samples_train=len(train_idx),
                samples_val=len(val_idx),
            )
        )
    model.load_state_dict(best)
    model.eval()
    with torch.no_grad():
        final = evaluate(model(x[test_idx]), y[test_idx], names, supported)
    final.update(
        elapsed_s=time.monotonic() - start,
        device="cpu",
        samples_train=len(train_idx),
        samples_val=len(val_idx),
        samples_test=len(test_idx),
        supported_classes=[names[i] for i in sorted(supported)],
        unsupported_classes=[n for i, n in enumerate(names) if i not in supported],
        split=split_info,
        model_id=candidate_id,
    )
    if cancelled():
        raise ValueError("Job cancelled before candidate export")
    model_root.mkdir(parents=True, exist_ok=True)
    dest = model_root / safe_id(candidate_id)
    temp = Path(tempfile.mkdtemp(prefix=".candidate-", dir=model_root))
    try:
        graph = Probabilities(model).eval()
        torch.onnx.export(
            graph,
            torch.zeros((1, 160)),
            str(temp / "model.onnx"),
            input_names=["features"],
            output_names=["probabilities"],
            opset_version=13,
            do_constant_folding=True,
        )
        import onnx

        onnx.checker.check_model(str(temp / "model.onnx"))
        width = request["width"]
        meta = dict(
            model_id=candidate_id,
            name=request.get("name") or candidate_id,
            version="1",
            family=(
                "traffic-behavior-v1" if request["task"] == "attack" else "traffic-application-v1"
            ),
            feature_schema="traffic-behavior-v1",
            input_size=160,
            output_schema=out_schema["schema"],
            output_size=len(names),
            architecture=dict(
                input_size=160,
                output_size=len(names),
                hidden=[
                    dict(
                        width=width, activation="relu", dropout=0, batchnorm=False, residual=False
                    ),
                    dict(
                        width=width // 2,
                        activation="relu",
                        dropout=0,
                        batchnorm=False,
                        residual=False,
                    ),
                ],
            ),
            training_dataset_ids=request["corpora"],
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            trainer_version=VERSION,
            parameter_count=sum(p.numel() for p in model.parameters()),
            model_hash="sha256:" + hashlib.sha256((temp / "model.onnx").read_bytes()).hexdigest(),
            coverage=dict(
                supported=final["supported_classes"],
                unsupported=final["unsupported_classes"],
                limitations=split_info["limitation"],
            ),
        )
        normalizer = dict(
            method="standard",
            transform="signed_log1p",
            clip=8,
            feature_schema="traffic-behavior-v1",
            per_feature=[
                dict(index=i, name=f["name"], mean=float(mean[i]), std=float(std[i]))
                for i, f in enumerate(feature_schema["features"])
            ],
        )
        for filename, data in [
            ("metadata.json", meta),
            ("normalizer.json", normalizer),
            ("metrics.json", final),
            (
                "training-recipe.json",
                dict(
                    **request,
                    seed=42,
                    normalizer_fit="train partition only",
                    split=split_info,
                    sources=manifests,
                    optimizer="AdamW",
                    learning_rate=0.001,
                    loss="Class-balanced weighted cross entropy; normal cost penalizes false positives, attack cost penalizes missed attacks",
                ),
            ),
        ]:
            atomic_json(temp / filename, data)
        os.rename(temp, dest)
    finally:
        if temp.exists():
            shutil.rmtree(temp)
    return final


def work(args, api, job):
    request = job["request"]
    stopped, lost = threading.Event(), threading.Event()
    state = {"run_id": "", "model_id": ""}

    def update(status="running", message=""):
        return api.post(
            f"workbench/{job['id']}/update",
            dict(lease=job["lease"], status=status, message=message, **state),
        )

    def heartbeat():
        while not stopped.wait(15):
            try:
                update()
            except Exception:
                lost.set()
                return

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        if request["kind"] == "prepare":
            capture = args.workdir / "uploads" / (safe_id(request["capture_id"]) + ".pcap")
            prepare(
                args.workdir,
                args.extractor,
                capture,
                request["label"],
                request["task"],
                request["name"],
                "corpus-" + job["id"],
            )
            if lost.is_set():
                raise ValueError("Worker lease lost")
            update("completed", "Labeled numeric corpus prepared")
        else:
            run = api.post(
                "training",
                dict(
                    name=request.get("name") or "Behavior training",
                    recipe=request,
                    epochs_total=request["epochs"],
                    trainer_version=VERSION,
                ),
            )
            state["run_id"] = run["id"]
            update()
            final = train(
                args.workdir,
                args.models,
                args.schemas,
                request,
                lambda event: api.post(f"training/{run['id']}/progress", event),
                lost.is_set,
                "candidate-" + job["id"],
            )
            api.post(f"training/{run['id']}/progress", dict(event="done", metrics=final))
            state["model_id"] = final["model_id"]
            update(
                "completed",
                "Candidate ready for evaluation; activation is an explicit operator action",
            )
            api.post(f"workbench/{job['id']}/register")
    except Exception as exc:
        # Log the exception type only; URLs, paths and packet metadata stay private.
        message = (
            str(exc) if isinstance(exc, ValueError) else "Worker failed: " + type(exc).__name__
        )
        if state["run_id"]:
            try:
                api.post(f"training/{state['run_id']}/fail", dict(reason=message))
            except Exception:
                pass
        try:
            update("failed", message)
        except Exception:
            pass
        print(message, flush=True)
    finally:
        stopped.set()
        thread.join(timeout=2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--api", default="http://127.0.0.1:8080")
    p.add_argument("--token-file")
    p.add_argument("--workdir", type=Path, required=True)
    p.add_argument("--models", type=Path, required=True)
    p.add_argument("--schemas", type=Path, required=True)
    p.add_argument("--extractor", type=Path, required=True)
    p.add_argument("--once", action="store_true")
    args = p.parse_args()
    api = API(args.api, args.token_file)
    while True:
        try:
            job = api.post("workbench/claim")
            if job:
                work(args, api, job)
        except Exception as exc:
            print("Worker polling failed: " + type(exc).__name__, flush=True)
        if args.once:
            break
        time.sleep(5)


if __name__ == "__main__":
    main()
