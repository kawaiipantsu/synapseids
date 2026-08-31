"""``synapse-trainer`` command-line entry point.

    synapse-trainer train --recipe FILE --data DIR --out DIR [--name N] [--report-to URL] [--progress-url URL] [--dry-run]
    synapse-trainer inspect-recipe --recipe FILE --data DIR [--json]
    synapse-trainer inspect-arch --recipe FILE

``inspect-arch`` and ``inspect-recipe`` need only numpy; ``train`` needs torch
and prints a clear message if it is missing.  ``inspect-recipe`` (and the
equivalent ``train --dry-run``) resolves every dataset in the recipe, splits and
weights them exactly as a real run would, and prints the resulting mixture plan
— per-dataset rows, effective weights, split sizes, label distribution and
imbalance warnings — without touching torch.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__


def _fmt_bytes(n: int) -> str:
    step = 1024.0
    val = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if val < step:
            return f"{val:.0f} {unit}" if unit == "B" else f"{val:.2f} {unit}"
        val /= step
    return f"{val:.2f} TiB"


def _cmd_inspect_arch(args: argparse.Namespace) -> int:
    from .recipe import load as load_recipe

    recipe = load_recipe(args.recipe)
    arch = recipe.architecture
    print(f"recipe:            {args.recipe}")
    print(f"name:              {recipe.name}")
    print(f"widths:            {' -> '.join(map(str, arch.widths()))}")
    print()
    print(arch.summary())
    print()
    print(f"parameter_count:   {arch.parameter_count():,}")
    print(f"estimated_size:    {_fmt_bytes(arch.estimated_size_bytes())} (fp32)")
    print(f"rough_flops:       {arch.rough_flops():,} MAC-FLOPs / forward (batch 1)")
    return 0


def _build_mixture(args: argparse.Namespace):
    """Resolve the recipe's datasets into one weighted mixture (torch-free)."""
    from .mixture import build_mixture
    from .recipe import load as load_recipe

    recipe = load_recipe(args.recipe)
    return recipe, build_mixture(recipe, args.data)


def _cmd_inspect_recipe(args: argparse.Namespace) -> int:
    from .mixture import format_plan

    recipe, mixture = _build_mixture(args)
    if args.json:
        print(json.dumps({"recipe": recipe.to_json(), "mixture": mixture.to_json()}, indent=2))
        return 0
    print(format_plan(mixture, recipe_name=f"{recipe.name} ({args.recipe})", data_root=str(args.data)))
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    from .mixture import format_plan
    from .normalize import Normalizer

    recipe, mixture = _build_mixture(args)
    if not args.quiet:
        print(format_plan(mixture, recipe_name=f"{recipe.name} ({args.recipe})", data_root=str(args.data)))
        print()
    if getattr(args, "dry_run", False):
        print("dry run: no model trained, no bundle written")
        return 0

    Xtr, ytr = mixture.X_train, mixture.y_train
    Xva, yva = mixture.X_val, mixture.y_val
    Xte, yte = mixture.X_test, mixture.y_test

    normalizer = Normalizer(recipe.normalizer).fit(Xtr)
    Xtr_n, Xva_n, Xte_n = (
        normalizer.transform(Xtr),
        normalizer.transform(Xva),
        normalizer.transform(Xte) if len(Xte) else Xte,
    )

    try:
        from .train import run_training
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Live progress reporting to a running synapsed (PROJECT.md §19.8; ADR 0019).
    # --report-to (or $SYNAPSE_DAEMON_URL) turns it on; without it the reporter is
    # a no-op and training runs exactly as before. Registration and every POST
    # are best-effort — a dashboard outage must not lose a model.
    from .progress import ProgressReporter

    reporter = ProgressReporter(
        args.report_to,
        logf=(None if args.quiet else lambda m: print(m, file=sys.stderr)),
    )
    reporter.start(
        name=args.name or recipe.name,
        recipe={"recipe": recipe.to_json(), "mixture": mixture.to_json()},
        epochs_total=recipe.epochs,
        trainer_version=__version__,
    )

    def _on_epoch(m: dict) -> None:
        if not args.quiet:
            _print_epoch(m)
        reporter.handle(m)

    try:
        model, metrics = run_training(
            recipe.architecture,
            recipe,
            Xtr_n,
            ytr,
            Xva_n,
            yva,
            Xte_n if len(Xte) else None,
            yte if len(Xte) else None,
            progress_url=args.progress_url,
            on_epoch=_on_epoch,
        )
    except RuntimeError as exc:
        reporter.fail(str(exc))
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive: still report the death
        reporter.fail(f"{type(exc).__name__}: {exc}")
        raise

    from .export import export_bundle

    recipe_json = recipe.to_json()
    recipe_json["split_result"] = mixture.split_result()
    recipe_json["mixture"] = mixture.to_json()
    result = export_bundle(
        model,
        recipe.architecture,
        normalizer,
        metrics,
        recipe_json,
        dataset_ids=mixture.dataset_ids,
        out_dir=args.out,
        name=args.name or recipe.name,
        trainer_version=__version__,
    )
    meta = result["metadata"]
    print()
    print(f"bundle written:   {result['dir']}")
    for f in ("model.onnx", "metadata.json", "normalizer.json", "metrics.json", "training-recipe.json"):
        print(f"  - {f}")
    print(f"model_id:         {meta['model_id']}")
    print(f"model_hash:       {meta['model_hash']}")
    print(f"parameter_count:  {meta['parameter_count']:,}")
    print(f"accuracy:         {metrics.get('accuracy', 0.0):.4f}")
    print(f"macro_f1:         {metrics.get('macro_f1', 0.0):.4f}")
    return 0


def _print_epoch(msg: dict) -> None:
    if msg.get("event") == "epoch":
        print(
            f"epoch {msg['epoch']:>3}/{msg['epochs']}  "
            f"train_loss={msg['train_loss']:.4f}  val_loss={msg['val_loss']:.4f}  "
            f"val_acc={msg['val_accuracy']:.4f}  lr={msg['lr']:.2e}"
        )
    elif msg.get("event") == "done":
        print("training complete")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="synapse-trainer",
        description="Train a flow-classifier-v1 model and export a deployable ONNX bundle.",
    )
    p.add_argument("--version", action="version", version=f"synapse-trainer {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("train", help="train a model and write a bundle")
    t.add_argument("--recipe", required=True, help="path to a training-recipe.json")
    t.add_argument(
        "--data",
        required=True,
        help="dataset root: each recipe dataset id resolves under it (see inspect-recipe)",
    )
    t.add_argument("--out", required=True, help="output directory for the bundle")
    t.add_argument("--name", default=None, help="model name (defaults to the recipe's name)")
    t.add_argument(
        "--report-to",
        default=os.environ.get("SYNAPSE_DAEMON_URL"),
        metavar="DAEMON_URL",
        help=(
            "base URL of a running synapsed (e.g. http://127.0.0.1:8080); the run "
            "registers there and streams live progress for the training dashboard. "
            "Defaults to $SYNAPSE_DAEMON_URL. Omit for no reporting."
        ),
    )
    t.add_argument(
        "--progress-url",
        default=None,
        help="low-level: also POST each per-epoch JSON object to this exact URL",
    )
    t.add_argument("--quiet", action="store_true", help="suppress the mixture plan and per-epoch output")
    t.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve datasets and print the mixture plan, then stop (no torch needed)",
    )
    t.set_defaults(func=_cmd_train)

    r = sub.add_parser(
        "inspect-recipe",
        help="resolve the recipe's datasets and print the training mixture plan (no torch)",
    )
    r.add_argument("--recipe", required=True, help="path to a training-recipe.json")
    r.add_argument("--data", required=True, help="dataset root the recipe's dataset ids resolve under")
    r.add_argument("--json", action="store_true", help="emit the resolved recipe + mixture as JSON")
    r.set_defaults(func=_cmd_inspect_recipe)

    a = sub.add_parser("inspect-arch", help="print param count / size / flops (no torch)")
    a.add_argument("--recipe", required=True, help="path to a training-recipe.json")
    a.set_defaults(func=_cmd_inspect_arch)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
