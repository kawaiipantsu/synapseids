"""``synapse-trainer`` command-line entry point.

    synapse-trainer train --recipe FILE --data DIR --out DIR [--name N] [--progress-url URL]
    synapse-trainer inspect-arch --recipe FILE

``inspect-arch`` needs only numpy; ``train`` needs torch and prints a clear
message if it is missing.
"""

from __future__ import annotations

import argparse
import json
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


def _load_dataset(data_path: str):
    from .dataset import load_csv

    return load_csv(data_path)


def _cmd_train(args: argparse.Namespace) -> int:
    from . import schema
    from .dataset import load_csv
    from .normalize import Normalizer
    from .recipe import load as load_recipe

    recipe = load_recipe(args.recipe)
    ds = load_csv(args.data)
    schema.check_compatible(ds.meta())

    split = ds.split(
        recipe.seed,
        train=recipe.split["train"],
        val=recipe.split["val"],
        test=recipe.split["test"],
    )
    Xtr, ytr = ds.subset(split.train)
    Xva, yva = ds.subset(split.val)
    Xte, yte = ds.subset(split.test)

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
            on_epoch=lambda m: _print_epoch(m) if not args.quiet else None,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    from .export import export_bundle

    recipe_json = recipe.to_json()
    recipe_json["split_result"] = split.to_json()
    result = export_bundle(
        model,
        recipe.architecture,
        normalizer,
        metrics,
        recipe_json,
        dataset_ids=[d.id for d in recipe.datasets],
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
    t.add_argument("--data", required=True, help="dataset CSV file or a directory containing one")
    t.add_argument("--out", required=True, help="output directory for the bundle")
    t.add_argument("--name", default=None, help="model name (defaults to the recipe's name)")
    t.add_argument("--progress-url", default=None, help="POST per-epoch JSON lines here")
    t.add_argument("--quiet", action="store_true", help="suppress per-epoch output")
    t.set_defaults(func=_cmd_train)

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
