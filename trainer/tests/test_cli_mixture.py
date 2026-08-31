"""``inspect-recipe`` / ``train --dry-run`` — the torch-free operator preview.

These run with numpy only: nothing here builds a model or writes a bundle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from synapse_trainer import schema
from synapse_trainer.cli import main
from tests.test_mixture import write_dataset, write_manifest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
MULTI_RECIPE = EXAMPLES / "recipe.multi-dataset.json"
EXAMPLE_DATA = EXAMPLES / "data"


def _recipe(tmp_path: Path, entries, **over) -> Path:
    obj = {"name": "cli-mix", "datasets": entries, "seed": 7, "epochs": 1}
    obj.update(over)
    p = tmp_path / "recipe.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_inspect_recipe_prints_a_plan_for_the_shipped_example(capsys):
    rc = main(["inspect-recipe", "--recipe", str(MULTI_RECIPE), "--data", str(EXAMPLE_DATA)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "hq-copenhagen/baseline-2026-08" in out
    assert "thugs/lab-attacks-2026-08" in out
    assert "hq-copenhagen/reviewed-anomalies-2026-09" in out
    assert "v10" in out  # resolved through the latest version dir
    assert "content_hash:  sha256:" in out
    assert "TOTAL" in out
    for name in schema.CLASS_NAMES:
        assert name in out
    assert "warnings" in out


def test_inspect_recipe_json_mode_carries_the_mixture(capsys):
    rc = main(
        ["inspect-recipe", "--recipe", str(MULTI_RECIPE), "--data", str(EXAMPLE_DATA), "--json"]
    )
    assert rc == 0
    obj = json.loads(capsys.readouterr().out)
    assert set(obj) == {"recipe", "mixture"}
    assert [d["id"] for d in obj["recipe"]["datasets"]] == [d["id"] for d in obj["mixture"]["datasets"]]
    assert obj["mixture"]["split_before_mix"] is True
    assert obj["mixture"]["sizes"]["train"] > 0


def test_inspect_recipe_reports_weighting_and_warnings(tmp_path, capsys):
    write_dataset(tmp_path / "big.csv", n=200, seed=70, labels=["normal"])
    d = tmp_path / "attacks"
    write_dataset(d / "dataset.csv", n=20, seed=71, labels=["scan", "dos_ddos"])
    write_manifest(d, content_hash="sha256:" + "12" * 32)
    r = _recipe(tmp_path, [{"id": "big", "weight": 0.9}, {"id": "attacks", "weight": 0.1}])

    rc = main(["inspect-recipe", "--recipe", str(r), "--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "up (+" in out or "down (-" in out
    assert "! class 'normal'" in out or "of the training mixture" in out
    assert "no rows in the training mixture" in out


def test_inspect_recipe_missing_dataset_exits_2(tmp_path, capsys):
    r = _recipe(tmp_path, [{"id": "nope", "weight": 1.0}])
    rc = main(["inspect-recipe", "--recipe", str(r), "--data", str(tmp_path)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "nope.csv" in err and "tried" in err


def test_train_dry_run_needs_no_torch(tmp_path, capsys):
    write_dataset(tmp_path / "a.csv", n=80, seed=72)
    write_dataset(tmp_path / "b.csv", n=40, seed=73)
    r = _recipe(tmp_path, [{"id": "a", "weight": 0.6}, {"id": "b", "weight": 0.4}])
    out_dir = tmp_path / "bundle"

    rc = main(["train", "--recipe", str(r), "--data", str(tmp_path), "--out", str(out_dir), "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "dry run: no model trained" in out
    assert not out_dir.exists()


def test_train_dry_run_rejects_an_incompatible_dataset(tmp_path, capsys):
    write_dataset(tmp_path / "a.csv", n=40, seed=74)
    write_dataset(tmp_path / "b.csv", n=40, seed=75, drop="syn_ack_ratio")
    r = _recipe(tmp_path, [{"id": "a", "weight": 0.5}, {"id": "b", "weight": 0.5}])
    rc = main(
        ["train", "--recipe", str(r), "--data", str(tmp_path), "--out", str(tmp_path / "o"), "--dry-run"]
    )
    assert rc == 2
    assert "syn_ack_ratio" in capsys.readouterr().err


def test_data_pointing_at_one_csv_still_works_for_a_single_dataset(tmp_path, capsys):
    csv_path = write_dataset(tmp_path / "solo.csv", n=60, seed=76)
    r = _recipe(tmp_path, [{"id": "solo", "weight": 1.0}])
    rc = main(["inspect-recipe", "--recipe", str(r), "--data", str(csv_path)])
    assert rc == 0
    assert "solo" in capsys.readouterr().out


def test_data_pointing_at_one_csv_is_rejected_for_a_multi_dataset_recipe(tmp_path, capsys):
    csv_path = write_dataset(tmp_path / "solo.csv", n=60, seed=77)
    write_dataset(tmp_path / "other.csv", n=60, seed=78)
    r = _recipe(tmp_path, [{"id": "solo", "weight": 0.5}, {"id": "other", "weight": 0.5}])
    rc = main(["inspect-recipe", "--recipe", str(r), "--data", str(csv_path)])
    assert rc == 2
    assert "point --data at the directory" in capsys.readouterr().err


@pytest.mark.parametrize("cmd", ["inspect-recipe", "inspect-arch"])
def test_inspect_commands_are_registered(cmd):
    from synapse_trainer.cli import build_parser

    sub = build_parser()._subparsers._group_actions[0].choices  # type: ignore[attr-defined]
    assert cmd in sub
