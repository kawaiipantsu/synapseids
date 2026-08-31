import json
from pathlib import Path

import pytest

from synapse_trainer import schema


def test_sizes_match_the_frozen_json():
    root = schema.find_schema_dir()
    feats = json.loads((root / "features" / "flow-features-v1.json").read_text())
    classes = json.loads((root / "outputs" / "traffic-classes-v1.json").read_text())

    assert schema.INPUT_SIZE == 48 == feats["input_size"]
    assert schema.OUTPUT_SIZE == 7 == classes["output_size"]
    assert len(schema.FEATURE_NAMES) == 48
    assert len(schema.CLASS_NAMES) == 7
    assert schema.FEATURE_SCHEMA == "flow-features-v1"
    assert schema.OUTPUT_SCHEMA == "traffic-classes-v1"


def test_feature_names_are_in_frozen_index_order():
    root = schema.find_schema_dir()
    feats = json.loads((root / "features" / "flow-features-v1.json").read_text())
    ordered = [f["name"] for f in sorted(feats["features"], key=lambda f: f["index"])]
    assert schema.FEATURE_NAMES == ordered
    assert schema.FEATURE_NAMES[0] == "flow_duration"
    assert schema.FEATURE_NAMES[47] == "snapshot_index"


def test_class_ids_round_trip():
    assert schema.class_id("normal") == 0
    assert schema.class_id("suspicious") == 6
    assert schema.class_id(3) == 3
    assert schema.class_id("3") == 3
    with pytest.raises(schema.SchemaMismatch):
        schema.class_id("not_a_class")
    with pytest.raises(schema.SchemaMismatch):
        schema.class_id(9)


def test_check_compatible_accepts_a_good_meta():
    schema.check_compatible(
        {
            "feature_schema": "flow-features-v1",
            "output_schema": "traffic-classes-v1",
            "feature_count": 48,
            "output_size": 7,
        }
    )


def test_check_compatible_rejects_wrong_schema_name():
    with pytest.raises(schema.SchemaMismatch):
        schema.check_compatible({"feature_schema": "flow-features-v2"})
    with pytest.raises(schema.SchemaMismatch):
        schema.check_compatible({"output_schema": "traffic-classes-v2"})


def test_check_compatible_rejects_wrong_column_count():
    with pytest.raises(schema.SchemaMismatch):
        schema.check_compatible({"feature_schema": "flow-features-v1", "feature_count": 40})
    with pytest.raises(schema.SchemaMismatch):
        schema.check_compatible(
            {"feature_schema": "flow-features-v1", "columns": schema.FEATURE_NAMES[:30] + ["label"]}
        )


def test_check_compatible_rejects_wrong_class_count():
    with pytest.raises(schema.SchemaMismatch):
        schema.check_compatible({"output_schema": "traffic-classes-v1", "num_classes": 5})


def test_env_override_is_honoured(tmp_path, monkeypatch):
    root = schema.find_schema_dir()
    dst = tmp_path / "schemas"
    (dst / "features").mkdir(parents=True)
    (dst / "outputs").mkdir(parents=True)
    (dst / "features" / "flow-features-v1.json").write_text(
        (root / "features" / "flow-features-v1.json").read_text()
    )
    (dst / "outputs" / "traffic-classes-v1.json").write_text(
        (root / "outputs" / "traffic-classes-v1.json").read_text()
    )
    monkeypatch.setenv("SYNAPSE_SCHEMA_DIR", str(dst))
    assert schema.find_schema_dir() == dst
