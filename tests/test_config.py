import json
from pathlib import Path

import pytest

from faceauth.config import AppConfig, load_config
from faceauth.exceptions import ConfigurationError


def test_default_config_loads_and_validates():
    config = load_config(None)
    assert isinstance(config, AppConfig)
    assert 0.0 <= config.policy.similarity_threshold <= 1.0


def test_load_config_from_valid_json_file(tmp_path: Path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"policy": {"similarity_threshold": 0.5}}))
    config = load_config(path)
    assert config.policy.similarity_threshold == 0.5
    # Untouched sections keep their defaults.
    assert config.rate_limit.max_consecutive_failures == 5


def test_missing_config_file_raises_configuration_error(tmp_path: Path):
    with pytest.raises(ConfigurationError, match="not found"):
        load_config(tmp_path / "does_not_exist.json")


def test_malformed_json_raises_configuration_error(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json,,,")
    with pytest.raises(ConfigurationError, match="not valid JSON"):
        load_config(path)


def test_json_array_instead_of_object_raises_configuration_error(tmp_path: Path):
    path = tmp_path / "array.json"
    path.write_text(json.dumps([1, 2, 3]))
    with pytest.raises(ConfigurationError, match="JSON object"):
        load_config(path)


def test_invalid_threshold_value_raises_configuration_error(tmp_path: Path):
    path = tmp_path / "bad_threshold.json"
    path.write_text(json.dumps({"policy": {"similarity_threshold": 5.0}}))  # out of [-1, 1]
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_quality_min_greater_than_max_raises_configuration_error(tmp_path: Path):
    path = tmp_path / "bad_quality.json"
    path.write_text(
        json.dumps({"quality": {"min_face_area_ratio": 0.9, "max_face_area_ratio": 0.1}})
    )
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_negative_enrollment_samples_rejected(tmp_path: Path):
    path = tmp_path / "bad_enroll.json"
    path.write_text(json.dumps({"enrollment": {"num_samples": -1}}))
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_passive_liveness_enabled_without_model_path_rejected(tmp_path: Path):
    path = tmp_path / "bad_liveness.json"
    path.write_text(json.dumps({"liveness": {"passive_backend_enabled": True}}))
    with pytest.raises(ConfigurationError):
        load_config(path)
