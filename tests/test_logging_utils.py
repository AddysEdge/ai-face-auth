from pathlib import Path

import numpy as np
import pytest

from faceauth.logging_utils import build_security_logger


def test_log_event_accepts_primitive_fields(tmp_path: Path):
    logger = build_security_logger("test-privacy-ok", tmp_path / "logs", "DEBUG")
    logger.log_event("authentication_granted", similarity_bucket="high", attempt=1, ok=True)
    log_file = tmp_path / "logs" / "faceauth.log"
    assert log_file.exists()
    assert "authentication_granted" in log_file.read_text()


@pytest.mark.parametrize("field_name", ["password", "secret_key", "embedding", "template", "raw_image", "frame"])
def test_log_event_rejects_forbidden_field_names(tmp_path: Path, field_name):
    logger = build_security_logger(f"test-privacy-{field_name}", tmp_path / "logs", "DEBUG")
    with pytest.raises(TypeError):
        logger.log_event("some_event", **{field_name: "value"})


def test_log_event_rejects_numpy_array_values(tmp_path: Path):
    logger = build_security_logger("test-privacy-array", tmp_path / "logs", "DEBUG")
    with pytest.raises(TypeError):
        logger.log_event("some_event", vector=np.zeros(128))


def test_log_event_allows_opaque_id_fields_despite_substring_match(tmp_path: Path):
    """Regression test: 'template_id'/'embedding_id' are safe correlation
    handles, not the sensitive payload, and must not be blocked just because
    they contain a forbidden word as a substring."""
    logger = build_security_logger("test-privacy-ids-ok", tmp_path / "logs", "DEBUG")
    logger.log_event("enrollment_completed", template_id="abc123", embedding_id="def456")


def test_log_event_still_rejects_bare_forbidden_word_with_id_like_suffix(tmp_path: Path):
    logger = build_security_logger("test-privacy-ids-bad", tmp_path / "logs", "DEBUG")
    with pytest.raises(TypeError):
        logger.log_event("some_event", template_bytes="not actually safe")


def test_log_event_rejects_bytes_values(tmp_path: Path):
    logger = build_security_logger("test-privacy-bytes", tmp_path / "logs", "DEBUG")
    with pytest.raises(TypeError):
        logger.log_event("some_event", payload=b"raw bytes")


def test_exception_event_never_includes_full_traceback_text(tmp_path: Path):
    logger = build_security_logger("test-privacy-exc", tmp_path / "logs", "DEBUG")
    huge_array_repr_exc = ValueError("boom")
    logger.exception_event("something_failed", huge_array_repr_exc)
    log_file = tmp_path / "logs" / "faceauth.log"
    content = log_file.read_text()
    assert "something_failed" in content
    assert "boom" in content
    assert "Traceback" not in content


def test_suspicious_array_like_message_is_redacted_by_filter(tmp_path: Path):
    import logging

    build_security_logger("test-privacy-redact", tmp_path / "logs", "DEBUG")
    # Bypass log_event's validation to simulate a raw stdlib call slipping
    # through, and confirm the handler-level filter still redacts it.
    raw_logger = logging.getLogger("test-privacy-redact")
    raw_logger.info("array([0.1, 0.2, 0.3], dtype=float32)")
    log_file = tmp_path / "logs" / "faceauth.log"
    content = log_file.read_text()
    assert "0.1, 0.2, 0.3" not in content
    assert "REDACTED" in content
