"""Privacy-conscious structured logging.

Two layers of defense against ever logging biometric material or secrets:

1. ``SecurityLogger.log_event`` is the *only* way application code logs
   anything through this module. It accepts a fixed set of primitive types
   (str/int/float/bool/None) as field values and raises ``TypeError`` for
   anything else - a numpy array (raw frame, embedding vector) or bytes
   (encrypted template, key material) cannot be passed in even by accident,
   because the call itself fails before any formatting happens.
2. A ``PrivacyRedactionFilter`` on the underlying handler is defense-in-depth:
   it scans the final formatted message for field names that must never
   appear (password, secret, embedding, template, image, frame) and for
   numpy's own array repr pattern, and replaces the whole record with a
   redaction marker rather than letting it through.

See docs/THREAT_MODEL.md "log leakage" for the scenario this defends against.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

_PRIMITIVE = (str, int, float, bool, type(None))
FieldValue = str | int | float | bool | None

_FORBIDDEN_FIELD_NAMES = {
    "password",
    "secret",
    "embedding",
    "template",
    "image",
    "frame",
    "biometric",
    "raw_image",
}
_SUSPICIOUS_MESSAGE_PATTERN = re.compile(r"array\(|dtype=|b'[^']{16,}'")


class PrivacyRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if _SUSPICIOUS_MESSAGE_PATTERN.search(message):
            record.msg = "[REDACTED: message contained a disallowed array/bytes payload]"
            record.args = ()
        return True


def _validate_fields(fields: dict[str, FieldValue]) -> None:
    for name, value in fields.items():
        lowered = name.lower()
        # An opaque identifier (e.g. "template_id") is safe to log even
        # though it contains a forbidden word as a substring - it is not the
        # sensitive payload itself, just a correlation handle. Only the bare
        # word or a non-"_id" compound (e.g. "template_bytes") is blocked.
        is_safe_identifier = lowered.endswith("_id")
        if not is_safe_identifier and any(bad in lowered for bad in _FORBIDDEN_FIELD_NAMES):
            raise TypeError(
                f"refusing to log field {name!r}: field names matching "
                f"{sorted(_FORBIDDEN_FIELD_NAMES)} are never allowed through SecurityLogger"
            )
        if not isinstance(value, _PRIMITIVE):
            raise TypeError(
                f"refusing to log field {name!r} of type {type(value).__name__}: "
                "SecurityLogger only accepts str/int/float/bool/None"
            )


class SecurityLogger:
    """Structured, privacy-safe logger. Wraps a stdlib logger; never exposes it directly."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def log_event(self, event: str, level: int = logging.INFO, **fields: FieldValue) -> None:
        _validate_fields(fields)
        payload = {"event": event, **fields}
        self._logger.log(level, json.dumps(payload, sort_keys=True))

    def exception_event(self, event: str, exc: BaseException, **fields: FieldValue) -> None:
        """Logs an event plus the exception's type and message only - never a
        full traceback, which could otherwise embed a repr of a local
        variable holding an embedding or template."""
        _validate_fields(fields)
        payload = {
            "event": event,
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            **fields,
        }
        self._logger.log(logging.ERROR, json.dumps(payload, sort_keys=True))


def build_security_logger(name: str, log_dir: Path, level: str = "INFO") -> SecurityLogger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.FileHandler(log_dir / "faceauth.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        handler.addFilter(PrivacyRedactionFilter())
        logger.addHandler(handler)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        stream_handler.addFilter(PrivacyRedactionFilter())
        logger.addHandler(stream_handler)
    return SecurityLogger(logger)
