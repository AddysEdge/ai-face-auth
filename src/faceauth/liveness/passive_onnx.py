"""Optional passive (single-frame) spoof-classifier liveness backend.

Disabled by default (see config.LivenessConfig.passive_backend_enabled).
This is a genuine, functional ONNX Runtime backend - it is not a stub - but
unlike the YuNet/SFace/Face-Landmarker integrations elsewhere in this repo,
its exact preprocessing contract has *not* been empirically cross-checked
against a specific reference implementation, because no specific checkpoint
is bundled with this repo (see docs/RESEARCH.md section 3: the natural
reference weights, Silent-Face-Anti-Spoofing/MiniFASNet, are Apache-2.0 but
effectively unmaintained since 2020, so this repo does not ship them by
default).

Contract this class expects from whatever ONNX model is configured:
  - Single input tensor, NCHW float32, square (input_size x input_size)
  - Values scaled to [0, 1] (uint8 crop divided by 255) unless
    ``mean``/``std`` are supplied for further normalization
  - Single output: either one scalar "spoof probability" in [0, 1], or a
    2-class [real, spoof] softmax/logit pair (index 1 is treated as spoof)

Anyone enabling this backend is responsible for confirming their chosen
checkpoint matches this contract and calibrating ``spoof_threshold``
themselves - see docs/README "liveness limitations".
"""

from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from faceauth.exceptions import ModelInferenceError, ModelInitializationError
from faceauth.interfaces.liveness import LivenessProvider
from faceauth.pipeline_types import ChallengeKind, FaceBox, Frame, LivenessResult


class PassiveOnnxSpoofLiveness(LivenessProvider):
    def __init__(
        self,
        model_path: Path,
        input_size: int = 80,
        spoof_threshold: float = 0.5,
        mean: float = 0.0,
        std: float = 1.0,
    ) -> None:
        if not Path(model_path).exists():
            raise ModelInitializationError(f"passive liveness model not found: {model_path}")
        try:
            so = ort.SessionOptions()
            so.log_severity_level = 3
            self._session = ort.InferenceSession(
                str(model_path), sess_options=so, providers=["CPUExecutionProvider"]
            )
        except Exception as exc:
            raise ModelInitializationError(f"failed to load passive liveness model: {exc}") from exc
        self._input_name = self._session.get_inputs()[0].name
        self._input_size = input_size
        self._spoof_threshold = spoof_threshold
        self._mean = mean
        self._std = std
        self._scores: list[float] = []

    def new_challenge(self) -> ChallengeKind:
        # This backend is challenge-agnostic (single-frame passive scoring);
        # it still implements the interface so it composes via
        # CompositeLivenessProvider alongside the active challenge backend.
        self._scores = []
        return ChallengeKind.BLINK

    def observe(self, frame: Frame, face: FaceBox) -> None:
        x0, y0 = max(int(face.x), 0), max(int(face.y), 0)
        x1 = min(int(face.x + face.width), frame.image.shape[1])
        y1 = min(int(face.y + face.height), frame.image.shape[0])
        if x1 <= x0 or y1 <= y0:
            return
        crop = frame.image[y0:y1, x0:x1]
        resized = cv2.resize(crop, (self._input_size, self._input_size))
        blob = resized[:, :, ::-1].astype(np.float32) / 255.0
        blob = (blob - self._mean) / self._std
        blob = blob.transpose(2, 0, 1)[None].copy()
        try:
            raw = self._session.run(None, {self._input_name: blob})[0].reshape(-1)
        except Exception as exc:
            raise ModelInferenceError(f"passive liveness inference failed: {exc}") from exc
        spoof_score = float(raw[1]) if raw.shape[0] >= 2 else float(raw[0])
        self._scores.append(spoof_score)

    def finalize(self) -> LivenessResult:
        if not self._scores:
            return LivenessResult(passed=False, reason="no_face_observed_during_challenge")
        avg_spoof_score = sum(self._scores) / len(self._scores)
        passed = avg_spoof_score < self._spoof_threshold
        return LivenessResult(
            passed=passed,
            reason="passive_liveness_ok" if passed else "passive_liveness_spoof_suspected",
            details={"avg_spoof_score": avg_spoof_score},
        )
