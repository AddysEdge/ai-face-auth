#!/usr/bin/env python3
"""Live diagnostic tool: prints real blink-score and head-turn-ratio values
as they're computed against the actual webcam, so liveness thresholds in
config.py can be calibrated from measured behavior instead of guessed.

This exists because a live enrollment test found the original head-turn
threshold (derived from an admittedly rough degrees-to-ratio heuristic that
has since been removed) was miscalibrated - 0/12 real head-turn attempts
passed. Run this, perform a blink and a deliberate head turn a few times
while watching the printed values, and use the observed ranges to set
LivenessConfig.blink_score_high / blink_score_low / head_turn_min_swing to
real numbers - see docs/RESEARCH.md for the calibration this repo currently
ships with.

Usage: python scripts/calibrate_liveness.py [--seconds 20]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import cv2  # noqa: E402

from faceauth.liveness.challenge_response import (  # noqa: E402
    _NOSE_TIP_IDX,
    _blink_score,
    _turn_ratio,
)
from faceauth.liveness.litert_landmarker import LiteRtFaceLandmarker  # noqa: E402

LANDMARKER_PATH = REPO_ROOT / "models" / "face_landmarker.task"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--device-index", type=int, default=0)
    args = parser.parse_args()

    # Same runtime the liveness provider uses, so the numbers printed here are
    # the numbers the thresholds will actually be compared against.
    landmarker = LiteRtFaceLandmarker(LANDMARKER_PATH)

    cap = cv2.VideoCapture(args.device_index, cv2.CAP_ANY)
    if not cap.isOpened():
        print(f"Could not open camera at device index {args.device_index}")
        return 1

    print(f"Watching for {args.seconds:.0f}s. Blink and turn your head a few times.")
    print("blink_score range is [0,1] (near 0=open, near 1=closed).")
    print("turn_ratio is signed; sign convention: positive = TURN_HEAD_RIGHT direction.\n")

    start = time.monotonic()
    try:
        while time.monotonic() - start < args.seconds:
            ok, frame = cap.read()
            if not ok:
                continue
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            result = landmarker.detect(rgb)
            if result is None:
                print("no face", end="\r")
                continue
            landmarks = result["landmarks"]
            blink = _blink_score(result["blendshapes"])
            turn = _turn_ratio(landmarks)
            elapsed = time.monotonic() - start
            print(
                f"t={elapsed:5.1f}s  blink_score={blink:6.3f}  turn_ratio={turn:+6.3f}"
                f"  nose_x={landmarks[_NOSE_TIP_IDX][0]:.3f}"
            )
    finally:
        cap.release()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
