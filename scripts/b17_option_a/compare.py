"""Compare the LiteRT replica against the mediapipe==1.0.1 oracle.

Runs both over the deterministic synthetic corpus and writes a small
machine-readable result file. Model weights, binaries, and per-case images are
never written here - only numbers.

    python -m scripts.b17_option_a.compare --out docs/b17/option_a_results.json

Every prerequisite failure is explicit and fatal. Nothing is silently skipped:
a missing model bundle, a missing runtime, or a missing oracle each stops the
run with a truthful message, because a comparison that quietly degrades to
"replica only" would look like a pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from scripts.b17_option_a.corpus import build_corpus, turn_ratio  # noqa: E402

BLINK_CATEGORIES = ("eyeBlinkLeft", "eyeBlinkRight")


def _blink(scores: dict[str, float]) -> float:
    return sum(scores[name] for name in BLINK_CATEGORIES) / len(BLINK_CATEGORIES)


def _require_bundle(path: Path) -> Path:
    if not path.is_file():
        raise SystemExit(
            f"FATAL: {path} not found. Run 'python scripts/fetch_models.py' first.\n"
            "This comparison needs the pinned face_landmarker.task; it is not committed."
        )
    return path


def _load_oracle(bundle: Path):
    try:
        import mediapipe as mp
        from mediapipe.tasks import python as mp_python
        from mediapipe.tasks.python import vision
    except ImportError as exc:
        raise SystemExit(
            f"FATAL: the oracle leg needs 'mediapipe' installed ({exc}).\n"
            "It is intentionally absent from the runtime dependencies (B17); install it\n"
            "into a throwaway environment to reproduce this comparison."
        ) from exc

    landmarker = vision.FaceLandmarker.create_from_options(
        vision.FaceLandmarkerOptions(
            base_options=mp_python.BaseOptions(model_asset_path=str(bundle)),
            output_face_blendshapes=True,
            num_faces=1,
        )
    )
    return mp, landmarker


def _load_replica(bundle: Path):
    try:
        from faceauth.liveness.litert_landmarker import LiteRtFaceLandmarker
    except ImportError as exc:
        raise SystemExit(f"FATAL: cannot import the replica ({exc}).") from exc
    return LiteRtFaceLandmarker(bundle)


def run(bundle: Path) -> dict:
    mp, oracle = _load_oracle(bundle)
    replica = _load_replica(bundle)

    rows: list[dict] = []
    try:
        for name, bgr in build_corpus():
            rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
            reference = oracle.detect(mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb))
            oracle_found = bool(reference.face_landmarks)
            actual = replica.detect(rgb)
            replica_found = actual is not None

            row: dict = {
                "case": name,
                "oracle_detected": oracle_found,
                "replica_detected": replica_found,
            }

            if oracle_found and replica_found:
                oracle_landmarks = np.array(
                    [[p.x, p.y] for p in reference.face_landmarks[0]], np.float32
                )
                oracle_scores = {c.category_name: c.score for c in reference.face_blendshapes[0]}
                replica_scores = actual["blendshapes"]

                row["blink_error"] = round(
                    abs(_blink(replica_scores) - _blink(oracle_scores)), 6
                )
                row["landmark_error"] = round(
                    float(np.abs(actual["landmarks"] - oracle_landmarks).max()), 6
                )
                row["blendshape_error"] = round(
                    max(abs(replica_scores[k] - v) for k, v in oracle_scores.items()), 6
                )
                oracle_turn = turn_ratio(oracle_landmarks)
                replica_turn = turn_ratio(actual["landmarks"])
                if oracle_turn is not None and replica_turn is not None:
                    row["turn_ratio_error"] = round(abs(replica_turn - oracle_turn), 6)

            rows.append(row)
    finally:
        oracle.close()

    def worst(key: str) -> dict | None:
        scored = [r for r in rows if key in r]
        if not scored:
            return None
        top = max(scored, key=lambda r: r[key])
        return {"value": top[key], "case": top["case"]}

    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "oracle": "mediapipe==1.0.1",
        "replica": "ai-edge-litert via faceauth.liveness.litert_landmarker",
        "cases": len(rows),
        "detection_agreement": sum(
            r["oracle_detected"] == r["replica_detected"] for r in rows
        ),
        "worst": {k: worst(k) for k in
                  ("blink_error", "landmark_error", "blendshape_error", "turn_ratio_error")},
        "results": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path,
                        default=REPO_ROOT / "models" / "face_landmarker.task")
    parser.add_argument("--out", type=Path, default=None,
                        help="write the machine-readable results here")
    args = parser.parse_args()

    report = run(_require_bundle(args.bundle))

    print(f"{'case':22s} {'blink':>9s} {'landmark':>9s} {'blendshp':>9s} {'turn':>9s}")
    for row in report["results"]:
        if "blink_error" in row:
            print(f"{row['case']:22s} {row['blink_error']:9.5f} {row['landmark_error']:9.5f} "
                  f"{row['blendshape_error']:9.5f} {row.get('turn_ratio_error', float('nan')):9.5f}")
        else:
            print(f"{row['case']:22s}   oracle={row['oracle_detected']} "
                  f"replica={row['replica_detected']}")

    print()
    for key, entry in report["worst"].items():
        if entry:
            print(f"worst {key:18s} = {entry['value']:.6f}  ({entry['case']})")
    print(f"detection agreement: {report['detection_agreement']} / {report['cases']}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {args.out}")

    return 0 if report["detection_agreement"] == report["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
