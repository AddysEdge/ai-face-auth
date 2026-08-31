"""Compare the LiteRT replica against the mediapipe==1.0.1 oracle, and enforce it.

Runs both over the deterministic synthetic corpus, writes a machine-readable
result file, and **exits nonzero if any declared tolerance is exceeded**. Model
weights, binaries, and per-case images are never written here - only numbers.

    python -m scripts.b17_option_a.compare --out docs/b17/option_a_results.json

An earlier revision of this file exited on detection agreement alone: landmark,
blink, blendshape and turn-ratio errors were computed, printed, and then
ignored by the exit status. A comparison that cannot fail is not evidence, so
every metric is now enforced against a limit declared in this module.

Every prerequisite failure is explicit and fatal. Nothing is silently skipped:
a missing model bundle, a missing runtime, or a missing oracle each stops the
run with a truthful message, because a comparison that quietly degraded to
"replica only" would look like a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
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

# --------------------------------------------------------------------------
# Tolerances. Declared here, before any evidence is regenerated, and tied to
# what each number means for the security decision rather than to whatever the
# implementation currently achieves.
#
#   landmark_error_px   One source-frame pixel. Landmarks are consumed as
#                       coordinates in the operator's own frame; sub-pixel
#                       agreement is the strongest claim the sub-pixel
#                       conditioning of the pipeline can support, and anything
#                       coarser would let the ROI drift visibly.
#   blink_error         0.02, a tenth of the 0.20-wide band between
#                       blink_score_low (0.20) and blink_score_high (0.40). A
#                       disagreement larger than a tenth of the band could move
#                       a reading across a threshold.
#   turn_ratio_error    0.0045, ten percent of the configured
#                       head_turn_min_swing of 0.045.
#   blendshape_error    0.05 on each of the 52 scores. These are 0..1 outputs;
#                       5% bounds how far any single expression channel may
#                       drift, including the 50 this project does not read.
#
# These are ceilings, not targets, and they are not to be relaxed to make a run
# pass. If the implementation cannot meet them, the implementation is wrong.
TOLERANCES: dict[str, float] = {
    "landmark_error_px": 1.0,
    "blink_error": 0.02,
    "turn_ratio_error": 0.0045,
    "blendshape_error": 0.05,
}

# Agreement metrics are all-or-nothing: any disagreement is a failure.
EXACT_AGREEMENT_METRICS = ("detection_agreement", "presence_agreement")

# Metrics every case that yielded a face must carry. A case missing one of
# these is a failure, not a case to skip over.
REQUIRED_FACE_METRICS = (
    "blink_error",
    "landmark_error",
    "landmark_error_px",
    "blendshape_error",
    "turn_ratio_error",
)


def _blink(scores: dict[str, float]) -> float:
    return sum(scores[name] for name in BLINK_CATEGORIES) / len(BLINK_CATEGORIES)


def _require_bundle(path: Path) -> Path:
    if not path.is_file():
        raise SystemExit(
            f"FATAL: {path} not found. Run 'python scripts/fetch_models.py' first.\n"
            "This comparison needs the pinned face_landmarker.task; it is not committed."
        )
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def _versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name, module in (("mediapipe", "mediapipe"), ("ai_edge_litert", "ai_edge_litert"),
                         ("numpy", "numpy"), ("cv2", "cv2")):
        try:
            versions[name] = __import__(module).__version__
        except (ImportError, AttributeError):
            versions[name] = "unknown"
    return versions


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

    corpus = build_corpus()
    expected_cases = [name for name, _ in corpus]
    rows: list[dict] = []

    try:
        for name, bgr in corpus:
            rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
            height, width = rgb.shape[:2]
            reference = oracle.detect(mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb))
            oracle_found = bool(reference.face_landmarks)

            # Split the replica's two stages so the presence gate is observable
            # on its own rather than hidden behind the final verdict.
            detector_fired = bool(replica._detect(rgb))
            actual = replica.detect(rgb)
            replica_found = actual is not None

            row: dict = {
                "case": name,
                "width": width,
                "height": height,
                "oracle_detected": oracle_found,
                "replica_detected": replica_found,
                "replica_detector_fired": detector_fired,
                "replica_presence_passed": replica_found,
            }
            if actual is not None:
                row["presence_score"] = round(float(actual["presence_score"]), 6)

            if oracle_found and replica_found:
                oracle_landmarks = np.array(
                    [[p.x, p.y] for p in reference.face_landmarks[0]], np.float32
                )
                oracle_scores = {c.category_name: c.score for c in reference.face_blendshapes[0]}
                replica_scores = actual["blendshapes"]

                delta = np.abs(actual["landmarks"] - oracle_landmarks)
                row["landmark_error"] = round(float(delta.max()), 6)
                # Normalized error is not comparable across frame shapes: x is
                # normalized by width and y by height. Convert each axis back
                # into source pixels before taking the worst.
                row["landmark_error_px"] = round(
                    float(max((delta[:, 0] * width).max(), (delta[:, 1] * height).max())), 6
                )
                row["blink_error"] = round(
                    abs(_blink(replica_scores) - _blink(oracle_scores)), 6
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

    detection_agreement = sum(r["oracle_detected"] == r["replica_detected"] for r in rows)
    # The presence gate only has an opinion where the detector actually fired.
    presence_relevant = [r for r in rows if r["replica_detector_fired"]]
    presence_agreement = sum(
        r["replica_presence_passed"] == r["oracle_detected"] for r in presence_relevant
    )

    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "source_commit": _source_commit(),
        "bundle": {"path": bundle.name, "sha256": _sha256(bundle)},
        "versions": _versions(),
        "oracle": "mediapipe==1.0.1",
        "replica": "ai-edge-litert via faceauth.liveness.litert_landmarker",
        "cases": len(rows),
        "expected_cases": expected_cases,
        "tolerances": dict(TOLERANCES),
        "detection_agreement": detection_agreement,
        "presence_agreement": presence_agreement,
        "presence_relevant_cases": len(presence_relevant),
        "worst": {k: worst(k) for k in
                  ("blink_error", "landmark_error", "landmark_error_px",
                   "blendshape_error", "turn_ratio_error")},
        "results": rows,
    }


def evaluate(report: dict) -> list[str]:
    """Every reason this report fails. Empty means it passes."""
    failures: list[str] = []
    rows = report.get("results")
    if not isinstance(rows, list) or not rows:
        return ["malformed report: no results"]

    expected = list(report.get("expected_cases") or [])
    seen = [r.get("case") for r in rows]
    missing = [name for name in expected if name not in seen]
    if missing:
        failures.append(f"missing expected case(s): {missing}")
    if len(seen) != len(set(seen)):
        failures.append("duplicate case(s) in results")
    if expected and len(rows) != len(expected):
        failures.append(f"expected {len(expected)} cases, got {len(rows)}")

    if report.get("detection_agreement") != len(rows):
        failures.append(
            f"detection agreement {report.get('detection_agreement')}/{len(rows)}; "
            "100% is required"
        )
    relevant = report.get("presence_relevant_cases")
    if report.get("presence_agreement") != relevant:
        failures.append(
            f"presence agreement {report.get('presence_agreement')}/{relevant}; "
            "100% is required"
        )

    tolerances = report.get("tolerances") or {}
    for metric, limit in tolerances.items():
        for row in rows:
            if metric not in row:
                continue
            value = row[metric]
            if not isinstance(value, (int, float)) or not np.isfinite(value):
                failures.append(f"{row['case']}: {metric} is not a finite number ({value!r})")
                continue
            if value > limit:
                failures.append(
                    f"{row['case']}: {metric} {value:.6f} exceeds limit {limit}"
                )

    # A case that produced a face must carry every metric. Silently absent
    # metrics are how a comparison stops measuring without anyone noticing.
    for row in rows:
        if not (row.get("oracle_detected") and row.get("replica_detected")):
            continue
        for metric in REQUIRED_FACE_METRICS:
            if metric not in row:
                failures.append(f"{row['case']}: missing metric {metric}")
    return failures


def _print(report: dict, failures: list[str]) -> None:
    print("=" * 78)
    print("ORACLE EQUIVALENCE COMPARISON")
    print("=" * 78)
    versions = report.get("versions", {})
    print(f"source commit : {report.get('source_commit')}")
    print(f"bundle        : {report['bundle']['path']}  sha256={report['bundle']['sha256']}")
    print(f"oracle        : {report.get('oracle')}  (mediapipe {versions.get('mediapipe')})")
    print(f"runtime       : ai-edge-litert {versions.get('ai_edge_litert')}, "
          f"numpy {versions.get('numpy')}, cv2 {versions.get('cv2')}")
    print(f"corpus cases  : {report['cases']}")
    print()

    def cell(row: dict, key: str) -> str:
        """Never raise while reporting: a missing metric is a finding to
        print, not a reason to crash before the findings are printed."""
        value = row.get(key)
        if isinstance(value, (int, float)):
            return f"{value:9.5f}"
        return f"{'--':>9s}" if value is None else f"{str(value)[:9]:>9s}"

    print(f"{'case':22s} {'blink':>9s} {'lmk(px)':>9s} {'blendshp':>9s} {'turn':>9s}")
    for row in report["results"]:
        if row.get("oracle_detected") and row.get("replica_detected"):
            print(f"{row['case']:22s} {cell(row, 'blink_error')} "
                  f"{cell(row, 'landmark_error_px')} {cell(row, 'blendshape_error')} "
                  f"{cell(row, 'turn_ratio_error')}")
        else:
            print(f"{row['case']:22s}   oracle={row.get('oracle_detected')} "
                  f"replica={row.get('replica_detected')} "
                  f"(detector_fired={row.get('replica_detector_fired')})")

    print()
    print(f"{'metric':22s} {'limit':>10s} {'measured':>10s}  {'case':22s} {'status':>6s}")
    for metric, limit in report["tolerances"].items():
        entry = (report.get("worst") or {}).get(metric)
        if entry is None:
            print(f"{metric:22s} {limit:10.5f} {'-':>10s}  {'(not measured)':22s} {'n/a':>6s}")
            continue
        status = "PASS" if entry["value"] <= limit else "FAIL"
        print(f"{metric:22s} {limit:10.5f} {entry['value']:10.5f}  "
              f"{entry['case']:22s} {status:>6s}")

    total = report["cases"]
    relevant = report["presence_relevant_cases"]
    det_ok = "PASS" if report["detection_agreement"] == total else "FAIL"
    pres_ok = "PASS" if report["presence_agreement"] == relevant else "FAIL"
    print(f"{'detection agreement':22s} {'100%':>10s} "
          f"{report['detection_agreement']:>7d}/{total:<3d}  {'':22s} {det_ok:>6s}")
    print(f"{'presence agreement':22s} {'100%':>10s} "
          f"{report['presence_agreement']:>7d}/{relevant:<3d}  {'':22s} {pres_ok:>6s}")

    print()
    if failures:
        print("FAIL: the replica does not agree with the oracle within the declared limits.")
        for failure in failures:
            print(f"  - {failure}")
    else:
        print("PASS: every metric is within its declared limit.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enforcing oracle equivalence comparison")
    parser.add_argument("--bundle", type=Path,
                        default=REPO_ROOT / "models" / "face_landmarker.task")
    parser.add_argument("--out", type=Path, default=None,
                        help="write the machine-readable results here")
    args = parser.parse_args(argv)

    report = run(_require_bundle(args.bundle))
    failures = evaluate(report)
    report["failures"] = failures
    report["passed"] = not failures

    _print(report, failures)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {args.out}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
