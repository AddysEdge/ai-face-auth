import numpy as np

from faceauth.pipeline_types import FaceBox
from faceauth.quality.heuristic_quality import HeuristicFaceQualityChecker


def _checker(**overrides) -> HeuristicFaceQualityChecker:
    defaults = dict(
        min_face_area_ratio=0.03,
        max_face_area_ratio=0.95,
        min_sharpness=10.0,
        min_brightness=40.0,
        max_brightness=220.0,
    )
    defaults.update(overrides)
    return HeuristicFaceQualityChecker(**defaults)


def _face(x=100, y=100, w=100, h=100) -> FaceBox:
    return FaceBox(x=x, y=y, width=w, height=h, confidence=0.9, landmarks=())


def test_sharp_well_lit_face_passes():
    rng = np.random.default_rng(0)
    image = rng.integers(0, 255, (480, 640, 3), dtype=np.uint8)  # high-variance -> sharp
    # Force mean brightness into range by scaling.
    image = (image.astype(np.float32) * 0.4 + 60).clip(0, 255).astype(np.uint8)
    report = _checker().check(image, _face(200, 150, 150, 150))
    assert report.passed, report.reasons


def test_too_dark_face_fails():
    image = np.full((480, 640, 3), 5, dtype=np.uint8)
    report = _checker().check(image, _face(200, 150, 150, 150))
    assert not report.passed
    assert "too_dark" in report.reasons


def test_too_bright_face_fails():
    image = np.full((480, 640, 3), 250, dtype=np.uint8)
    report = _checker().check(image, _face(200, 150, 150, 150))
    assert not report.passed
    assert "too_bright" in report.reasons


def test_blurry_flat_face_fails():
    image = np.full((480, 640, 3), 128, dtype=np.uint8)  # zero variance -> zero sharpness
    report = _checker(min_sharpness=1.0).check(image, _face(200, 150, 150, 150))
    assert not report.passed
    assert "too_blurry" in report.reasons


def test_face_too_small_fails():
    image = np.full((480, 640, 3), 128, dtype=np.uint8)
    report = _checker().check(image, _face(0, 0, 5, 5))
    assert not report.passed
    assert "face_too_small" in report.reasons


def test_face_box_out_of_bounds_fails_safely():
    image = np.zeros((100, 100, 3), dtype=np.uint8)
    report = _checker().check(image, _face(150, 150, 50, 50))  # entirely outside the image
    assert not report.passed
    assert "face_box_out_of_bounds" in report.reasons
