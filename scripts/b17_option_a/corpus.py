"""Deterministic synthetic corpus for the B17 Option A comparison.

Procedurally drawn faces only. No camera, no real person, no biometric data,
and nothing captured from one. The single randomized case uses a fixed seed, so
the whole corpus is byte-reproducible from this file alone - which is why no
images are committed.

The stimuli are crude by design: the point is not realism but coverage of the
transforms the pipeline has to get right (translation, scale, rotation,
non-square resolutions, clipping at the frame edge, brightness/contrast, and
the degenerate no-face and multi-face cases).
"""

from __future__ import annotations

import cv2
import numpy as np

BACKGROUND = 220
SEED = 20260827

# The liveness contract's landmark indices (MediaPipe FaceMesh topology).
NOSE_TIP_IDX = 1
RIGHT_EYE_OUTER_IDX = 33
LEFT_EYE_OUTER_IDX = 263


def draw_face(
    image: np.ndarray,
    center_x: float,
    center_y: float,
    scale: float,
    openness: float,
    turn: float = 0.0,
) -> np.ndarray:
    """One face. ``openness`` drives the eyelids, ``turn`` offsets the nose."""
    cx, cy = int(center_x), int(center_y)
    cv2.ellipse(image, (cx, cy), (int(110 * scale), int(150 * scale)), 0, 0, 360,
                (200, 175, 155), -1)

    for offset in (-40, 40):
        ex, ey = int(cx + offset * scale), int(cy - 35 * scale)
        rx = int(16 * scale)
        ry = max(1, int(16 * scale * openness))
        cv2.ellipse(image, (ex, ey), (rx, ry), 0, 0, 360, (255, 255, 255), -1)
        if openness > 0.25:
            cv2.circle(image, (ex, ey), max(1, int(7 * scale)), (60, 40, 30), -1)
        cv2.ellipse(image, (ex, ey), (rx, ry), 0, 0, 360, (120, 95, 80), 1)

    nose_x = int(cx + turn * 40 * scale)
    cv2.line(image, (nose_x, int(cy - 20 * scale)), (nose_x, int(cy + 35 * scale)),
             (170, 140, 120), 3)
    cv2.ellipse(image, (cx, int(cy + 70 * scale)), (int(40 * scale), int(18 * scale)),
                0, 0, 180, (140, 90, 90), -1)
    return image


def make_case(
    name: str,
    width: int = 480,
    height: int = 480,
    faces: tuple[tuple[float, float, float, float, float], ...] = ((0, 0, 1.0, 1.0, 0.0),),
    rotation_deg: float = 0.0,
    brightness: int = 0,
    contrast: float = 1.0,
) -> tuple[str, np.ndarray]:
    """Build one named BGR image. ``faces`` entries are (dx, dy, scale, openness, turn)."""
    image = np.full((height, width, 3), BACKGROUND, np.uint8)
    for dx, dy, scale, openness, turn in faces:
        draw_face(image, width / 2 + dx, height / 2 + dy, scale, openness, turn)

    if rotation_deg:
        matrix = cv2.getRotationMatrix2D((width / 2, height / 2), rotation_deg, 1.0)
        image = cv2.warpAffine(image, matrix, (width, height),
                               borderValue=(BACKGROUND, BACKGROUND, BACKGROUND))
    if brightness or contrast != 1.0:
        image = cv2.convertScaleAbs(image, alpha=contrast, beta=brightness)
    return name, image


def build_corpus() -> list[tuple[str, np.ndarray]]:
    """The full fixed corpus, in a stable order."""
    cases: list[tuple[str, np.ndarray]] = []

    for openness in (1.00, 0.70, 0.45, 0.30, 0.25, 0.20, 0.15, 0.10, 0.05, 0.02):
        cases.append(make_case(f"open{openness:.2f}", faces=((0, 0, 1.0, openness, 0.0),)))

    for dx, dy in ((30, 0), (-30, 0), (0, 30), (0, -30), (45, 45)):
        cases.append(make_case(f"shift{dx:+d}{dy:+d}", faces=((dx, dy, 1.0, 0.25, 0.0),)))

    for scale in (0.75, 0.85, 1.15, 1.30):
        cases.append(make_case(f"scale{scale:.2f}", faces=((0, 0, scale, 0.25, 0.0),)))

    for degrees in (-20, -12, -6, 6, 12, 20):
        cases.append(make_case(f"rot{degrees:+d}", faces=((0, 0, 1.0, 0.25, 0.0),),
                               rotation_deg=degrees))

    # Non-square resolutions matter: the blendshape model consumes landmarks
    # denormalized by image size, so an anisotropic frame exercises a step a
    # square frame hides.
    for width, height in ((640, 480), (480, 640), (320, 240), (800, 600), (1024, 768)):
        cases.append(make_case(f"res{width}x{height}", width=width, height=height,
                               faces=((0, 0, width / 480.0, 0.25, 0.0),)))

    for dx, dy in ((150, 0), (-150, 0), (0, 140), (0, -140)):
        cases.append(make_case(f"clip{dx:+d}{dy:+d}", faces=((dx, dy, 1.0, 0.25, 0.0),)))

    for brightness, contrast in ((-60, 1.0), (60, 1.0), (0, 0.6), (0, 1.4)):
        cases.append(make_case(f"bright{brightness:+d}_c{contrast:.1f}",
                               faces=((0, 0, 1.0, 0.25, 0.0),),
                               brightness=brightness, contrast=contrast))

    for turn in (-1.0, -0.5, 0.5, 1.0):
        cases.append(make_case(f"turn{turn:+.1f}", faces=((0, 0, 1.0, 0.25, turn),)))

    cases.append(("noface_flat", np.full((480, 480, 3), 200, np.uint8)))
    rng = np.random.default_rng(SEED)
    cases.append(("noface_noise", rng.integers(0, 256, (480, 480, 3), dtype=np.uint8)))

    cases.append(make_case("twofaces", width=640, height=480,
                           faces=((-140, 0, 0.7, 0.25, 0.0), (140, 0, 0.7, 1.0, 0.0))))
    return cases


def turn_ratio(landmarks: np.ndarray) -> float | None:
    """The liveness contract's head-turn signal, on indices 1 / 33 / 263.

    Kept identical to ``challenge_response._turn_ratio`` so the comparison
    measures the quantity the security decision actually uses.
    """
    nose = landmarks[NOSE_TIP_IDX]
    right = landmarks[RIGHT_EYE_OUTER_IDX]
    left = landmarks[LEFT_EYE_OUTER_IDX]
    midpoint = (right[0] + left[0]) / 2.0
    inter_eye = abs(left[0] - right[0])
    if inter_eye < 1e-6:
        return None
    return float((nose[0] - midpoint) / inter_eye)
