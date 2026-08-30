"""Tests for the transcribed MediaPipe preprocessing arithmetic.

These check :mod:`faceauth.liveness.mediapipe_ops` against an **independent
implementation written inside the test** of the same published operations -
never against recorded MediaPipe output. That distinction matters: pinning
these to oracle numbers would make them pass for a transform that is merely
consistently wrong, and would quietly turn a fitted constant into a
"verified" one. No model weights are needed, so these run everywhere.

Upstream sources, all at tag v1.0.0 of google-ai-edge/mediapipe, are named on
each function under test.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from faceauth.liveness.mediapipe_ops import (
    BORDER_REPLICATE,
    BORDER_ZERO,
    compute_rotation,
    denormalize_for_blendshapes,
    get_roi,
    image_to_tensor,
    normalize_radians,
    pad_roi,
    project_landmarks,
    remove_letterbox,
    transform_normalized_rect,
)


def _gradient_image(width: int = 200, height: int = 160) -> np.ndarray:
    """A smooth, non-symmetric image: every pixel is distinguishable."""
    ys, xs = np.mgrid[0:height, 0:width]
    # Floor of 20, not 0: a black corner would make BORDER_REPLICATE
    # indistinguishable from BORDER_ZERO in the border-mode test.
    return np.stack(
        [
            (20 + xs * 235 // max(width - 1, 1)).astype(np.uint8),
            (20 + ys * 235 // max(height - 1, 1)).astype(np.uint8),
            (20 + (xs + ys) * 235 // max(width + height - 2, 1)).astype(np.uint8),
        ],
        axis=-1,
    )


# --------------------------------------------------------------------- GetRoi


def test_get_roi_without_rect_covers_the_whole_image():
    assert get_roi(640, 480, None) == [320.0, 240.0, 640.0, 480.0, 0.0]


def test_get_roi_scales_a_normalized_rect_into_pixels():
    roi = get_roi(640, 480, (0.5, 0.25, 0.5, 0.5, 0.3))
    # x by width, y by height, independently - the anisotropic case is the
    # one a square test image would hide.
    assert roi == pytest.approx([320.0, 120.0, 320.0, 240.0, 0.3])


# --------------------------------------------------------------------- PadRoi


def test_pad_roi_is_a_noop_when_aspect_ratio_is_not_kept():
    roi = [100.0, 100.0, 60.0, 40.0, 0.0]
    assert pad_roi(256, 256, False, roi) == (0.0, 0.0, 0.0, 0.0)
    assert roi == [100.0, 100.0, 60.0, 40.0, 0.0]


@pytest.mark.parametrize("roi_w,roi_h", [(60.0, 40.0), (40.0, 60.0), (50.0, 50.0)])
def test_pad_roi_letterboxes_into_a_square_tensor(roi_w, roi_h):
    roi = [0.0, 0.0, roi_w, roi_h, 0.0]
    left, top, right, bottom = pad_roi(128, 128, True, roi)

    # Independent derivation: a square tensor means the padded ROI must be
    # square, sized by the ROI's own long side, and the padding is the share
    # of the padded extent the original did not occupy, split evenly.
    long_side = max(roi_w, roi_h)
    assert roi[2] == pytest.approx(long_side)
    assert roi[3] == pytest.approx(long_side)
    assert left == right and top == bottom
    assert left == pytest.approx((1.0 - roi_w / long_side) / 2.0)
    assert top == pytest.approx((1.0 - roi_h / long_side) / 2.0)


# ------------------------------------------------------------- ImageToTensor


def test_image_to_tensor_axis_aligned_crop_matches_a_direct_slice():
    """An unrotated ROI on exact pixel boundaries is a plain crop-and-copy."""
    image = _gradient_image()
    # ROI covering x in [40,104), y in [30,94) - width/height 64, so 1:1.
    roi = [72.0, 62.0, 64.0, 64.0, 0.0]
    out = image_to_tensor(image, roi, 64, 64, 0.0, 255.0, BORDER_REPLICATE)

    expected = image[30:94, 40:104].astype(np.float32)
    assert np.abs(out - expected).max() <= 1.0


def test_image_to_tensor_applies_the_range_after_resampling():
    """Order matters: scale/offset act on the resampled 0-255 values."""
    image = _gradient_image()
    roi = [72.0, 62.0, 64.0, 64.0, 0.0]

    raw = image_to_tensor(image, roi, 32, 32, 0.0, 255.0, BORDER_REPLICATE)
    unit = image_to_tensor(image, roi, 32, 32, 0.0, 1.0, BORDER_REPLICATE)
    signed = image_to_tensor(image, roi, 32, 32, -1.0, 1.0, BORDER_REPLICATE)

    assert unit == pytest.approx(raw / 255.0, abs=1e-5)
    assert signed == pytest.approx(raw * (2.0 / 255.0) - 1.0, abs=1e-5)


def test_image_to_tensor_uses_the_published_corner_ordering():
    """boxPoints -> (0,h) (0,0) (w,0) (w,h) fixes the output's orientation.

    A wrong corner ordering still produces a plausible-looking crop - it is
    flipped or rotated by a quarter turn - so orientation is asserted against
    the source image directly rather than eyeballed.
    """
    image = _gradient_image()
    roi = [72.0, 62.0, 64.0, 64.0, 0.0]
    out = image_to_tensor(image, roi, 64, 64, 0.0, 255.0, BORDER_REPLICATE)

    # Red channel increases with x, green with y, in the source. Both must
    # still hold in the crop; a flip or transpose would break one of them.
    assert out[0, -1, 0] > out[0, 0, 0]
    assert out[-1, 0, 1] > out[0, 0, 1]


def test_image_to_tensor_rotation_matches_an_independent_inverse_map():
    """Sample the source directly through the inverse rotation and compare."""
    image = _gradient_image()
    cx, cy, size, angle = 100.0, 80.0, 48.0, math.radians(20.0)
    out = image_to_tensor(image, [cx, cy, size, size, angle], 32, 32,
                          0.0, 255.0, BORDER_REPLICATE)

    # Independent: for output pixel (u,v), the source point is the ROI centre
    # plus the rotated offset of that pixel within the rect.
    cos_a, sin_a = math.cos(angle), math.sin(angle)
    errors = []
    for v in range(2, 30):
        for u in range(2, 30):
            fx = (u + 0.5) / 32 * size - size / 2
            fy = (v + 0.5) / 32 * size - size / 2
            sx = cx + cos_a * fx - sin_a * fy
            sy = cy + sin_a * fx + cos_a * fy
            x0, y0 = int(math.floor(sx - 0.5)), int(math.floor(sy - 0.5))
            ax, ay = (sx - 0.5) - x0, (sy - 0.5) - y0
            patch = image[y0:y0 + 2, x0:x0 + 2].astype(np.float64)
            expected = (
                patch[0, 0] * (1 - ax) * (1 - ay) + patch[0, 1] * ax * (1 - ay)
                + patch[1, 0] * (1 - ax) * ay + patch[1, 1] * ax * ay
            )
            errors.append(np.abs(out[v, u] - expected).max())

    # OpenCV's INTER_LINEAR uses 5-bit fixed-point weights (INTER_BITS=5), so
    # it quantizes the interpolation weights this float reference does not.
    # The bound is that quantization, not a fitted tolerance.
    assert max(errors) <= 4.0


def test_border_modes_differ_outside_the_image():
    """BORDER_ZERO is the detector's override; BORDER_REPLICATE the default."""
    image = _gradient_image()
    roi = [10.0, 10.0, 80.0, 80.0, 0.0]  # deliberately hangs off the corner

    zero = image_to_tensor(image, roi, 32, 32, 0.0, 255.0, BORDER_ZERO)
    replicate = image_to_tensor(image, roi, 32, 32, 0.0, 255.0, BORDER_REPLICATE)

    assert zero[0, 0].max() == pytest.approx(0.0)
    assert replicate[0, 0].max() > 0.0


# ------------------------------------------------------------ ComputeRotation


def test_compute_rotation_is_zero_for_horizontal_keypoints():
    assert compute_rotation((0.2, 0.5), (0.8, 0.5), 640, 480) == pytest.approx(0.0)


def test_compute_rotation_uses_pixel_space_deltas():
    """The same normalized offset gives a different angle on a non-square frame."""
    square = compute_rotation((0.4, 0.4), (0.6, 0.6), 480, 480)
    wide = compute_rotation((0.4, 0.4), (0.6, 0.6), 640, 480)
    assert square != pytest.approx(wide)
    # Independent: rotation = -atan2(-dy_px, dx_px) with target 0.
    assert wide == pytest.approx(-math.atan2(-(0.2 * 480), 0.2 * 640))


@pytest.mark.parametrize("angle", [0.0, 1.0, math.pi, -math.pi + 0.1, 7.0, -7.0])
def test_normalize_radians_lands_in_the_expected_interval(angle):
    # Upstream is angle - 2*pi*floor((angle + pi) / (2*pi)), a half-open
    # [-pi, pi) - so exactly +pi normalizes to -pi, not to itself.
    normalized = normalize_radians(angle)
    assert -math.pi <= normalized < math.pi
    assert (normalized - angle) % (2 * math.pi) == pytest.approx(0.0, abs=1e-9)


# ------------------------------------------------------ RectTransformation


def test_transform_normalized_rect_scales_normalized_dimensions():
    """Without square_long, the scale applies to normalized w/h directly.

    Scaling in pixel space and converting back would give a different result
    on a non-square frame, so this pins the published behaviour.
    """
    out = transform_normalized_rect((0.5, 0.5, 0.2, 0.3, 0.4), 1.5, 1.5)
    assert out == pytest.approx((0.5, 0.5, 0.3, 0.45, 0.4))


# ------------------------------------------------------- LandmarkProjection


def test_project_landmarks_maps_the_crop_centre_to_the_rect_centre():
    centre = np.array([[0.5, 0.5]], np.float32)
    projected = project_landmarks(centre, (0.3, 0.7, 0.2, 0.4, 0.9))
    assert projected[0] == pytest.approx((0.3, 0.7), abs=1e-6)


def test_project_landmarks_rotates_about_the_centre_then_scales():
    rect = (0.5, 0.5, 0.4, 0.2, math.radians(30.0))
    points = np.array([[1.0, 0.5], [0.5, 1.0], [0.0, 0.0]], np.float32)
    projected = project_landmarks(points, rect)

    cos_a, sin_a = math.cos(rect[4]), math.sin(rect[4])
    for point, actual in zip(points, projected, strict=True):
        x, y = point[0] - 0.5, point[1] - 0.5
        expected = (
            (cos_a * x - sin_a * y) * rect[2] + rect[0],
            (sin_a * x + cos_a * y) * rect[3] + rect[1],
        )
        assert actual == pytest.approx(expected, abs=1e-6)


def test_project_landmarks_inverts_an_unrotated_crop():
    rect = (0.4, 0.6, 0.5, 0.25, 0.0)
    points = np.array([[0.25, 0.75]], np.float32)
    projected = project_landmarks(points, rect)
    assert projected[0] == pytest.approx((0.4 + (0.25 - 0.5) * 0.5,
                                          0.6 + (0.75 - 0.5) * 0.25), abs=1e-6)


# -------------------------------------------------------- LetterboxRemoval


def test_remove_letterbox_undoes_pad_roi():
    roi = [0.0, 0.0, 60.0, 40.0, 0.0]
    padding = pad_roi(128, 128, True, roi)

    # A point at the centre is unaffected; an edge point maps back to 0/1.
    points = np.array([[0.5, 0.5], [padding[0], padding[1]]], np.float32)
    restored = remove_letterbox(points, padding)
    assert restored[0] == pytest.approx((0.5, 0.5), abs=1e-6)
    assert restored[1] == pytest.approx((0.0, 0.0), abs=1e-6)


# ------------------------------------------------- LandmarksToTensor scaling


def test_denormalize_for_blendshapes_scales_x_and_y_independently():
    landmarks = np.array([[0.5, 0.5], [0.25, 0.75]], np.float32)
    out = denormalize_for_blendshapes(landmarks, 640, 480)
    assert out == pytest.approx(np.array([[320.0, 240.0], [160.0, 360.0]]), abs=1e-4)


def test_denormalize_for_blendshapes_does_not_mutate_its_input():
    landmarks = np.array([[0.5, 0.5]], np.float32)
    denormalize_for_blendshapes(landmarks, 640, 480)
    assert landmarks == pytest.approx(np.array([[0.5, 0.5]]))


def test_denormalize_is_anisotropic_on_a_non_square_frame():
    """The step whose omission cost up to 0.6 of blendshape score."""
    landmarks = np.array([[0.5, 0.5]], np.float32)
    square = denormalize_for_blendshapes(landmarks, 480, 480)
    wide = denormalize_for_blendshapes(landmarks, 640, 480)
    assert square[0, 0] == pytest.approx(square[0, 1])
    assert wide[0, 0] != pytest.approx(wide[0, 1])
