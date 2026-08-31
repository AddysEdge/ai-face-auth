"""MediaPipe's published CPU pipeline arithmetic, transcribed from primary source.

Every function here names the upstream file it came from, all read at tag
``v1.0.0`` of https://github.com/google-ai-edge/mediapipe. Nothing in this
module is fitted to observed MediaPipe output: each constant is either read
from the source, read from the graph options, or a documented enumerated
choice. That property is what makes the replica checkable - see
``tests/test_b17_preprocessing.py``, which re-derives these operations
independently rather than pinning them to oracle numbers.

Why this exists: the bundled ``mediapipe`` wheel uploads telemetry on session
teardown (docs/PRIVACY_NETWORK_AUDIT.md), which blocks acceptance criterion
B17. Driving the same pinned weights through a telemetry-free runtime requires
reproducing the surrounding graph exactly, because the landmark CNN amplifies
sub-pixel input differences into decision-relevant blendshape differences.
"""

from __future__ import annotations

import math

import cv2
import numpy as np

# image_to_tensor_calculator.proto: BORDER_REPLICATE is the default; the face
# detector graph overrides it to BORDER_ZERO, the landmark graph does not.
BORDER_ZERO = cv2.BORDER_CONSTANT
BORDER_REPLICATE = cv2.BORDER_REPLICATE

Roi = list[float]
"""[x_center_px, y_center_px, width_px, height_px, rotation_rad]"""

NormRect = tuple[float, float, float, float, float]
"""(x_center, y_center, width, height, rotation_rad), all image-normalized."""


def get_roi(input_w: int, input_h: int, norm_rect: NormRect | None = None) -> Roi:
    """image_to_tensor_utils.cc :: GetRoi

    With no rect, the ROI is the whole image. Otherwise the normalized rect is
    scaled into pixels. Rotation passes through untouched.
    """
    if norm_rect is None:
        return [0.5 * input_w, 0.5 * input_h, float(input_w), float(input_h), 0.0]
    x_center, y_center, width, height, rotation = norm_rect
    return [
        x_center * input_w,
        y_center * input_h,
        width * input_w,
        height * input_h,
        rotation,
    ]


def pad_roi(
    tensor_w: int, tensor_h: int, keep_aspect_ratio: bool, roi: Roi
) -> tuple[float, float, float, float]:
    """image_to_tensor_utils.cc :: PadRoi

    Mutates ``roi`` in place to the letterboxed size and returns the padding as
    (left, top, right, bottom) in normalized units. With ``keep_aspect_ratio``
    false this is a no-op returning zero padding, which is the landmark stage's
    configuration.
    """
    if not keep_aspect_ratio:
        return (0.0, 0.0, 0.0, 0.0)

    tensor_aspect = tensor_h / tensor_w
    roi_aspect = roi[3] / roi[2]
    horizontal = vertical = 0.0

    if tensor_aspect > roi_aspect:
        new_w = roi[2]
        new_h = roi[2] * tensor_aspect
        vertical = (1.0 - roi_aspect / tensor_aspect) / 2.0
    else:
        new_w = roi[3] / tensor_aspect
        new_h = roi[3]
        horizontal = (1.0 - tensor_aspect / roi_aspect) / 2.0

    roi[2] = new_w
    roi[3] = new_h
    return (horizontal, vertical, horizontal, vertical)


def image_to_tensor(
    image_rgb: np.ndarray,
    roi: Roi,
    out_w: int,
    out_h: int,
    range_min: float,
    range_max: float,
    border_mode: int,
) -> np.ndarray:
    """image_to_tensor_converter_opencv.cc :: OpenCvProcessor::Convert

    The exact published sequence, and the order matters:

      1. build a ``cv::RotatedRect`` from the ROI, angle in *degrees*
      2. take ``cv::boxPoints`` for the source quad
      3. map to the fixed destination corners (0,h) (0,0) (w,0) (w,h)
      4. ``cv::getPerspectiveTransform`` then ``cv::warpPerspective``
      5. apply the value-range transform **after** resampling

    Resampling before the range conversion is not interchangeable with doing it
    after: the border mode and the interpolation both act on raw 0-255 values.
    """
    x_center, y_center, width, height, rotation = roi

    rotated_rect = (
        (float(x_center), float(y_center)),
        (float(width), float(height)),
        float(rotation) * 180.0 / math.pi,
    )
    src_points = cv2.boxPoints(rotated_rect).astype(np.float32)
    dst_points = np.array(
        [[0.0, out_h], [0.0, 0.0], [out_w, 0.0], [out_w, out_h]],
        dtype=np.float32,
    )

    transform = cv2.getPerspectiveTransform(src_points, dst_points)
    resampled = cv2.warpPerspective(
        image_rgb,
        transform,
        (out_w, out_h),
        flags=cv2.INTER_LINEAR,
        borderMode=border_mode,
    )

    # GetValueRangeTransformation(0, 255, range_min, range_max)
    scale = (range_max - range_min) / 255.0
    return resampled.astype(np.float32) * scale + range_min


def project_landmarks(points_norm: np.ndarray, norm_rect: NormRect) -> np.ndarray:
    """landmark_projection_calculator.cc, the NormalizedRect branch.

    ``points_norm`` are (N, 2) landmarks normalized to the crop - that is,
    raw model output divided by the crop size. Points are rotated about the
    rect centre, then scaled by the rect's normalized size.
    """
    x_center, y_center, width, height, rotation = norm_rect

    x = points_norm[:, 0] - 0.5
    y = points_norm[:, 1] - 0.5
    cos_r, sin_r = math.cos(rotation), math.sin(rotation)
    rotated_x = cos_r * x - sin_r * y
    rotated_y = sin_r * x + cos_r * y

    return np.stack(
        [rotated_x * width + x_center, rotated_y * height + y_center], axis=1
    ).astype(np.float32)


def remove_letterbox(
    points_norm: np.ndarray, padding: tuple[float, float, float, float]
) -> np.ndarray:
    """detection_letterbox_removal_calculator.cc

    Undoes the padding ``pad_roi`` introduced, mapping points back onto the
    un-letterboxed normalized image.
    """
    left, top, right, bottom = padding
    letterbox_w = 1.0 - left - right
    letterbox_h = 1.0 - top - bottom

    out = points_norm.copy()
    out[:, 0] = (out[:, 0] - left) / letterbox_w
    out[:, 1] = (out[:, 1] - top) / letterbox_h
    return out


def compute_rotation(
    start_kp: tuple[float, float],
    end_kp: tuple[float, float],
    image_w: int,
    image_h: int,
    target_angle: float = 0.0,
) -> float:
    """detections_to_rects_calculator.cc :: ComputeRotation

    ``rotation = NormalizeRadians(target_angle - atan2(-(y1 - y0), x1 - x0))``,
    with the keypoint deltas taken in *pixel* space.
    """
    x0, y0 = start_kp
    x1, y1 = end_kp
    angle = target_angle - math.atan2(-((y1 - y0) * image_h), (x1 - x0) * image_w)
    return normalize_radians(angle)


def normalize_radians(angle: float) -> float:
    """detections_to_rects_calculator.h :: NormalizeRadians -> [-pi, pi)."""
    return angle - 2 * math.pi * math.floor((angle + math.pi) / (2 * math.pi))


def transform_normalized_rect(
    rect: NormRect, scale_x: float, scale_y: float
) -> NormRect:
    """rect_transformation_calculator.cc :: TransformNormalizedRect

    With no shift and neither ``square_long`` nor ``square_short`` set - the
    face landmarker's configuration - the scale applies directly to the
    *normalized* width and height, not to pixel dimensions.
    """
    x_center, y_center, width, height, rotation = rect
    return (x_center, y_center, width * scale_x, height * scale_y, rotation)


def denormalize_for_blendshapes(
    landmarks_norm: np.ndarray, image_w: int, image_h: int
) -> np.ndarray:
    """landmarks_to_tensor_calculator.cc :: GetAttributeScale

    The blendshape graph feeds ``IMAGE_SIZE`` into ``LandmarksToTensorCalculator``
    to denormalize: attribute X is scaled by image *width*, Y by image *height*.
    The blendshape model therefore consumes full-image pixel coordinates. On a
    square image the difference from normalized input is an isotropic scale the
    model largely absorbs; on a non-square image it is an anisotropic
    distortion, and skipping it costs up to 0.6 of blendshape score.
    """
    out = landmarks_norm.astype(np.float32).copy()
    out[:, 0] *= float(image_w)
    out[:, 1] *= float(image_h)
    return out
