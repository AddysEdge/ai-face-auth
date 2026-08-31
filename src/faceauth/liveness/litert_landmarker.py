"""Face Landmarker on a telemetry-free runtime.

Drives the *same* pinned weights as ``mediapipe==1.0.1`` - the three ``.tflite``
files inside ``face_landmarker.task`` - through ``ai-edge-litert`` instead of
the MediaPipe wheel, reproducing the published graph with
:mod:`faceauth.liveness.mediapipe_ops`.

The motivation is acceptance criterion B17: the MediaPipe wheel opens a TLS
connection to ``play.googleapis.com`` on session teardown and offers no
supported way to disable it (docs/PRIVACY_NETWORK_AUDIT.md). The weights are
not the problem; the runtime is.

Only the parts of the graph the liveness contract needs are implemented:
detection, ROI derivation, the 478 landmarks, and the 52 blendshapes. Face
geometry, smoothing, and video-mode tracking are not.
"""

from __future__ import annotations

import math
import zipfile
from pathlib import Path

import numpy as np

from faceauth.exceptions import ModelInferenceError, ModelInitializationError
from faceauth.liveness.mediapipe_ops import (
    BORDER_REPLICATE,
    BORDER_ZERO,
    NormRect,
    compute_rotation,
    denormalize_for_blendshapes,
    get_roi,
    image_to_tensor,
    pad_roi,
    project_landmarks,
    remove_letterbox,
    transform_normalized_rect,
)

# Members of the .task bundle (a zip). Named in the bundle's own manifest.
_DETECTOR_MEMBER = "face_detector.tflite"
_LANDMARKS_MEMBER = "face_landmarks_detector.tflite"
_BLENDSHAPES_MEMBER = "face_blendshapes.tflite"

_DETECTOR_SIZE = 128
_LANDMARKS_SIZE = 256
_NUM_LANDMARKS = 478

# image_preprocessing_graph.cc derives these from the model's
# NormalizationOptions as min=(0-mean)/std, max=(255-mean)/std. Neither .tflite
# carries those options, so the pair was identified by measuring the two
# documented candidates across all four combinations; the separation between
# the best and the next-best is 4-90x. See docs/PHASE2_5_B17_RESEARCH.md.
_DETECTOR_RANGE = (-1.0, 1.0)  # mean 127.5, std 127.5
_LANDMARKS_RANGE = (0.0, 1.0)  # mean 0, std 255

# face_detector_graph.cc: min_detection_confidence, min_suppression_threshold.
_MIN_DETECTION_SCORE = 0.5
_MIN_SUPPRESSION = 0.3

# tensors_to_detections_calculator, configured by face_detector_graph.cc for the
# short-range model: 896 boxes, 16 coords, sigmoid_score, score_clipping_thresh
# 100.0, reverse_output_order (so coords are x,y,w,h rather than y,x,h,w), and
# x/y/w/h_scale all kShortRangeImageSize = 128.
_SCORE_CLIPPING_THRESH = 100.0

# face_landmarker_graph.cc: RectTransformationCalculator scale for the face ROI.
_ROI_SCALE = 1.5

# The 146 landmark indices the blendshape ("HUND") model consumes, from
# face_blendshapes_graph.cc :: kLandmarksSubsetIdxs.
BLENDSHAPE_LANDMARK_SUBSET = (
    0, 1, 4, 5, 6, 7, 8, 10, 13, 14, 17, 21, 33, 37, 39, 40, 46, 52, 53, 54,
    55, 58, 61, 63, 65, 66, 67, 70, 78, 80, 81, 82, 84, 87, 88, 91, 93, 95,
    103, 105, 107, 109, 127, 132, 133, 136, 144, 145, 146, 148, 149, 150, 152,
    153, 154, 155, 157, 158, 159, 160, 161, 162, 163, 168, 172, 173, 176, 178,
    181, 185, 191, 195, 197, 234, 246, 249, 251, 263, 267, 269, 270, 276, 282,
    283, 284, 285, 288, 291, 293, 295, 296, 297, 300, 308, 310, 311, 312, 314,
    317, 318, 321, 323, 324, 332, 334, 336, 338, 356, 361, 362, 365, 373, 374,
    375, 377, 378, 379, 380, 381, 382, 384, 385, 386, 387, 388, 389, 390, 397,
    398, 400, 402, 405, 409, 415, 454, 466, 468, 469, 470, 471, 472, 473, 474,
    475, 476, 477,
)

# face_blendshapes_graph.cc :: kBlendshapeNames, in model output order.
BLENDSHAPE_NAMES = (
    "_neutral", "browDownLeft", "browDownRight", "browInnerUp", "browOuterUpLeft",
    "browOuterUpRight", "cheekPuff", "cheekSquintLeft", "cheekSquintRight",
    "eyeBlinkLeft", "eyeBlinkRight", "eyeLookDownLeft", "eyeLookDownRight",
    "eyeLookInLeft", "eyeLookInRight", "eyeLookOutLeft", "eyeLookOutRight",
    "eyeLookUpLeft", "eyeLookUpRight", "eyeSquintLeft", "eyeSquintRight",
    "eyeWideLeft", "eyeWideRight", "jawForward", "jawLeft", "jawOpen",
    "jawRight", "mouthClose", "mouthDimpleLeft", "mouthDimpleRight",
    "mouthFrownLeft", "mouthFrownRight", "mouthFunnel", "mouthLeft",
    "mouthLowerDownLeft", "mouthLowerDownRight", "mouthPressLeft",
    "mouthPressRight", "mouthPucker", "mouthRight", "mouthRollLower",
    "mouthRollUpper", "mouthShrugLower", "mouthShrugUpper", "mouthSmileLeft",
    "mouthSmileRight", "mouthStretchLeft", "mouthStretchRight",
    "mouthUpperUpLeft", "mouthUpperUpRight", "noseSneerLeft", "noseSneerRight",
)


def generate_ssd_anchors() -> np.ndarray:
    """ssd_anchors_calculator.cc, with face_detector_graph.cc's options.

    num_layers 4, strides (8, 16, 16, 16), aspect_ratios [1.0],
    interpolated_scale_aspect_ratio 1.0, fixed_anchor_size. Yields 896 anchors.
    Only the centres are needed; the sizes are fixed and cancel out of the box
    decode below.
    """
    strides = (8, 16, 16, 16)
    num_layers = len(strides)
    anchors: list[tuple[float, float]] = []

    layer = 0
    while layer < num_layers:
        anchors_per_cell = 0
        last = layer
        while last < num_layers and strides[last] == strides[layer]:
            # one for aspect_ratios=[1.0], one for the interpolated scale
            anchors_per_cell += 2
            last += 1

        feature_map = int(math.ceil(_DETECTOR_SIZE / strides[layer]))
        for y in range(feature_map):
            for x in range(feature_map):
                for _ in range(anchors_per_cell):
                    anchors.append(((x + 0.5) / feature_map, (y + 0.5) / feature_map))
        layer = last

    return np.array(anchors, dtype=np.float32)


class LiteRtFaceLandmarker:
    """Detector -> ROI -> 478 landmarks -> 52 blendshapes, all on LiteRT.

    Not thread-safe: LiteRT interpreters hold mutable tensor state, and the
    liveness provider drives one frame at a time from a single thread.
    """

    def __init__(self, model_asset_path: str | Path):
        path = Path(model_asset_path)
        if not path.is_file():
            raise ModelInitializationError(f"Face landmarker bundle not found: {path}")

        try:
            from ai_edge_litert.interpreter import Interpreter
        except ImportError as exc:  # pragma: no cover - dependency is pinned
            raise ModelInitializationError(
                "ai-edge-litert is required for the liveness path; "
                "install the project's pinned dependencies"
            ) from exc

        try:
            with zipfile.ZipFile(path) as bundle:
                members = set(bundle.namelist())
                missing = {
                    _DETECTOR_MEMBER,
                    _LANDMARKS_MEMBER,
                    _BLENDSHAPES_MEMBER,
                } - members
                if missing:
                    raise ModelInitializationError(
                        f"{path.name} is missing expected model(s): {sorted(missing)}"
                    )
                detector_bytes = bundle.read(_DETECTOR_MEMBER)
                landmarks_bytes = bundle.read(_LANDMARKS_MEMBER)
                blendshapes_bytes = bundle.read(_BLENDSHAPES_MEMBER)
        except zipfile.BadZipFile as exc:
            raise ModelInitializationError(
                f"{path.name} is not a readable .task bundle"
            ) from exc

        try:
            self._detector = Interpreter(model_content=detector_bytes)
            self._detector.allocate_tensors()
            self._landmarks = Interpreter(model_content=landmarks_bytes)
            self._landmarks.allocate_tensors()
            self._blendshapes = Interpreter(model_content=blendshapes_bytes)
            self._blendshapes.allocate_tensors()
        except (ValueError, RuntimeError) as exc:
            raise ModelInitializationError(
                f"Failed to initialize the liveness models from {path.name}: {exc}"
            ) from exc

        self._anchors = generate_ssd_anchors()

    # ------------------------------------------------------------------ util
    @staticmethod
    def _invoke(interpreter, tensor: np.ndarray) -> list[np.ndarray]:
        detail = interpreter.get_input_details()[0]
        interpreter.set_tensor(detail["index"], tensor)
        interpreter.invoke()
        return [interpreter.get_tensor(o["index"]) for o in interpreter.get_output_details()]

    # ---------------------------------------------------------------- detect
    def _detect(self, image_rgb: np.ndarray) -> list[dict] | None:
        height, width = image_rgb.shape[:2]
        roi = get_roi(width, height, None)
        padding = pad_roi(_DETECTOR_SIZE, _DETECTOR_SIZE, True, roi)
        tensor = image_to_tensor(
            image_rgb, roi, _DETECTOR_SIZE, _DETECTOR_SIZE,
            _DETECTOR_RANGE[0], _DETECTOR_RANGE[1], BORDER_ZERO,
        )

        outputs = self._invoke(self._detector, tensor[None, ...])
        regressors, scores_raw = (
            (outputs[0], outputs[1]) if outputs[0].shape[-1] == 16 else (outputs[1], outputs[0])
        )

        # float64 for the sigmoid: at the clipping threshold exp(100) overflows
        # float32 and warns, even though the result saturates to the right value.
        logits = np.clip(
            scores_raw[0, :, 0].astype(np.float64),
            -_SCORE_CLIPPING_THRESH,
            _SCORE_CLIPPING_THRESH,
        )
        scores = 1.0 / (1.0 + np.exp(-logits))
        keep = np.nonzero(scores >= _MIN_DETECTION_SCORE)[0]
        if keep.size == 0:
            return None

        # reverse_output_order: columns are x, y, w, h, then 6 keypoint pairs.
        reg = regressors[0].astype(np.float32)
        cx = reg[:, 0] / _DETECTOR_SIZE + self._anchors[:, 0]
        cy = reg[:, 1] / _DETECTOR_SIZE + self._anchors[:, 1]
        bw = reg[:, 2] / _DETECTOR_SIZE
        bh = reg[:, 3] / _DETECTOR_SIZE
        boxes = np.stack([cx - bw / 2, cy - bh / 2, cx + bw / 2, cy + bh / 2], axis=1)
        keypoints = np.stack(
            [reg[:, 4 + 2 * k : 6 + 2 * k] / _DETECTOR_SIZE + self._anchors for k in range(6)],
            axis=1,
        )

        results = self._weighted_nms(boxes, keypoints, scores, keep)

        detections = []
        for score, box, kps in results:
            points = remove_letterbox(
                np.vstack([box.reshape(2, 2), kps]).astype(np.float32), padding
            )
            bounds, blended_kps = points[:2].reshape(-1), points[2:]
            detections.append(
                {
                    "score": float(score),
                    "xmin": float(bounds[0]),
                    "ymin": float(bounds[1]),
                    "xmax": float(bounds[2]),
                    "ymax": float(bounds[3]),
                    "keypoints": [(float(x), float(y)) for x, y in blended_kps],
                }
            )
        return detections

    @staticmethod
    def _weighted_nms(boxes, keypoints, scores, keep) -> list[tuple[float, np.ndarray, np.ndarray]]:
        """non_max_suppression_calculator.cc, WEIGHTED mode.

        Unlike plain NMS this does not just drop overlapping boxes - it blends
        the whole overlapping cluster, box and keypoints alike, weighted by
        score. Dropping instead of blending shifts the ROI by a fraction of a
        pixel, which is enough to move the blink score measurably.
        """

        def iou(candidate, others):
            x1 = np.maximum(candidate[0], others[:, 0])
            y1 = np.maximum(candidate[1], others[:, 1])
            x2 = np.minimum(candidate[2], others[:, 2])
            y2 = np.minimum(candidate[3], others[:, 3])
            intersection = np.clip(x2 - x1, 0, None) * np.clip(y2 - y1, 0, None)
            area_a = (candidate[2] - candidate[0]) * (candidate[3] - candidate[1])
            area_b = (others[:, 2] - others[:, 0]) * (others[:, 3] - others[:, 1])
            return intersection / np.maximum(area_a + area_b - intersection, 1e-12)

        remaining = list(keep[np.argsort(-scores[keep])])
        results = []
        while remaining:
            best = remaining[0]
            overlap = iou(boxes[best], boxes[remaining])
            cluster = [remaining[i] for i in range(len(remaining)) if overlap[i] > _MIN_SUPPRESSION]
            rest = [remaining[i] for i in range(len(remaining)) if overlap[i] <= _MIN_SUPPRESSION]

            if cluster:
                total = scores[cluster].sum()
                box = (boxes[cluster] * scores[cluster][:, None]).sum(axis=0) / total
                kps = (keypoints[cluster] * scores[cluster][:, None, None]).sum(axis=0) / total
            else:
                box, kps = boxes[best], keypoints[best]

            results.append((float(scores[best]), box, kps))
            remaining = rest
        return results

    # ------------------------------------------------------------------- roi
    @staticmethod
    def _detection_to_rect(detection: dict, width: int, height: int) -> NormRect:
        """detections_to_rects_calculator.cc then rect_transformation_calculator.cc.

        Keypoints 0 and 1 are the two eyes; the rect is rotated so they lie on
        a horizontal line (target angle 0), then expanded by 1.5.
        """
        rotation = compute_rotation(
            detection["keypoints"][0], detection["keypoints"][1], width, height
        )
        rect: NormRect = (
            (detection["xmin"] + detection["xmax"]) / 2.0,
            (detection["ymin"] + detection["ymax"]) / 2.0,
            detection["xmax"] - detection["xmin"],
            detection["ymax"] - detection["ymin"],
            rotation,
        )
        return transform_normalized_rect(rect, _ROI_SCALE, _ROI_SCALE)

    # ------------------------------------------------------------- landmarks
    def _landmarks_for(self, image_rgb: np.ndarray, rect: NormRect) -> np.ndarray:
        height, width = image_rgb.shape[:2]
        roi = get_roi(width, height, rect)
        pad_roi(_LANDMARKS_SIZE, _LANDMARKS_SIZE, False, roi)
        tensor = image_to_tensor(
            image_rgb, roi, _LANDMARKS_SIZE, _LANDMARKS_SIZE,
            _LANDMARKS_RANGE[0], _LANDMARKS_RANGE[1], BORDER_REPLICATE,
        )

        outputs = self._invoke(self._landmarks, tensor[None, ...])
        landmark_outputs = [o for o in outputs if o.size >= _NUM_LANDMARKS * 3]
        if not landmark_outputs:
            raise ModelInferenceError("Landmark model produced no landmark tensor")

        raw = landmark_outputs[0].reshape(-1, 3)[:_NUM_LANDMARKS]
        # Model emits crop-pixel coordinates in 0..256, not normalized values.
        normalized = (raw[:, :2] / _LANDMARKS_SIZE).astype(np.float32)
        return project_landmarks(normalized, rect)

    # ------------------------------------------------------------ blendshape
    def _blendshapes_for(
        self, landmarks: np.ndarray, width: int, height: int
    ) -> dict[str, float]:
        subset = landmarks[list(BLENDSHAPE_LANDMARK_SUBSET)]
        denormalized = denormalize_for_blendshapes(subset, width, height)
        scores = self._invoke(self._blendshapes, denormalized[None, ...])[0].reshape(-1)
        return {name: float(score) for name, score in zip(BLENDSHAPE_NAMES, scores, strict=True)}

    # ------------------------------------------------------------------ main
    def detect(self, image_rgb: np.ndarray) -> dict | None:
        """Run the full pipeline on one RGB frame.

        Returns ``None`` when no face is detected, otherwise a dict with
        ``landmarks`` (478x2, image-normalized) and ``blendshapes``
        (name -> score).
        """
        detections = self._detect(image_rgb)
        if not detections:
            return None

        height, width = image_rgb.shape[:2]
        rect = self._detection_to_rect(detections[0], width, height)
        landmarks = self._landmarks_for(image_rgb, rect)
        return {
            "landmarks": landmarks,
            "blendshapes": self._blendshapes_for(landmarks, width, height),
            "score": detections[0]["score"],
        }
