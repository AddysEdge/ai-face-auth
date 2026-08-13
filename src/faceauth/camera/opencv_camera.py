from __future__ import annotations

import time

import cv2
import numpy as np

from faceauth.exceptions import CameraUnavailableError
from faceauth.interfaces.camera import CameraProvider
from faceauth.pipeline_types import Frame


class OpenCvCameraProvider(CameraProvider):
    """Webcam capture via OpenCV's VideoCapture.

    Uses the platform-appropriate backend automatically (DirectShow/Media
    Foundation on Windows via cv2.CAP_ANY) and always releases the capture
    handle in ``close()``, including when ``open()`` itself failed partway
    through - a partially-opened ``cv2.VideoCapture`` still holds the device
    handle until ``release()`` is called.
    """

    def __init__(self, device_index: int = 0, width: int = 640, height: int = 480) -> None:
        self._device_index = device_index
        self._width = width
        self._height = height
        self._cap: cv2.VideoCapture | None = None

    def open(self) -> None:
        cap = cv2.VideoCapture(self._device_index, cv2.CAP_ANY)
        try:
            if not cap.isOpened():
                raise CameraUnavailableError(
                    f"could not open camera at device index {self._device_index}"
                )
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, self._width)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self._height)
            self._cap = cap
        except Exception:
            cap.release()
            self._cap = None
            raise

    def read(self) -> Frame:
        if self._cap is None or not self._cap.isOpened():
            raise CameraUnavailableError("camera is not open")
        ok, image = self._cap.read()
        if not ok or image is None:
            raise CameraUnavailableError("camera stopped producing frames")
        return Frame(image=image, timestamp=time.monotonic())

    def close(self) -> None:
        if self._cap is not None:
            self._cap.release()
            self._cap = None

    def is_opened(self) -> bool:
        return self._cap is not None and self._cap.isOpened()


class ArrayFeedCameraProvider(CameraProvider):
    """Deterministic CameraProvider fed from a pre-supplied list of frames.

    Not a mock in the test-double sense - a genuine, real implementation of
    the interface useful for demos/tests/offline replay, e.g. against a
    recorded clip. Raises CameraUnavailableError once the feed is exhausted.
    """

    def __init__(self, frames: list[np.ndarray]) -> None:
        self._frames = frames
        self._index = 0
        self._opened = False

    def open(self) -> None:
        self._opened = True
        self._index = 0

    def read(self) -> Frame:
        if not self._opened:
            raise CameraUnavailableError("camera is not open")
        if self._index >= len(self._frames):
            raise CameraUnavailableError("frame feed exhausted")
        image = self._frames[self._index]
        self._index += 1
        return Frame(image=image, timestamp=time.monotonic())

    def close(self) -> None:
        self._opened = False

    def is_opened(self) -> bool:
        return self._opened
