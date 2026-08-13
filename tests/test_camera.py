from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from faceauth.camera.opencv_camera import ArrayFeedCameraProvider, OpenCvCameraProvider
from faceauth.exceptions import CameraUnavailableError


def test_array_feed_camera_yields_frames_in_order():
    frames = [np.zeros((2, 2, 3), np.uint8) + i for i in range(3)]
    cam = ArrayFeedCameraProvider(frames)
    with cam:
        for i in range(3):
            frame = cam.read()
            assert frame.image[0, 0, 0] == i


def test_array_feed_camera_raises_when_exhausted():
    cam = ArrayFeedCameraProvider([np.zeros((2, 2, 3), np.uint8)])
    with cam:
        cam.read()
        with pytest.raises(CameraUnavailableError):
            cam.read()


def test_array_feed_camera_read_before_open_raises():
    cam = ArrayFeedCameraProvider([np.zeros((2, 2, 3), np.uint8)])
    with pytest.raises(CameraUnavailableError):
        cam.read()


@patch("faceauth.camera.opencv_camera.cv2.VideoCapture")
def test_opencv_camera_releases_on_successful_open(mock_video_capture):
    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = True
    mock_video_capture.return_value = mock_cap

    cam = OpenCvCameraProvider(device_index=0)
    cam.open()
    assert cam.is_opened()
    cam.close()
    mock_cap.release.assert_called_once()


@patch("faceauth.camera.opencv_camera.cv2.VideoCapture")
def test_opencv_camera_releases_even_when_open_fails(mock_video_capture):
    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = False  # simulate device unavailable
    mock_video_capture.return_value = mock_cap

    cam = OpenCvCameraProvider(device_index=0)
    with pytest.raises(CameraUnavailableError):
        cam.open()
    mock_cap.release.assert_called_once()  # released even though open() raised
    assert not cam.is_opened()


@patch("faceauth.camera.opencv_camera.cv2.VideoCapture")
def test_opencv_camera_releases_even_when_exception_raised_inside_with_block(mock_video_capture):
    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = True
    mock_video_capture.return_value = mock_cap

    cam = OpenCvCameraProvider(device_index=0)
    with pytest.raises(RuntimeError), cam:
        raise RuntimeError("simulated failure mid-capture")
    mock_cap.release.assert_called_once()


@patch("faceauth.camera.opencv_camera.cv2.VideoCapture")
def test_opencv_camera_read_failure_raises_camera_unavailable(mock_video_capture):
    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = True
    mock_cap.read.return_value = (False, None)
    mock_video_capture.return_value = mock_cap

    cam = OpenCvCameraProvider(device_index=0)
    with cam, pytest.raises(CameraUnavailableError):
        cam.read()


def test_opencv_camera_close_is_idempotent():
    cam = OpenCvCameraProvider(device_index=0)
    cam.close()  # never opened - must not raise
    cam.close()
