from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType

from faceauth.pipeline_types import Frame


class CameraProvider(ABC):
    """Source of video frames.

    Implementations MUST guarantee the underlying device is released in
    ``close()`` even if ``open()`` partially failed or an exception occurred
    while frames were being read - callers are expected (and tested) to use
    this as a context manager rather than call open/close manually.
    """

    @abstractmethod
    def open(self) -> None:
        """Acquire the camera device. Raises CameraUnavailableError on failure."""

    @abstractmethod
    def read(self) -> Frame:
        """Return the next available frame. Raises CameraUnavailableError if the
        device stops producing frames."""

    @abstractmethod
    def close(self) -> None:
        """Release the camera device. Must be safe to call multiple times and
        safe to call even if ``open()`` was never called or failed."""

    @abstractmethod
    def is_opened(self) -> bool: ...

    def __enter__(self) -> CameraProvider:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
