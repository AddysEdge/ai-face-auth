#!/usr/bin/env python3
"""Downloads the pretrained model files this repo needs and verifies their
checksums against src/faceauth/model_registry.py.

The two OpenCV Zoo ONNX files are stored via Git LFS in that repo; fetching
them from raw.githubusercontent.com returns the LFS *pointer* text (~130
bytes), not the binary - this script uses the actual LFS media endpoint,
which was verified to serve the real binary during development (see
docs/RESEARCH.md).

Usage: python scripts/fetch_models.py [--models-dir PATH]
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from faceauth.model_registry import MODEL_REGISTRY  # noqa: E402

_LFS_MEDIA_MAP = {
    "yunet_2023mar.onnx": (
        "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/"
        "models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
    ),
    "sface_2021dec.onnx": (
        "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/"
        "models/face_recognition_sface/face_recognition_sface_2021dec.onnx"
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_all(models_dir: Path) -> int:
    models_dir.mkdir(parents=True, exist_ok=True)
    failures = 0
    for entry in MODEL_REGISTRY:
        dest = models_dir / entry.filename
        url = _LFS_MEDIA_MAP.get(entry.filename, entry.source_url)
        if dest.exists() and entry.sha256 and _sha256(dest) == entry.sha256:
            print(f"[ok] {entry.filename} already present and verified")
            continue
        print(f"[fetch] {entry.filename} <- {url}")
        try:
            urllib.request.urlretrieve(url, dest)  # noqa: S310 - fixed, hardcoded HTTPS URLs only
        except OSError as exc:
            print(f"[error] failed to download {entry.filename}: {exc}")
            failures += 1
            continue
        if entry.sha256:
            actual = _sha256(dest)
            if actual != entry.sha256:
                print(
                    f"[error] checksum mismatch for {entry.filename}: "
                    f"expected {entry.sha256}, got {actual}"
                )
                dest.unlink(missing_ok=True)
                failures += 1
                continue
        print(f"[ok] {entry.filename} downloaded and verified ({entry.license_name})")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--models-dir", type=Path, default=REPO_ROOT / "models", help="Destination directory."
    )
    args = parser.parse_args()
    failures = fetch_all(args.models_dir)
    if failures:
        print(f"{failures} model(s) failed to download/verify.")
        return 1
    print("All models present and verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
