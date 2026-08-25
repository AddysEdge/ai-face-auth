"""Local Windows face-authentication MVP.

All biometric processing happens on this machine: no image, frame, template, or
embedding is ever transmitted. This package is **not** network-silent, though -
the bundled MediaPipe binary uploads usage telemetry to play.googleapis.com on
session teardown, and upstream provides no supported way to disable it. See
docs/PRIVACY_NETWORK_AUDIT.md for the full measurement and ADR-0005 for the
open decision.

See docs/RESEARCH.md for the technical rationale behind every model and
architecture choice, and docs/THREAT_MODEL.md for what this system does and
does not defend against. This package never talks to the real Windows logon
path (LogonUI/Winlogon/LSA) - it is a standalone demo application.
"""

__version__ = "0.1.0"
