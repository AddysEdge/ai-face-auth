"""Local Windows face-authentication MVP.

All biometric processing happens on this machine: no image, frame, template, or
embedding is ever transmitted. As of Phase 2.5 the package makes no outbound
network connections at all - the mediapipe wheel, whose bundled binary uploaded
usage telemetry to play.googleapis.com on session teardown with no supported
opt-out, has been replaced by ai-edge-litert running the same pinned weights.
See docs/PRIVACY_NETWORK_AUDIT.md for the original measurement and ADR-0005 for
the decision.

See docs/RESEARCH.md for the technical rationale behind every model and
architecture choice, and docs/THREAT_MODEL.md for what this system does and
does not defend against. This package never talks to the real Windows logon
path (LogonUI/Winlogon/LSA) - it is a standalone demo application.
"""

__version__ = "0.1.0"
