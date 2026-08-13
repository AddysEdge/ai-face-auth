"""Local, offline Windows face-authentication MVP.

See docs/RESEARCH.md for the technical rationale behind every model and
architecture choice, and docs/THREAT_MODEL.md for what this system does and
does not defend against. This package never talks to the real Windows logon
path (LogonUI/Winlogon/LSA) - it is a standalone demo application.
"""

__version__ = "0.1.0"
