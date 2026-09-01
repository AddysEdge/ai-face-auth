"""Reject tracked B18 participant data, generated evidence, and runtime artifacts.

Run by CI over every tracked file, and runnable locally:

    python scripts/check_b18_data_leak.py            # check the working tree
    python scripts/check_b18_data_leak.py --self-test  # prove the rules bite

Why this is not a pathname check
--------------------------------
An earlier version exempted whole directories - ``scripts/b18_stage0/`` and
``tests/test_b18_*`` - on the theory that they hold only source. A ``git add -f``
of a real manifest into either would then have been invisible, and so would a
generated ``results.json`` or ``report.md`` dropped beside the code that makes
them. **There are no directory exemptions here.** Every rule is applied to every
tracked file, and the allowlist is a short list of exact paths that are exempt
from one named rule each, never from all of them.

The rules distinguish *source code that describes the manifest format* from
*data in the manifest format* structurally, not by where the file sits:

* A file whose entire content parses as JSON and carries manifest fields is
  data. That is true under ``tests/`` exactly as it is under ``docs/``.
* Source code mentioning ``blink_scores`` is source code. It does not parse as
  a JSON document, so the manifest rule never looks at it.
* A generated Stage 0 report carries the run banner. Publishing aggregate
  evidence to Git requires decision **D16**, which is undecided, so no such file
  may be tracked - see docs/B18_REAL_INPUT_VALIDATION_PLAN.md §11.3.

Undecodable files fail closed. A file this guard cannot read is a file it cannot
clear, and ``errors="ignore"`` would silently hide exactly the bytes worth
hiding.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
from typing import Any, NamedTuple

# --------------------------------------------------------------------- rules

#: Fields that together identify a session manifest.
MANIFEST_FIELDS = ("participant_id", "session_id", "blink_scores", "trials")
MANIFEST_FIELD_THRESHOLD = 2

#: Emitted into every generated Stage 0 report and result document.
REPORT_SIGNATURES = (
    "SYNTHETIC STAGE 0 EVIDENCE ONLY",
    "## Per-participant results",
    "### FAR per attack type",
)

#: Extensions that may never be tracked, whatever they contain.
FORBIDDEN_SUFFIXES = {
    # models and weights
    ".task", ".tflite", ".onnx", ".pb", ".pt", ".pth", ".h5", ".caffemodel",
    ".safetensors", ".bin", ".weights",
    # recordings and stills
    ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp", ".heic",
    ".mp4", ".mov", ".avi", ".mkv", ".webm", ".wav", ".mp3", ".m4a",
    # archives and databases
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".db", ".sqlite",
    ".sqlite3", ".mdb", ".parquet",
    # secrets and credentials
    ".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".ppk",
}

#: Path prefixes and suffixes that are runtime artifacts, never source.
FORBIDDEN_PATH_PREFIXES = ("b18_data/", "b18_workspace/", "b18_stage0_", "b18_stage0_rehearsal_")
FORBIDDEN_PATH_SUFFIXES = (".manifest.json", "/results.json", "/report.md")

#: Labelled identity fields, in the form ``Signature: <value>``.
#:
#: The colon is required: prose such as "signature matches the real boundary" or
#: ``inspect.signature(...)`` is not a record, and an earlier draft that made the
#: colon optional flagged eleven files of ordinary source and documentation.
#:
#: The captured value is then post-filtered by :func:`_is_filled`, because a
#: *blank* form is a template, not a record - the repository deliberately ships
#: ``CONSENT_FORM.md`` carrying ``**Participant signature:** `____` `` so a human
#: can print and sign it on paper, and that file must stay tracked.
#:
#: The value stops at the next bold label or table cell boundary. Without that,
#: ``**Signature:** `___`  **Date:** `___` `` captured the word "Date" from the
#: *following* label and read a blank form as filled.
IDENTITY_FIELDS = re.compile(
    r"\b(signature|full\s+name|date\s+of\s+birth|signed\s+by)\s*\**\s*:"
    r"(?P<value>(?:(?!\*\*[A-Za-z])[^\r\n|])*)",
    re.I,
)

#: Fires wherever it appears: this phrasing has no template reading.
STRONG_IDENTITY = (re.compile(r"\bI\s+consent\b", re.I),)

#: Characters a blank form uses to mark where a value goes.
_PLACEHOLDER_CHARS = set(" \t_`*|<>[]().-/…")
_PLACEHOLDER_WORDS = {"na", "n/a", "none", "tbd", "redacted", "pseudonym", "p", "s"}

#: Weak signatures are contact details: identifying on a consent form, and
#: unremarkable in source. They fire only close to identity context.
#:
#: The telephone pattern demands real separators and refuses a match touching a
#: decimal point or a hyphenated date - an earlier draft read ``0.3999999995``
#: and ``2026-01-01`` as phone numbers, which would have made the rule noise.
WEAK_IDENTITY = (
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"),
    re.compile(
        r"(?<![\d.\-])(?:\+\d{1,3}[ .\-]?)?(?:\(\d{2,4}\)[ .\-]?)?"
        r"\d{3,4}[ .\-]\d{3,4}(?:[ .\-]\d{2,4})?(?![\d.\-])"
    ),
)
IDENTITY_CONTEXT = re.compile(r"participant|consent|enrol|enroll", re.I)

#: How close a weak signature must sit to identity context to count.
IDENTITY_PROXIMITY = 200

#: Document types that carry content rather than produce it. A generated report
#: is one of these; the code that renders it is not.
DOCUMENT_SUFFIXES = {".md", ".markdown", ".txt", ".csv", ".tsv", ".html", ".htm", ".rst"}

#: A rendered evidence row - a Markdown table row whose first cell is a
#: participant or camera pseudonym. Templates and source do not contain these.
RENDERED_EVIDENCE_ROW = re.compile(r"^\|\s*[PS]\d{2,4}\s*\|", re.M)

#: A tabular participant/session record: a header naming a participant column
#: and a score or outcome column.
TABLE_HEADER = re.compile(
    r"participant[_\s]*id\b.{0,120}?\b(blink_?scores?|max_blink|attempt_outcome)",
    re.I | re.S,
)

#: Exact paths exempt from ONE named rule each. Never a directory, never blanket.
ALLOWLIST: dict[str, set[str]] = {
    # This guard's own self-test embeds representative leaked documents so the
    # rules can be proven to bite. It is the only file that needs an exemption,
    # and the structural manifest and type rules still apply to it.
    "scripts/check_b18_data_leak.py": {
        "report-signature", "identity-record", "participant-table",
    },
}


class Finding(NamedTuple):
    path: str
    rule: str
    detail: str


def _exempt(path: str, rule: str) -> bool:
    return rule in ALLOWLIST.get(path, set())


def _manifest_shaped(document: Any) -> int:
    """How many manifest fields a parsed JSON document exposes."""
    found: set[str] = set()

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if key in MANIFEST_FIELDS:
                    found.add(key)
                walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:50]:
                walk(item, depth + 1)

    walk(document)
    return len(found)


def _is_filled(value: str) -> bool:
    """True when an identity field carries a real value rather than a blank.

    A form ships with ``Signature: ____``; a record carries ``Signature: A
    Name``. Anything made only of placeholder punctuation, or whose words are
    all placeholder words, is a blank.
    """
    stripped = "".join(ch for ch in value if ch not in _PLACEHOLDER_CHARS).strip()
    if len(stripped) < 2:
        return False
    if not any(ch.isalnum() for ch in stripped):
        return False
    words = [w for w in re.split(r"[^A-Za-z0-9/]+", stripped.lower()) if w]
    return bool(words) and not all(w in _PLACEHOLDER_WORDS for w in words)


def _identity_finding(text: str) -> str | None:
    """Describe an identity or consent signature in ``text``, or return None."""
    for pattern in STRONG_IDENTITY:
        match = pattern.search(text)
        if match:
            return f"consent/identity phrasing {match.group(0)!r}"

    for match in IDENTITY_FIELDS.finditer(text):
        value = match.group("value")
        if _is_filled(value):
            label = match.group(1).lower()
            return f"identity field {label!r} carries a filled value, not a blank"

    contexts = [m.start() for m in IDENTITY_CONTEXT.finditer(text)]
    if not contexts:
        return None
    for pattern in WEAK_IDENTITY:
        for match in pattern.finditer(text):
            if any(abs(match.start() - start) <= IDENTITY_PROXIMITY for start in contexts):
                return (
                    f"contact detail {match.group(0)!r} within "
                    f"{IDENTITY_PROXIMITY} characters of participant/consent context"
                )
    return None


def classify(path: str, raw: bytes) -> list[Finding]:
    """Every reason this tracked file must not be in the repository."""
    findings: list[Finding] = []
    lowered = path.lower()
    suffix = pathlib.PurePosixPath(lowered).suffix

    if suffix in FORBIDDEN_SUFFIXES:
        findings.append(Finding(path, "forbidden-type",
                                f"{suffix} files (models, media, archives, keys) are never tracked"))
        return findings

    if lowered.startswith(FORBIDDEN_PATH_PREFIXES) or any(
        lowered.endswith(s) for s in FORBIDDEN_PATH_SUFFIXES
    ):
        findings.append(Finding(path, "runtime-artifact",
                                "a Stage 0 workspace or generated run artifact"))
        return findings

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Fail closed: unreadable is not the same as clean.
        findings.append(Finding(path, "undecodable",
                                f"not valid UTF-8 ({exc}); cannot be cleared by inspection"))
        return findings

    # --- structural: is the whole file a manifest? ------------------------
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            document = json.loads(text)
        except ValueError:
            document = None
        if document is not None:
            count = _manifest_shaped(document)
            if count >= MANIFEST_FIELD_THRESHOLD:
                findings.append(Finding(
                    path, "manifest-data",
                    f"parses as JSON carrying {count} manifest field(s); a session "
                    f"manifest is data about a person and is never tracked",
                ))

    # --- generated Stage 0 evidence ---------------------------------------
    #
    # Source that *emits* the banner is not a report; a document *carrying* it
    # is. Extension separates the two, and for source types the banner alone is
    # not enough - it must come with a rendered evidence row, which a template
    # never has. That keeps ``analyze.py`` (which defines the banner) clean while
    # still catching a report renamed to ``.py`` to slip past the type check.
    if not _exempt(path, "report-signature"):
        carries_banner = any(signature in text for signature in REPORT_SIGNATURES)
        rendered = RENDERED_EVIDENCE_ROW.search(text) is not None
        is_document = suffix in DOCUMENT_SUFFIXES
        if carries_banner and (is_document or rendered):
            findings.append(Finding(
                path, "report-signature",
                "carries generated Stage 0 report structure; publishing aggregate "
                "evidence to Git requires decision D16, which is undecided",
            ))

    # --- participant/session tables ---------------------------------------
    if not _exempt(path, "participant-table") and TABLE_HEADER.search(text):
        findings.append(Finding(path, "participant-table",
                                "a per-participant table of scores or outcomes"))

    # --- consent / identity records ---------------------------------------
    if not _exempt(path, "identity-record"):
        detail = _identity_finding(text)
        if detail is not None:
            findings.append(Finding(path, "identity-record", detail))

    return findings


# ---------------------------------------------------------------- self-test

_LEAKED_MANIFEST = json.dumps({
    "session_id": "S01",
    "participant_id": "P01",
    "data_classification": "synthetic_stage0",
    "trials": [{"trial_index": 0, "blink_scores": [0.21, 0.62, 0.18]}],
}).encode("utf-8")

_LEAKED_REPORT = (
    b"# B18 Stage 0\n\nSYNTHETIC STAGE 0 EVIDENCE ONLY - B18 REMAINS OPEN.\n\n"
    b"## Per-participant results (primary)\n\n| Participant | FRR |\n|---|---|\n| P01 | 1/4 |\n"
)

_LEAKED_TABLE = (
    b"participant_id,session_id,blink_scores\nP01,S01,\"0.21;0.62\"\n"
)

_LEAKED_CONSENT = (
    b"Participant consent record\n\nFull name: A Real Person\n"
    b"Signature: A Real Person\nContact: someone@example.com\n"
)

#: A blank form is a template, not a record. The repository deliberately ships
#: one so a participant could sign it on paper, so this must NOT be rejected.
_BLANK_FORM = (
    b"# Participant consent form\n\n"
    b"**Participant signature:** `____________________`  **Date:** `__________`\n"
)

#: Source that renders a report is not a report. This must NOT be rejected.
_RENDERING_SOURCE = (
    b'BANNER = "SYNTHETIC STAGE 0 EVIDENCE ONLY - B18 REMAINS OPEN."\n'
    b'def render():\n    return BANNER\n'
)

#: The same report renamed to a source extension, carrying a rendered evidence
#: row. The type check alone would not catch it; the rendered row does.
#:
#: Every leaked sample lives here rather than in the test suite, because a file
#: containing these literals IS what the guard rejects - putting them in
#: tests/test_b18_stage0_corrections.py made the guard flag that file, which was
#: correct. Keeping one definition inside the single allowlisted file lets the
#: tests import them without widening the allowlist to cover a test.
_DISGUISED_REPORT = _LEAKED_REPORT + b"\n| P01 | 1/4 |\n"

#: Each case is (label, path, bytes, expected rule). The paths deliberately sit
#: under directories the old guard trusted outright.
SELF_TEST_CASES = (
    ("leaked manifest under the tool's own source directory",
     "scripts/b18_stage0/session_S01.json", _LEAKED_MANIFEST, "manifest-data"),
    ("leaked manifest under the test directory",
     "tests/test_b18_fixture.json", _LEAKED_MANIFEST, "manifest-data"),
    ("leaked manifest with an innocuous name at the repository root",
     "notes.json", _LEAKED_MANIFEST, "manifest-data"),
    ("generated report under the test directory",
     "tests/test_b18_report.md", _LEAKED_REPORT, "report-signature"),
    ("generated report under docs",
     "docs/b18/stage0_report.md", _LEAKED_REPORT, "report-signature"),
    ("participant score table as CSV",
     "scripts/b18_stage0/summary.csv", _LEAKED_TABLE, "participant-table"),
    ("consent record",
     "docs/b18/forms/signed_consent.md", _LEAKED_CONSENT, "identity-record"),
    ("model weights",
     "tests/face_landmarker.task", b"\x00\x01", "forbidden-type"),
    ("captured still",
     "scripts/b18_stage0/frame.png", b"\x89PNG", "forbidden-type"),
    ("published run artifact",
     "b18_stage0_abc123/run-0001/results.json", b"{}", "runtime-artifact"),
    ("undecodable file",
     "docs/notes.md", b"\xff\xfe\x00garbage\xc3\x28", "undecodable"),
    ("report renamed to .py to dodge the type check",
     "scripts/b18_stage0/report_backup.py", _DISGUISED_REPORT, "report-signature"),
)

#: Files that must be accepted. A guard that rejects the repository's own
#: templates and source is a guard nobody can leave switched on.
SELF_TEST_NEGATIVES = (
    ("blank consent form", "docs/b18/forms/CONSENT_FORM.md", _BLANK_FORM),
    ("source that renders the banner", "scripts/b18_stage0/analyze.py", _RENDERING_SOURCE),
)


def self_test() -> int:
    """Prove each rule bites, including under previously trusted paths."""
    failures = 0
    for label, path, raw, expected in SELF_TEST_CASES:
        rules = {f.rule for f in classify(path, raw)}
        ok = expected in rules
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}\n"
              f"         {path} -> {sorted(rules) or 'no findings'}")
        if not ok:
            failures += 1

    for label, path, raw in SELF_TEST_NEGATIVES:
        rules = {f.rule for f in classify(path, raw)}
        ok = not rules
        print(f"  [{'PASS' if ok else 'FAIL'}] accepted: {label}"
              f"{'' if ok else ' -> ' + str(sorted(rules))}")
        if not ok:
            failures += 1

    # And the real tracked source must still pass, or the guard is unusable.
    real = ("scripts/b18_stage0/schema.py", "scripts/b18_stage0/synthetic.py",
            "scripts/b18_stage0/analyze.py", "scripts/b18_stage0/cli.py",
            "tests/test_b18_manifest_validator.py", "tests/test_b18_analysis.py",
            "docs/b18/forms/CONSENT_FORM.md")
    checked = 0
    for path in real:
        candidate = pathlib.Path(path)
        if not candidate.is_file():
            continue
        checked += 1
        rules = {f.rule for f in classify(path, candidate.read_bytes())}
        ok = not rules
        print(f"  [{'PASS' if ok else 'FAIL'}] real file stays clean: {path}"
              f"{'' if ok else ' -> ' + str(sorted(rules))}")
        if not ok:
            failures += 1

    total = len(SELF_TEST_CASES) + len(SELF_TEST_NEGATIVES) + checked
    print(f"\nself-test: {total - failures} passed, {failures} failed")
    return 1 if failures else 0


# -------------------------------------------------------------------- driver

def tracked_files() -> list[str]:
    result = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
    return [line for line in result.stdout.splitlines() if line.strip()]


def check_tree() -> int:
    findings: list[Finding] = []
    scanned = 0
    for name in tracked_files():
        path = pathlib.Path(name)
        try:
            raw = path.read_bytes()
        except OSError:
            continue        # deleted from the working tree but still in the index
        scanned += 1
        findings.extend(classify(name, raw))

    if findings:
        print(f"::error::{len(findings)} B18 data-leak finding(s) in tracked files")
        for finding in findings:
            print(f"  {finding.path}: [{finding.rule}] {finding.detail}")
        print("\nNo directory is exempt from these rules. Publishing aggregate "
              "Stage 0 evidence requires decision D16, which is undecided.")
        return 1

    print(f"No B18 participant data, generated evidence, or runtime artifacts "
          f"tracked ({scanned} files scanned by content and type).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true",
                        help="prove the rules reject representative leaked files")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    return check_tree()


if __name__ == "__main__":
    raise SystemExit(main())
