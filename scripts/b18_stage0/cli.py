"""Command line for B18 Stage 0 manifest validation and analysis.

    python -m scripts.b18_stage0.cli validate MANIFEST [MANIFEST ...]
    python -m scripts.b18_stage0.cli analyse  MANIFEST [MANIFEST ...] \
        [--out results.json] [--report report.md]

Exit codes
----------
``0``  every manifest is valid; for ``analyse``, the analysis completed.
``1``  at least one manifest failed validation. Findings are printed, one per
       line, each naming the JSON path that failed.
``2``  the command could not run at all: a missing or unreadable file,
       unparseable JSON, a refused output path, or a write failure.

A validation failure is deliberately distinct from a usage failure - "your data
is wrong" and "I could not look at your data" are different answers, and a
caller scripting this needs to tell them apart.

Nothing here touches a camera, a network, or any real participant record. It
reads JSON and writes JSON and Markdown.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b18_stage0.analyze import analyse, render_markdown  # noqa: E402
from scripts.b18_stage0.schema import ManifestError, require_valid_session  # noqa: E402

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_USAGE = 2


class UsageError(Exception):
    """The command could not run. Distinct from a manifest being invalid."""


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise UsageError(f"{path}: no such file")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"{path}: cannot read ({exc})") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageError(f"{path}: not valid JSON ({exc})") from exc


def _resolve_output(raw: str) -> Path:
    """Refuse output paths that would write outside an existing directory.

    Guards against a traversal-shaped argument silently landing a report
    somewhere unexpected. The parent must already exist: this tool writes
    reports, it does not create directory trees on a caller's behalf.
    """
    path = Path(raw).expanduser()
    resolved = (Path.cwd() / path).resolve() if not path.is_absolute() else path.resolve()
    parent = resolved.parent
    if not parent.is_dir():
        raise UsageError(f"{raw}: output directory {parent} does not exist")
    if resolved.is_dir():
        raise UsageError(f"{raw}: is a directory, not a file")
    return resolved


def _write(path: Path, content: str) -> None:
    """Write atomically enough that a failure leaves no truncated artefact.

    A half-written report is worse than none: it looks like evidence.
    """
    temporary = path.with_name(path.name + ".partial")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.replace(path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise UsageError(f"{path}: cannot write ({exc})") from exc


def _validate_all(paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    sessions: list[dict[str, Any]] = []
    findings: list[str] = []
    for path in sorted(paths):
        document = _load(path)
        try:
            sessions.append(require_valid_session(document, path.name))
        except ManifestError as exc:
            findings.extend(exc.findings)
    return sessions, findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="b18-stage0",
        description="B18 Stage 0: validate session manifests and analyse them.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate manifests against the schema")
    validate.add_argument("manifests", nargs="+", type=Path)

    analyse_cmd = sub.add_parser("analyse", help="validate, then produce aggregate results")
    analyse_cmd.add_argument("manifests", nargs="+", type=Path)
    analyse_cmd.add_argument("--out", help="write machine-readable results here")
    analyse_cmd.add_argument("--report", help="write the Markdown report here")

    args = parser.parse_args(argv)

    try:
        # Resolve output paths before doing any work, so a bad path fails fast
        # rather than after the analysis has run.
        out_path = _resolve_output(args.out) if getattr(args, "out", None) else None
        report_path = _resolve_output(args.report) if getattr(args, "report", None) else None

        sessions, findings = _validate_all(list(args.manifests))
    except UsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if findings:
        print(f"INVALID: {len(findings)} finding(s)", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "\nNo manifest was partially accepted. Fix the findings and re-run.",
            file=sys.stderr,
        )
        return EXIT_INVALID

    if args.command == "validate":
        print(f"VALID: {len(sessions)} manifest(s), schema-conformant")
        print(
            "Automated validation cannot prove that free-text fields are "
            "non-identifying. A human must read `notes` and `operator_role` "
            "before any manifest leaves the approved storage."
        )
        return EXIT_OK

    try:
        result = analyse(sessions)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = render_markdown(result)
    # sort_keys plus a fixed separator keeps this byte-identical run to run.
    serialised = json.dumps(result, indent=1, sort_keys=True, ensure_ascii=False) + "\n"

    try:
        if out_path is not None:
            _write(out_path, serialised)
        if report_path is not None:
            _write(report_path, report)
    except UsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if out_path is None and report_path is None:
        print(report)
    else:
        if out_path is not None:
            print(f"wrote {out_path}")
        if report_path is not None:
            print(f"wrote {report_path}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
