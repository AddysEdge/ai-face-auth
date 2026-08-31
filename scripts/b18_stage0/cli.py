"""Command line for B18 Stage 0 manifest validation and analysis.

    python -m scripts.b18_stage0.cli validate         MANIFEST [MANIFEST ...]
    python -m scripts.b18_stage0.cli analyse          MANIFEST [MANIFEST ...]
    python -m scripts.b18_stage0.cli rehearse-cleanup

Exit codes
----------
``0``  every manifest is valid; for ``analyse``, the run was published.
``1``  the manifests were read but are not acceptable - schema findings, or a
       corpus that cannot legitimately be aggregated.
``2``  the command could not run at all: a missing or unreadable file, invalid
       UTF-8, duplicate JSON keys, unparseable JSON, or an output workspace that
       could not be created or written.

"Your data is wrong" and "I could not look at your data" are different answers,
and a caller scripting this needs to tell them apart.

Output safety
-------------
No option names an output path. An earlier revision accepted arbitrary
destinations, which let ``pyproject.toml`` be nominated as a report path and let
both artefacts resolve to the same file; a later one accepted ``--workspace``,
which a forged marker could satisfy. Both are gone. ``analyse`` creates its own
workspace beneath the system temporary directory and publishes into a fresh
``run-NNNN`` inside it, under fixed filenames. Output is left in place for
review - nothing deletes it.

Nothing is written until the input is fully accepted. Parsing, schema validation
and corpus validation all complete *before* the workspace is created, so an
invalid run leaves no directory behind at all: an empty workspace is
indistinguishable from a run that produced nothing, and that ambiguity is worth
avoiding. Both artefacts are then staged and published by a single atomic
rename, so a failure cannot leave one finished-looking file behind.

``rehearse-cleanup`` exercises the deletion procedure. It takes no path, and
there is no flag that will delete a path you name - see ``cleanup.py``.

Nothing here touches a camera, a network, or any real participant record.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b18_stage0.analyze import analyse, render_markdown  # noqa: E402
from scripts.b18_stage0.cleanup import rehearsal_report, rehearse  # noqa: E402
from scripts.b18_stage0.corpus import CorpusError  # noqa: E402
from scripts.b18_stage0.schema import ManifestError, require_valid_session  # noqa: E402
from scripts.b18_stage0.workspace import (  # noqa: E402
    WorkspaceError,
    create_workspace,
    next_run_directory,
)

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_USAGE = 2

RESULTS_NAME = "results.json"
REPORT_NAME = "report.md"


class UsageError(Exception):
    """The command could not run. Distinct from the data being invalid."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``json`` keeps the last of duplicate keys; that silently discards data.

    A manifest with two ``participant_id`` entries would validate against
    whichever survived, so duplicates are refused rather than resolved.
    """
    seen: set[str] = set()
    duplicates: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            duplicates.add(key)
        seen.add(key)
    if duplicates:
        raise ValueError(f"duplicate object key(s): {sorted(duplicates)}")
    return dict(pairs)


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise UsageError(f"{path}: no such file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UsageError(f"{path}: cannot read ({exc})") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UsageError(f"{path}: not valid UTF-8 ({exc})") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as exc:      # JSONDecodeError and the duplicate-key raise
        raise UsageError(f"{path}: not valid JSON ({exc})") from exc


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


def _publish(workspace: Path, results: str, report: str) -> Path:
    """Stage both artefacts, then publish the run directory atomically.

    Writing straight into the final location risks a half-published run that
    looks like a completed result. The staging directory is removed on any
    failure, so the workspace either gains a whole run or gains nothing.
    """
    run_dir = next_run_directory(workspace)
    staging = run_dir.with_name(run_dir.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    try:
        staging.mkdir(parents=True)
        (staging / RESULTS_NAME).write_text(results, encoding="utf-8", newline="\n")
        (staging / REPORT_NAME).write_text(report, encoding="utf-8", newline="\n")
        staging.rename(run_dir)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise UsageError(f"{workspace}: cannot publish run ({exc})") from exc
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="b18-stage0",
        description=(
            "B18 Stage 0: validate synthetic session manifests and analyse them. "
            "Synthetic manifests only - every input must declare "
            "data_classification 'synthetic_stage0'."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate manifests against the schema")
    validate.add_argument("manifests", nargs="+", type=Path)

    analyse_cmd = sub.add_parser("analyse", help="validate, then publish an analysis run")
    analyse_cmd.add_argument("manifests", nargs="+", type=Path)

    sub.add_parser(
        "rehearse-cleanup",
        help="exercise the deletion procedure on a throwaway directory (takes no path)",
    )

    args = parser.parse_args(argv)

    if args.command == "rehearse-cleanup":
        try:
            record = rehearse()
        except OSError as exc:
            print(f"ERROR: cleanup rehearsal could not run ({exc})", file=sys.stderr)
            return EXIT_USAGE
        print(rehearsal_report(record), end="")
        return EXIT_OK

    try:
        sessions, findings = _validate_all(list(args.manifests))
    except UsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if findings:
        print(f"INVALID: {len(findings)} finding(s)", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print("\nNo manifest was partially accepted. Fix the findings and re-run.",
              file=sys.stderr)
        return EXIT_INVALID

    if args.command == "validate":
        print(f"VALID: {len(sessions)} synthetic manifest(s), schema-conformant")
        print(
            "Automated validation cannot prove that free-text fields are "
            "non-identifying. A human must read `notes` and `operator_role` "
            "before any manifest leaves the approved storage."
        )
        return EXIT_OK

    try:
        result = analyse(sessions, list(args.manifests))
    except CorpusError as exc:
        print(f"INVALID: {len(exc.findings)} corpus finding(s)", file=sys.stderr)
        for finding in exc.findings:
            print(f"  {finding}", file=sys.stderr)
        print("\nThese manifests cannot legitimately be aggregated. No analysis was run.",
              file=sys.stderr)
        return EXIT_INVALID
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    serialised = json.dumps(result, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    report = render_markdown(result)

    # Only now, with valid input and a rendered result in hand, does anything
    # touch the filesystem. An invalid run leaves no workspace behind at all:
    # an empty workspace is indistinguishable from a run that produced nothing.
    try:
        workspace = create_workspace()
    except (OSError, WorkspaceError) as exc:
        print(f"ERROR: cannot create an output workspace ({exc})", file=sys.stderr)
        return EXIT_USAGE

    try:
        run_dir = _publish(workspace, serialised, report)
    except (UsageError, WorkspaceError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(f"published {run_dir}")
    print(f"  {RESULTS_NAME}")
    print(f"  {REPORT_NAME}")
    print(
        "\nSYNTHETIC STAGE 0 EVIDENCE ONLY - B18 REMAINS OPEN. "
        "This run authorizes nothing."
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
