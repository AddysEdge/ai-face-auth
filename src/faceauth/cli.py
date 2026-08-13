"""Command-line entry point: `faceauth <command> ...`.

Every command builds its pipeline through pipeline_factory.py from an
AppConfig - no command constructs a concrete implementation directly, so the
CLI automatically picks up any backend swap made there.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from faceauth import pipeline_factory
from faceauth.config import load_config
from faceauth.evaluate import evaluate, load_score_file
from faceauth.exceptions import FaceAuthError, RateLimitedError
from faceauth.pipeline_types import CHALLENGE_PROMPTS, AuthDecision, ChallengeKind


def _announce_challenge(kind: ChallengeKind) -> None:
    # Printed immediately when the challenge window opens so a human has a
    # real chance to react within it - see capture_utils.py's module
    # docstring for why this matters (a live test found the window was
    # otherwise too short and unannounced to be usable). flush=True matters:
    # Python fully buffers stdout when it isn't attached to a real terminal
    # (e.g. piped/redirected output), which would otherwise silently delay
    # this "real-time" prompt until process exit - a second real bug found
    # live, alongside the timing one.
    print(f">>> {CHALLENGE_PROMPTS.get(kind, kind.name)}!", flush=True)


def _cmd_enroll(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    service = pipeline_factory.build_enrollment_service(config)
    print(
        f"Enrolling '{args.user_id}': collecting {config.enrollment.num_samples} samples. "
        f"You'll have {config.liveness.challenge_timeout_seconds:.0f}s per prompt to react."
    )
    try:
        result = service.enroll(args.user_id, on_challenge=_announce_challenge)
    except FaceAuthError as exc:
        print(f"Enrollment failed: {exc}")
        return 1
    print(f"Enrolled '{result.user_id}' using {result.num_samples_used} samples "
          f"(template_id={result.template_id}).")
    return 0


def _cmd_authenticate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    service = pipeline_factory.build_authentication_service(config)
    print(f"Authenticating '{args.user_id}': watch for the challenge prompt below.")
    try:
        result = service.authenticate(args.user_id, on_challenge=_announce_challenge)
    except RateLimitedError as exc:
        print(f"COOLDOWN ACTIVE - retry in {exc.retry_after_seconds:.0f}s")
        return 2
    similarity_line = (
        f"similarity={result.similarity:.4f} threshold={config.policy.similarity_threshold:.4f}"
        if result.similarity is not None
        else "similarity=n/a"
    )
    if result.decision is AuthDecision.GRANTED:
        print(f"ACCESS GRANTED ({result.reason}) [{similarity_line}]")
        return 0
    print(f"ACCESS DENIED ({result.reason}) [{similarity_line}]")
    return 1


def _cmd_demo(args: argparse.Namespace) -> int:
    from faceauth.authentication import AuthenticationService
    from faceauth.demo_ui import DemoLockScreenApp
    from faceauth.enrollment import EnrollmentService

    config = load_config(args.config)
    service: EnrollmentService | AuthenticationService
    if args.mode == "enroll":
        service = pipeline_factory.build_enrollment_service(config)
    else:
        service = pipeline_factory.build_authentication_service(config)
    app = DemoLockScreenApp(service=service, user_id=args.user_id, mode=args.mode)
    app.run()
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    genuine, impostor = load_score_file(args.scores)
    report = evaluate(genuine, impostor, target_far=args.target_far)
    output = {
        "num_genuine": report.num_genuine,
        "num_impostor": report.num_impostor,
        "eer": report.eer,
        "eer_threshold": report.eer_threshold,
        "recommended_threshold": report.recommended_threshold,
        "target_far": report.target_far,
        "roc": [
            {"threshold": p.threshold, "far": p.far, "frr": p.frr, "tar": p.tar}
            for p in report.roc
        ],
    }
    print(json.dumps(output, indent=2))
    return 0


def _cmd_list_users(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    logger = pipeline_factory.build_logger(config)
    store = pipeline_factory.build_template_store(config, logger)
    for user_id in store.list_users():
        print(user_id)
    return 0


def _cmd_delete_user(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    logger = pipeline_factory.build_logger(config)
    store = pipeline_factory.build_template_store(config, logger)
    store.delete(args.user_id)
    print(f"Deleted template for '{args.user_id}' (if it existed).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="faceauth", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_enroll = sub.add_parser("enroll", help="Enroll a new user via the webcam.")
    p_enroll.add_argument("--user-id", required=True)
    p_enroll.add_argument("--config", type=Path, default=None)
    p_enroll.set_defaults(func=_cmd_enroll)

    p_auth = sub.add_parser("authenticate", help="Authenticate an enrolled user via the webcam.")
    p_auth.add_argument("--user-id", required=True)
    p_auth.add_argument("--config", type=Path, default=None)
    p_auth.set_defaults(func=_cmd_authenticate)

    p_demo = sub.add_parser("demo", help="Launch the demo lock-screen window.")
    p_demo.add_argument("--user-id", required=True)
    p_demo.add_argument("--mode", choices=["enroll", "authenticate"], default="authenticate")
    p_demo.add_argument("--config", type=Path, default=None)
    p_demo.set_defaults(func=_cmd_demo)

    p_eval = sub.add_parser("evaluate", help="Compute FAR/FRR/EER from a genuine/impostor score file.")
    p_eval.add_argument("--scores", type=Path, required=True)
    p_eval.add_argument("--target-far", type=float, default=1e-5)
    p_eval.set_defaults(func=_cmd_evaluate)

    p_list = sub.add_parser("list-users", help="List enrolled user ids.")
    p_list.add_argument("--config", type=Path, default=None)
    p_list.set_defaults(func=_cmd_list_users)

    p_delete = sub.add_parser("delete-user", help="Delete an enrolled user's template.")
    p_delete.add_argument("--user-id", required=True)
    p_delete.add_argument("--config", type=Path, default=None)
    p_delete.set_defaults(func=_cmd_delete_user)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Python fully buffers stdout when it isn't attached to a real terminal
    # (piped/redirected output) - without this, every print() in this
    # module, including the real-time challenge prompts, would only appear
    # after the process exits. Found via a real live-hardware test.
    # typeshed's TextIO stub doesn't declare reconfigure(), but sys.stdout is
    # a real io.TextIOWrapper at runtime where this method exists (Python
    # 3.7+) and works correctly - not a bug, just a stub gap.
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
