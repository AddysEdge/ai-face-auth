"""Demo lock-screen interface.

This is ONLY a demonstration application - a plain Tkinter window - and
must never be confused with, and does not touch, the real Windows LogonUI.
It exists to show the pipeline's state machine (CAMERA READY -> FACE
DETECTED -> CHECKING LIVENESS -> VERIFYING IDENTITY -> ACCESS
GRANTED/DENIED -> TRY AGAIN / COOLDOWN ACTIVE) end to end against a real
webcam. See docs/PHASE2_CREDENTIAL_PROVIDER.md for how a *real* Windows
integration would legitimately work instead.

Runs the actual pipeline (enrollment or authentication) on a background
thread and marshals UI updates back to the main thread via
``root.after(...)`` - Tkinter widgets must only be touched from the main
thread.
"""

from __future__ import annotations

import threading
import tkinter as tk
from typing import Literal

from faceauth.authentication import AuthenticationService
from faceauth.enrollment import EnrollmentService
from faceauth.exceptions import EnrollmentFailedError, FaceAuthError, RateLimitedError
from faceauth.pipeline_types import CHALLENGE_PROMPTS, AuthDecision, ChallengeKind, DemoState

_STATE_TEXT: dict[DemoState, str] = {
    DemoState.CAMERA_READY: "CAMERA READY",
    DemoState.FACE_DETECTED: "FACE DETECTED",
    DemoState.CHECKING_LIVENESS: "CHECKING LIVENESS",
    DemoState.VERIFYING_IDENTITY: "VERIFYING IDENTITY",
    DemoState.ACCESS_GRANTED: "ACCESS GRANTED",
    DemoState.ACCESS_DENIED: "ACCESS DENIED",
    DemoState.TRY_AGAIN: "TRY AGAIN",
    DemoState.COOLDOWN_ACTIVE: "COOLDOWN ACTIVE",
}
_STATE_COLOR: dict[DemoState, str] = {
    DemoState.ACCESS_GRANTED: "#1b8a3a",
    DemoState.ACCESS_DENIED: "#a33a3a",
    DemoState.COOLDOWN_ACTIVE: "#a3843a",
}
_DEFAULT_COLOR = "#2b2b2b"
_RETRY_DELAY_MS = 2000


class DemoLockScreenApp:
    def __init__(
        self,
        service: AuthenticationService | EnrollmentService,
        user_id: str,
        mode: Literal["authenticate", "enroll"],
    ) -> None:
        self._service = service
        self._user_id = user_id
        self._mode = mode

        self._root = tk.Tk()
        self._root.title("FaceAuth Demo (NOT Windows Hello / NOT LogonUI)")
        self._root.geometry("520x320")
        self._root.configure(bg=_DEFAULT_COLOR)

        self._banner = tk.Label(
            self._root,
            text="DEMO ONLY - does not touch Windows sign-in",
            fg="#cccccc",
            bg=_DEFAULT_COLOR,
            font=("Segoe UI", 9),
        )
        self._banner.pack(pady=(10, 0))

        self._state_label = tk.Label(
            self._root,
            text="IDLE",
            fg="white",
            bg=_DEFAULT_COLOR,
            font=("Segoe UI", 24, "bold"),
        )
        self._state_label.pack(expand=True)

        self._detail_label = tk.Label(
            self._root, text="", fg="#cccccc", bg=_DEFAULT_COLOR, font=("Segoe UI", 10)
        )
        self._detail_label.pack(pady=(0, 10))

        self._button = tk.Button(
            self._root,
            text="Start Enrollment" if mode == "enroll" else "Start Authentication",
            command=self._start,
        )
        self._button.pack(pady=(0, 20))

    def run(self) -> None:
        self._root.mainloop()

    def _start(self) -> None:
        self._button.config(state=tk.DISABLED)
        self._detail_label.config(text="")
        thread = threading.Thread(target=self._run_pipeline, daemon=True)
        thread.start()

    def _run_pipeline(self) -> None:
        try:
            if self._mode == "enroll":
                assert isinstance(self._service, EnrollmentService)
                enroll_result = self._service.enroll(
                    self._user_id, on_state=self._post_state, on_challenge=self._post_challenge
                )
                self._root.after(
                    0,
                    self._finish,
                    DemoState.ACCESS_GRANTED,
                    f"Enrolled ({enroll_result.num_samples_used} samples)",
                )
            else:
                assert isinstance(self._service, AuthenticationService)
                auth_result = self._service.authenticate(
                    self._user_id, on_state=self._post_state, on_challenge=self._post_challenge
                )
                final = (
                    DemoState.ACCESS_GRANTED
                    if auth_result.decision is AuthDecision.GRANTED
                    else DemoState.ACCESS_DENIED
                )
                self._root.after(0, self._finish, final, auth_result.reason)
        except RateLimitedError as exc:
            self._root.after(
                0,
                self._finish,
                DemoState.COOLDOWN_ACTIVE,
                f"retry in {exc.retry_after_seconds:.0f}s",
            )
        except EnrollmentFailedError as exc:
            self._root.after(0, self._finish, DemoState.ACCESS_DENIED, str(exc))
        except FaceAuthError as exc:
            self._root.after(0, self._finish, DemoState.ACCESS_DENIED, str(exc))

    def _post_state(self, state: DemoState) -> None:
        self._root.after(0, self._apply_state, state, "")

    def _post_challenge(self, kind: ChallengeKind) -> None:
        prompt = CHALLENGE_PROMPTS.get(kind, kind.name)
        self._root.after(0, self._detail_label.config, {"text": prompt})

    def _apply_state(self, state: DemoState, detail: str) -> None:
        self._state_label.config(
            text=_STATE_TEXT.get(state, state.name), bg=_STATE_COLOR.get(state, _DEFAULT_COLOR)
        )
        self._root.configure(bg=_STATE_COLOR.get(state, _DEFAULT_COLOR))
        self._detail_label.config(text=detail)

    def _finish(self, state: DemoState, detail: str) -> None:
        self._apply_state(state, detail)
        if state is DemoState.COOLDOWN_ACTIVE:
            self._apply_state(DemoState.COOLDOWN_ACTIVE, detail)
        else:
            self._apply_state(DemoState.TRY_AGAIN if state is DemoState.ACCESS_DENIED else state, detail)
        self._root.after(_RETRY_DELAY_MS, lambda: self._button.config(state=tk.NORMAL))
