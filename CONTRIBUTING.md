# Contributing

Thanks for looking at this. Before anything else, please read
[SECURITY.md](SECURITY.md) - particularly
["What this project will never do"](SECURITY.md#what-this-project-will-never-do).
Those boundaries are not negotiable, and a change that crosses one will be
turned down however well it is written.

This is a **research prototype**. Its value is in being honest about what it
can and cannot do, so a change that improves a capability but overstates it is
a net loss.

## Project layout

| Path | What it is |
|---|---|
| `src/faceauth/` | Phase 1: the standalone Python pipeline. Real, working, complete for its scope. |
| `tests/` | Python test suite (224 tests): the Phase 1 pipeline, plus the OS-level network check. |
| `scripts/` | Model fetcher and the live liveness-calibration diagnostic. |
| `native/` | Phase 2: the inert IPC contract scaffold. **Not** a Credential Provider, **not** a service. |
| `docs/` | Research, architecture, threat model, Phase 2 review, ADRs. |

## Python setup (3.12)

Python is pinned to 3.12 in `pyproject.toml`. The CV/ML stack here - MediaPipe
especially - is most reliably supported there (`docs/RESEARCH.md`).

```powershell
uv venv --python 3.12 .venv
uv pip install --python .venv -e ".[dev]"
python scripts/fetch_models.py
```

A plain `venv` + `pip install -e ".[dev]"` works identically; `uv` is just what
was used during development. `scripts/fetch_models.py` downloads the ONNX/task
model files and verifies their SHA-256 against
`src/faceauth/model_registry.py`. **Model weights are never committed.**

## Native toolchain setup

Required only if you are touching `native/`:

- Windows x64
- Visual Studio 2022 Build Tools or newer, with **Desktop development with C++**
- CMake 3.21 or newer

There are no third-party native dependencies, and there must not be any: the
only libraries linked are `bcrypt` and `advapi32`, both OS components. Adding a
third-party dependency to a security-boundary scaffold needs a strong,
explicitly argued case.

## Build and test commands

Run all of these before opening a pull request. CI runs exactly the same ones.

### Python

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\ruff.exe check --no-cache src tests scripts
.venv\Scripts\mypy.exe --no-incremental src
```

Every existing test must still pass, and any test you add must pass too. The
suite is 224 tests as of this writing; treat the current count as whatever
`pytest --collect-only -q` reports rather than a number copied from here.

If your environment denies pytest access to the system temp directory, redirect
it into the repository (`.pytest_tmp/` is gitignored):

```powershell
.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp
```

### Native

```powershell
cmake -S native -B native/build -A x64
cmake --build native/build --config Debug
ctest --test-dir native/build -C Debug --output-on-failure
cmake --build native/build --config Release
ctest --test-dir native/build -C Release --output-on-failure
```

Warnings are errors (`/W4 /permissive- /WX`). Fix the warning; do not suppress
it. `-DFACEAUTH_WARNINGS_AS_ERRORS=OFF` exists for iterating locally, not for
landing code.

If you add a test to `native/tests/test_protocol.cpp`, add its name to
`FACEAUTH_TEST_NAMES` in `native/CMakeLists.txt` as well, so CTest reports it
individually. `protocol.all_registered_tests` runs everything the binary knows
about and will catch the omission.

## Formatting and type checking

- **Ruff** is the formatter and linter of record. Line length 100; rule set
  `E, F, I, UP, B, SIM` (`pyproject.toml`). Run `ruff check --fix` for the
  mechanical ones.
- **mypy** must pass cleanly on `src`. `disallow_untyped_defs` is off, but new
  code should be annotated anyway.
- **C++** follows the existing style in `native/`: 4-space indent, 100-column
  soft limit, `snake_case` functions, `PascalCase` types, trailing underscore
  on private members. There is no clang-format config; match the surrounding
  file.

## Security boundaries

Everything under `native/` is deliberately inert. Keep it that way. In
particular:

- The IPC contract must never gain a free-form, blob, or unbounded-length
  field. That absence is what makes "this channel cannot carry a frame, an
  embedding, a template, a password, a certificate, or a key" verifiable by
  reading one header instead of trusting a policy
  (`docs/adr/0003-ipc-security-protocol.md` section 2.1).
- Any protocol change is a **version bump**, not an in-place edit of version 1.
- `ICredentialGate` in `native/include/faceauth/ipc/boundaries.hpp` has no
  implementation on purpose. A fake credential gate is exactly the "path that
  reports successful Windows authentication based only on a face match" this
  project must never create. Do not add one, not even for tests.
- Fail-closed is a structural property, not a convention. If you add a state,
  transition, or error path, its default must be DENY.

## Prohibited changes

Two different things are listed below, and the difference matters. Conflating
them would make the project's own documented Phase 3 roadmap impossible to ever
deliver, which would be its own kind of dishonesty.

### Permanently prohibited - no phase, no approval, ever

- Handling a Windows password in any form, at any layer: requesting, reading,
  deriving, storing, serializing, transmitting, or auto-typing it. This
  includes APIs that hand a credential blob back to this process (see
  `docs/adr/0004-enrollment-provisioning-and-recovery.md` E5).
- Populating an `Exclude` list, filtering or hiding the password provider or
  Windows Hello, or making this the sole sign-in option.
- Modifying or patching LogonUI, Winlogon, LSA, Credential Guard, Windows
  Hello, Windows authentication policies, or account settings.
- Bypassing Windows' own authorization decision, or reporting a successful
  Windows authentication on the basis of a face match alone.
- Using undocumented NGC or Windows Hello internals.
- Sending biometric data off the machine.
- Weakening domain-controller certificate-binding enforcement (for example via
  `StrongCertificateBindingEnforcement`) to make a weak mapping work.
- Claiming an API or integration path is supported without a citation to
  current official Microsoft documentation.
- Committing biometric data, templates, raw images, model weights, runtime
  logs, private keys, certificates, secrets, registry exports, or build output.
- Weakening, skipping, deleting, or rewriting a test to make the suite pass.
- Describing this project as equivalent to Windows Hello, or removing an
  existing limitation warning without evidence that the limitation is gone.

### Currently gated - Phase 2 gate, not a permanent ban

These are **blocked today** and will stay blocked until the Phase 3 entry
criteria in `docs/PHASE2_ACCEPTANCE_CRITERIA.md` Part B - **every criterion,
including B4a, B16, and B17** - pass and the repository owner records explicit
written approval:

- Implementing `ICredentialProvider` / `ICredentialProviderCredential2`.
- COM registration: a CLSID, a credential-provider registry entry, a
  `DllRegisterServer`, or a `.reg` file.
- Installing, starting, stopping, or configuring a Windows service.
- Credential serialization - constructing a `KERB_*` structure.
- TPM, NCrypt, CNG, or certificate-store access.
- Camera access from native code.

A PR that lands any of these **without** that approval will be closed. A PR
that lands them **with** it is the whole point of Phase 3 (see
["Proposing gated Phase 3 work"](#proposing-gated-phase-3-work) below).

The `repo-hygiene` CI job enforces the current gate mechanically. It is a
backstop, not the boundary.

## Proposing gated Phase 3 work

Phase 3 is not forbidden forever - it is **not authorized yet**. To propose it:

1. Confirm **every Part B entry criterion, including B4a, B16, and B17**, in
   `docs/PHASE2_ACCEPTANCE_CRITERIA.md` has evidence, and link that evidence.
   The list is not a contiguous range - do not write "B1-B15" and assume it
   covers everything.
2. Link the owner's recorded product-scope decision accepting the
   AD-domain-only scope (**B7**).
3. Link the disposable-VM snapshot/rollback policy (**B5**) and the rehearsed
   recovery runbook (**B6**).
4. Link the independent Windows-authentication implementation-plan security
   review (**B11**).
5. Link the strong-certificate-binding verification against a Full Enforcement
   domain controller (**B4a**), and the cancellable-backend design if
   in-flight cancellation is in scope (**B16**).
6. Link the evidence that the verification path makes **no outbound network
   connections** (**B17**): ADR-0005 accepted with Option A or B implemented,
   and `scripts/check_network_activity.py` showing zero external endpoints
   against an empty `scripts/network_allowlist.json`. A firewall rule or a
   hosts-file entry does not count - the requirement is a property of the
   software, not of the machine it happens to run on.
7. Use the **Phase 3 (gated)** option in the pull-request template and complete
   its extra checklist instead of the Phase 2 boundary checklist.

**Changing the `repo-hygiene` guard is itself gated.** It may only be relaxed
by a separate, standalone "Phase 3 enablement" PR that changes nothing else,
links the approval above, and states exactly which markers are being unblocked
and why. Do not weaken it as a side effect of a feature PR, and never delete
the job.

## Privacy rules

- **Never commit biometric data.** No face images, no video, no embeddings, no
  templates. Not in tests, not in fixtures, not in documentation.
- Tests use synthetic arrays and the fakes in `tests/conftest.py`. If you need
  a new fixture, generate it - do not capture one.
- Logging goes through `SecurityLogger.log_event` in Python and
  `DiagnosticEvent` in C++. Both reject biometric and secret field names
  outright rather than redacting them, and both accept only primitive values.
  Do not add a bypass.
- Similarity scores are logged as coarse buckets, never as raw floats next to
  an identity. Keep it that way - a raw score is a side channel.
- Never create or collect a face dataset for this project. The evaluation tool
  (`faceauth evaluate`) computes metrics from scores **you already have**; it
  does not gather them.

## Pull request expectations

- **One concern per PR.** A refactor mixed with a behaviour change is hard to
  review and harder to revert. Phase 3 enablement is always its own PR.
- **Branch from `main`.** Do not commit to `main` directly.
- **Explain the security impact**, even if it is "none". The PR template asks;
  answer it honestly.
- **Include tests.** A bug fix should come with a regression test that fails
  before the fix.
- **Cite your sources.** Any claim about Windows behaviour needs a link to
  current official Microsoft documentation. "It seems to work" is not evidence,
  and neither is a blog post.
- **Do not weaken a warning to make a feature look better.** If measurement
  shows a documented limitation is wrong, bring the measurement and we will
  gladly change the docs.
- **Report results honestly.** If a test fails, say so and paste the output. A
  PR that says "all tests pass" when they do not is worse than a broken PR.

### Commit messages

Conventional-commit style, matching the existing history:

```
feat: implement composite liveness provider (AND semantics)
test: add persistent rate limiter tests
docs: add Phase 2 security review and ADRs
fix: reject trailing bytes after the declared payload
```

Explain *why* in the body when it is not obvious. The existing history does
this well - `git log` is worth reading before you write yours.

## Questions

Open a regular issue for questions and ideas. For anything security-sensitive,
use the private channels in [SECURITY.md](SECURITY.md) instead.
