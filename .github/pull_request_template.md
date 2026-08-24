<!--
Please read CONTRIBUTING.md and SECURITY.md before opening this PR.
Do NOT report a security vulnerability here - use the private channels in
SECURITY.md instead.
-->

## What this changes

<!-- One or two sentences. What is different after this PR? -->

## Why

<!-- The problem being solved. Link an issue if there is one. -->

## Phase and scope

- [ ] Phase 1 (Python pipeline under `src/faceauth/`)
- [ ] Phase 2 (documentation, ADRs, or the inert `native/` scaffold)
- [ ] Repository infrastructure (CI, docs, tooling)
- [ ] Other (explain below)

## Security impact

<!-- Required. "None" is an acceptable answer, but say it explicitly and say
     why. If this touches liveness, template storage, rate limiting, logging,
     the fail-closed paths, or the IPC contract, describe the impact in detail. -->

## Verification

Paste the actual output. If something failed, say so - a PR that claims a green
run it did not get is worse than a red one.

```
# .venv\Scripts\python.exe -m pytest -q
# (paste result)

# .venv\Scripts\ruff.exe check --no-cache src tests scripts
# (paste result)

# .venv\Scripts\mypy.exe --no-incremental src
# (paste result)
```

If `native/` changed:

```
# cmake -S native -B native/build -A x64
# cmake --build native/build --config Debug
# ctest --test-dir native/build -C Debug --output-on-failure
# cmake --build native/build --config Release
# ctest --test-dir native/build -C Release --output-on-failure
# (paste results)
```

- [ ] All 137 pre-existing Python tests still pass
- [ ] Any tests I added pass
- [ ] Ruff passes
- [ ] mypy passes
- [ ] Native Debug and Release build and test pass, **or** I do not have the
      MSVC/CMake toolchain and am relying on CI (say which)
- [ ] I did not weaken, skip, delete, or rewrite a test to make the suite pass

## Boundary checklist

Confirm every line. These are the project's non-negotiable boundaries
(CONTRIBUTING.md, SECURITY.md).

- [ ] No Windows password is requested, read, derived, stored, serialized,
      transmitted, or auto-typed
- [ ] No Credential Provider is registered; no CLSID or credential-provider
      registry entry is created or modified
- [ ] No Windows service is installed, started, stopped, or configured
- [ ] No change to LogonUI, Winlogon, LSA, Credential Guard, Windows Hello,
      provider filters, authentication policies, or account settings
- [ ] No credential serialization; no `KERB_*` structure is constructed
- [ ] No TPM, NCrypt, certificate, or camera access is added to `native/`
- [ ] No undocumented NGC or Windows Hello internals are used
- [ ] No path reports a successful Windows authentication based on a face match
- [ ] No biometric data, template, raw image, model weight, log, key,
      certificate, secret, registry export, or build output is committed
- [ ] Any claim about Windows behaviour cites current official Microsoft
      documentation (link it below)
- [ ] Nothing describes this project as equivalent to Windows Hello
- [ ] Existing limitation warnings (RGB liveness, video replay, no Windows
      sign-in integration) are intact, or their removal is justified by
      evidence included here

## Sources

<!-- Links to official documentation for any Windows behaviour claim. -->

## Anything a reviewer should look at first

<!-- The part you are least sure about. Being honest here speeds up review. -->
