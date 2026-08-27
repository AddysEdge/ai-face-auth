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
- [ ] **Phase 3 (gated)** - complete the Phase 3 section below instead of the
      Phase 2 gate checklist
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

- [ ] All pre-existing Python tests still pass (no count is hard-coded here on
      purpose - it goes stale; paste the run above)
- [ ] Any tests I added pass
- [ ] Ruff passes
- [ ] mypy passes
- [ ] Native Debug and Release build and test pass, **or** I do not have the
      MSVC/CMake toolchain and am relying on CI (say which)
- [ ] I did not weaken, skip, delete, or rewrite a test to make the suite pass

## Permanent boundary checklist

Confirm every line. These apply to **every** PR in **every** phase and are never
waived (CONTRIBUTING.md "Permanently prohibited", SECURITY.md).

- [ ] No Windows password is requested, read, derived, stored, serialized,
      transmitted, or auto-typed - including via any API that returns a
      credential blob to this process
- [ ] No `Exclude` list, no provider filtering, no hiding of the password
      provider or Windows Hello, and this is never the sole sign-in option
- [ ] No change to LogonUI, Winlogon, LSA, Credential Guard, Windows Hello,
      authentication policies, or account settings
- [ ] Windows' own authorization decision is not bypassed, and no path reports a
      successful Windows authentication based on a face match alone
- [ ] No undocumented NGC or Windows Hello internals are used
- [ ] No biometric data leaves the machine
- [ ] No weakening of domain-controller certificate-binding enforcement
- [ ] No biometric data, template, raw image, model weight, log, key,
      certificate, secret, registry export, or build output is committed
- [ ] Any claim about Windows behaviour cites current official Microsoft
      documentation (link it below)
- [ ] Nothing describes this project as equivalent to Windows Hello
- [ ] Existing limitation warnings (RGB liveness, video replay, no Windows
      sign-in integration) are intact, or their removal is justified by
      evidence included here

## Phase 2 gate checklist

Complete this **unless** you ticked "Phase 3 (gated)" above. These are current
gates, not permanent prohibitions - see CONTRIBUTING.md.

- [ ] No Credential Provider is registered; no CLSID, provider registry entry,
      `DllRegisterServer`, or `.reg` file
- [ ] No Windows service is installed, started, stopped, or configured
- [ ] No credential serialization; no `KERB_*` structure is constructed
- [ ] No TPM, NCrypt, certificate, or camera access is added to `native/`

## Phase 3 (gated) - only if you ticked it above

Phase 3 work is **not authorized by default**. Link the evidence; a PR without
these links will be closed.

- [ ] Owner's recorded product-scope decision accepting the AD-domain-only
      scope (B7): <!-- link -->
- [ ] Evidence for **every Part B entry criterion, including B4a, B16, and B17**, in
      `docs/PHASE2_ACCEPTANCE_CRITERIA.md` (the list is not a contiguous
      range): <!-- link -->
- [ ] Disposable-VM snapshot/rollback policy (**B5**) and rehearsed recovery
      runbook (**B6**): <!-- link -->
- [ ] Independent Windows-authentication implementation-plan security review
      (**B11**): <!-- link -->
- [ ] Strong certificate binding verified against a Full Enforcement domain
      controller (**B4a**): <!-- link -->
- [ ] If in-flight cancellation is in scope: cancellable/bounded backend and an
      interruptible service design, under a new protocol version (**B16**):
      <!-- link -->
- [ ] Verification path makes **no outbound network connections** (**B17**):
      ADR-0005 accepted with Option A or B implemented, and
      `scripts/check_network_activity.py` showing zero external endpoints with
      an empty `scripts/network_allowlist.json`: <!-- link -->
- [ ] This PR does **not** also relax the `repo-hygiene` CI guard. Relaxing it
      is a separate, standalone Phase 3-enablement PR.

## Sources

<!-- Links to official documentation for any Windows behaviour claim. -->

## Anything a reviewer should look at first

<!-- The part you are least sure about. Being honest here speeds up review. -->
