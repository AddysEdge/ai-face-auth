# GitHub Actions workflows

## `ci.yml`

Runs on pushes to `main` and `phase-*`, on pull requests into `main`, and on
demand.

| Job | Runner | What it does |
|---|---|---|
| `python` | `windows-latest` | Installs the project with its declared dev extras on Python 3.12, then runs `pytest`, `ruff check --no-cache src tests scripts`, and `mypy --no-incremental src`. Uploads the JUnit XML. |
| `native` | `windows-latest` | Matrix over `Debug` and `Release`. Configures with `-A x64`, builds, and runs the full CTest suite. This is the **authoritative** native result: the development machine has no MSVC or CMake (`docs/PHASE2_ACCEPTANCE_CRITERIA.md` Part D). |
| `repo-hygiene` | `ubuntu-latest` | Fails if a binary, secret, key, certificate, registry export, model weight, log, or biometric artefact is tracked in git, and fails if a Credential Provider registration, service creation, or credential-serialization marker appears in code. |
| `dependency-review` | `ubuntu-latest` | Pull requests only. **Currently neither runs nor blocks - see below.** |
| `pip-audit` | `ubuntu-latest` | Audits the platform-independent dependency set. **Enforcing** - it fails the job on any known vulnerability affecting a declared dependency. See "Severity policy" below. |

### `dependency-review`: two separate things are currently false

It is worth being precise, because "enabled" can mean either of two things and
neither is true right now:

| Question | Answer today |
|---|---|
| Does the action **run** (actually review the diff)? | **No.** It requires the repository's **Dependency graph** feature, which is off, so it reports *"Dependency review is not supported on this repository"*. |
| Can the job **block a PR** if it finds something? | **No.** The step carries `continue-on-error: true`, so even a real finding would not fail the job. |

**Do not read a green tick on this job as "dependencies were reviewed."** The
job prints a warning annotation saying exactly that whenever the review did not
run. `pip-audit` is the dependency scanning that genuinely runs and genuinely
blocks today.

**Enabling Dependency graph alone does NOT make this enforcing.** It would make
the action *run*; the `continue-on-error: true` would still stop it failing the
job. Making it enforcing is therefore two deliberate changes:

1. A repository admin enables **Dependency graph** under Settings -> Code
   security. This is a repository security setting and is the owner's decision;
   it is deliberately not made automatically.
2. Someone removes `continue-on-error: true` from the step in `ci.yml`, in a PR
   that says so.

The job is wired up and left in place so that step 1 is all that is needed to
start getting real signal, and step 2 is a conscious choice to start enforcing
on it.

Enabling Dependency graph is also the prerequisite for Dependabot *security*
updates (currently disabled); Dependabot *version* updates, configured in
`dependabot.yml`, work regardless.

### Why `repo-hygiene` exists

`.gitignore` protects against accident. `repo-hygiene` protects against
`git add -f` and against someone quietly crossing a Phase 2 boundary. It greps
the tracked tree for `DllRegisterServer`, `ICredentialProviderCredential`,
`CredentialProviderFilters`, `CreateServiceW`/`CreateServiceA`,
`Security Packages`, and the `KERB_*` credential structures, outside
documentation. Those names are quoted deliberately in the ADRs, so `docs/**`,
`*.md`, and this workflow directory are excluded.

If you are legitimately introducing one of these in a later phase, the
exclusion list is the place to have that conversation - do not delete the job.

### `pip-audit` severity policy

`pip-audit` **fails the job on any known vulnerability** affecting a declared
dependency. It used to carry `continue-on-error`, which meant a green tick could
coexist with a live CVE - an advisory job nobody reads is not a security
control, so that was removed.

Every dependency is exactly pinned in `pyproject.toml`, so a finding is always
actionable: bump the pin, or add an explicit `--ignore-vuln` exception in
`ci.yml` **with a comment explaining why it does not apply here**. There are no
ignored advisories today, and adding one silently is not acceptable.

## Pinned action versions

Every action is pinned to a full commit SHA with a trailing version comment:

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

A moving tag like `@v7` can be repointed at new code by whoever controls the
repository; a SHA cannot. The version comment keeps the pin readable, and
Dependabot's `github-actions` ecosystem understands this exact form - it bumps
both the SHA and the comment together, so pinning does not freeze the actions.

## `codeql.yml`

Runs on the same triggers plus a weekly schedule, so a newly published query
still reaches old commits.

| Job | Runner | Language |
|---|---|---|
| `analyze-python` | `ubuntu-latest` | `python`, `build-mode: none`, `security-and-quality` |
| `analyze-cpp` | `windows-latest` | `c-cpp`, `build-mode: manual`, `security-and-quality` |

The C++ job builds manually because the CMake project lives in `native/`, which
autobuild does not discover. It configures with
`-DFACEAUTH_WARNINGS_AS_ERRORS=OFF` so a CodeQL instrumentation warning cannot
mask the analysis; `ci.yml` is what enforces the strict-warning build.

## Permissions and secrets

Every workflow declares `permissions: contents: read` at the top level. Only
the CodeQL jobs widen it, to the `security-events: write` they need to upload
results, and only within those jobs.

**No workflow uses, references, or has access to a repository secret.** A pull
request from a fork therefore cannot exfiltrate anything, and no job can mutate
the repository.

## `dependabot.yml`

Weekly `pip` and `github-actions` updates. Every dependency is exactly pinned
in `pyproject.toml`, so Dependabot surfaces a release or advisory as a PR that
must pass the full matrix before it can merge - it is a review trigger, not a
silent updater.

CV/ML dependencies are grouped (`opencv-*`, `onnxruntime*`, `mediapipe`,
`numpy`) because they constrain each other and MediaPipe pulls
`opencv-contrib-python` transitively (`docs/RESEARCH.md` section 18); bumping
them one at a time produces conflicting PRs.

The native project has no third-party dependencies, so there is no ecosystem
registered for it. Add one here at the same time as adding the dependency.

## Local equivalents

Everything CI runs, you can run:

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\ruff.exe check --no-cache src tests scripts
.venv\Scripts\mypy.exe --no-incremental src

cmake -S native -B native/build -A x64
cmake --build native/build --config Debug
ctest --test-dir native/build -C Debug --output-on-failure
cmake --build native/build --config Release
ctest --test-dir native/build -C Release --output-on-failure
```
