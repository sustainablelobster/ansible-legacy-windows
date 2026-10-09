# Working instructions for coding agents

## Craft

Maintained code is not disposable. Correct behavior is necessary, but working
code alone is not finished work. Names must convey purpose, structure must
reveal the design, and interfaces must be understandable and usable. Each
change must form a coherent part of the surrounding system.

Judge simplicity by what the reader must understand. Passing tests does not
excuse confusing names, hidden assumptions, unnecessary duplication, or
accumulated workarounds. Write for people who will use and change the code
after the original conversation is forgotten.

## Product and boundaries

`sustainablelobster.legacy_windows` aims to reimplement all first-party
`ansible.windows` functionality with Python 3.4.4-compatible Windows payloads.
The [README](README.md) is the user entry point. Keep user-facing prerequisites
and meaningful limitations in [Usage](docs/usage.md), not these instructions.
Windows versions and connection plugins are not allowlisted; distinguish the
capabilities a workflow needs from the environments in its execution evidence.

Do not infer runtime support from a successful build, local installation, or
controller-side test. Base implementation on a recorded upstream release and
verified controller-to-target behavior. Do not invent a transport framework to
fill gaps in execution evidence.

Python 3.4.4 is the minimum Windows target version, not an exact-version
requirement. Target payloads and every imported helper must use Python
3.4.4-compatible syntax, standard-library APIs, and dependencies. Controller
code must support the declared controller Python versions; development tooling
uses Nix Python.
Keep these execution environments explicit; do not introduce a modern dependency
into target code through a shared helper. Prove target compatibility using the
actual Python 3.4.4 runtime on an authorized Windows host before claiming it.

## Engineering rules

- Prefer maintained libraries and established tools over custom machinery,
  subject to the target runtime requirement.
- Prefer Python's standard library for target behavior and native Windows APIs
  for management operations it cannot provide. Preserve familiar upstream
  interfaces where practical; document meaningful differences instead of
  recreating PowerShell or .NET internals for exact equivalence.
- Write only code needed for the current user-visible outcome. Do not add
  abstractions, registries, state models, or frameworks for possible future work.
- Keep names, types, and control flow obvious. Validate real inputs and return
  actionable failures.
- Do not add compatibility layers for unreleased designs.
- Test observable behavior, idempotence, failures, and recovery rather than
  implementation trivia. Never weaken a gate merely to make it pass.
- Treat size warnings as prompts to review module boundaries, not quotas.
- Keep warning suppressions narrow. Add an adjacent plain-English comment
  explaining why suppression is clearer than changing the code.
- Use Ansible's module documentation format for module interfaces and
  Sphinx-style docstrings for public Python contracts. Obvious private helpers
  do not need ceremonial docstrings.
- License project contributions under GPL-3.0-or-later, matching the recorded
  ansible.windows baseline. Preserve required upstream and compatible
  third-party notices, copyrights, and license files. Do not add notices for tools
  merely installed as development dependencies.
- Use Joe Lustri for project-owned author and copyright attribution.
  `sustainablelobster` is the GitHub handle and collection namespace, not an
  organization or a collective author. Preserve third-party attribution.
- Do not echo credentials gratuitously. Keep private inventories and local
  connection settings out of version control and collection artifacts.
- Keep agent-created logs, captures, inventories, snapshots and working files
  under `tmp/codex/`. Preserve historical evidence there; do not scatter agent
  outputs directly under `tmp/` or move user inputs without authorization.

## Command-first work

Every implementation increment starts with one sentence:

```text
DEMO: <exact command> -> <observable result>
```

Run that command after the change. If it cannot demonstrate the result, the
increment is not complete. A packaging command demonstrates packaging, not
Windows execution. A deletion-only cleanup demonstrates that affected
commands still work while maintained code or prose is removed.

Use a usable module or comparable user-visible feature as the default
increment. Build its interface, payload, helper staging, and behavior tests
together; keep helper fixes within that increment rather than treating each
as a separate handoff. Prioritize exercising the public behavior. Expand
edge-case investigation when a supported workflow, an observed failure, or a
review finding requires it. Record significant limitations without claiming
untested behavior; incidental upstream differences are not release blockers.

Independent module increments may be implemented in parallel with explicit
file ownership. Coordinate shared-code edits, collection installation, and lab
operations so one worker cannot invalidate another's execution evidence. Each
increment still requires its own demonstration, relevant checks, and independent
review before a support claim. Stop and ask the user when progress depends on a
product choice, unavailable infrastructure, unknown Windows or Ansible
behavior that cannot be established by authorized tests, or materially broader
work. Do not fill the gap with defensive scaffolding.

## Development and checks

Use the standalone Nix environment and commands in the
[development guide](docs/development.md). Keep developer-tool versions in
`flake.lock`; keep target and controller compatibility separate from the
workstation interpreter. Do not depend on a parent project's environment.

Install hooks explicitly; never install them automatically on shell entry.
Do not change global Nix or Git configuration to make local checks work.

Run the demonstration and `just lint check` before handoff, including relevant
behavior tests. Use focused checks during development, then run the full
required checks on the integrated increment. After a fix, rerun the checks
whose evidence it invalidates; do not repeat the whole suite for every edit.
Documentation-only changes need documentation checks and review, not another
Windows run. Retain prior execution evidence when the tested behavior and its
dependencies are unchanged, recording the relationship between revisions.

Report every failed or skipped check and distinguish controller-only evidence
from execution on Windows. Routine local checks must not contact Windows
hosts or lab infrastructure. These batching rules do not relax target-runtime,
cleanup, recovery, or compatibility requirements.

## Review and commits

Use an independent human reviewer or a separate assistant when available.
Review does not depend on a particular coding harness or agent definition.
If an independent reviewer is unavailable, disclose that limit and perform a
self-review without presenting it as independent review.

For material changes to user or engineering documentation, docstrings, or
comments, include a documentation review. Check technical accuracy before
reader usefulness and prose. Assign explicit file ownership to any reviewer
who edits; the implementer owns integration and checks.

After the demonstration and required checks pass, obtain one independent,
read-only review of the complete increment when a reviewer is available.
Review against a recorded, previously reviewed baseline, including all affected
shared code, tests, and documentation. An accumulating uncommitted worktree
does not require reviewing unchanged earlier increments again. Review wider
behavior when new changes invalidate earlier conclusions. Record the baseline
and reviewed diff without creating commits merely to establish a checkpoint.
The initial brief contains only:

- The user's request.
- The raw increment diff and its baseline identifier, or the commit range.
- The instruction to review the implementation and behavior.

Do not provide the implementer's summary, rationale, claimed test results,
suspected weak points, or suggested verdict. The reviewer reads relevant files
and runs useful checks independently, examining defects, regressions,
unnecessary complexity, maintainability, names, interfaces, and whether the
result serves the user's job.

Findings must identify exact locations and concrete effects on users or
maintainers. Do not invent new architecture or hypothetical requirements.
Even a passing review must name the paths and behavior inspected and describe
how the reviewer tried to find faults. Fix valid findings and return the
corrections for review when the reviewer is available; do not restart unrelated
review or validation for each correction.

When a local commit is part of the authorized work:

1. Re-read the complete intended diff and `git status`.
2. Stage only explicit reviewed paths, never `git add .` or `git add -A`.
3. Run `git diff --cached --check`.
4. Create one cohesive commit with an imperative subject of at most 72 characters.

Do not initialize a repository, amend, rebase, reset, tag, push, change Git
configuration, or mutate a remote unless the user explicitly requests it.

## Communication and lab access

Speak in plain English. Lead with what changed, what it means, and what the
user needs to do next. Keep updates proportionate; include logs and internal
details only when they help the user understand, decide, or act.

Lab access and mutations require explicit authorization. A bounded or standing
grant remains valid until revoked or its stated condition ends. Stay within
the granted systems and operations, report material effects, and clean up
resources the work creates. External actions outside an active grant and
destructive Git operations require fresh approval.
