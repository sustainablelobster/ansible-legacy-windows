# Development

Use the source checkout for development. Collection archives contain user
documentation and plugins, but exclude development tools and tests.

## Enter the Nix environment

Install Nix on x86-64 Linux with its `nix-command` and `flakes` experimental
features enabled. From the source directory:

```console
nix develop path:.
```

The explicit `path:.` also works for source files that have not been added to
Git. To enable the experimental features for one invocation without changing
Nix configuration:

```console
nix --extra-experimental-features 'nix-command flakes' develop path:.
```

`flake.lock` pins the tools. A separate virtual environment or pip installation
is not required. The `NixOS/nixpkgs` input is the Nix package repository; using
it does not require NixOS as the workstation operating system. The
`nixos-` branch name identifies the stable package set shared with a NixOS
release; it does not install NixOS.

## Build a collection archive

From the source directory inside the Nix shell, build the archive:

```console
just build
ls dist/sustainablelobster-legacy_windows-*.tar.gz
```

`just build` writes a distributable archive to `dist/`, replacing an existing
archive of the same version. Use the archive path reported by the build;
`dist/` may also contain older versions. Copy that archive to the Ansible
controller and follow the [installation instructions](../README.md#install).
The controller does not need Nix or the source checkout to install it.

## Local checks

Run these commands inside the Nix shell:

```console
just lint check
```

`just lint` runs `pre-commit run --all-files`, which checks tracked files. To
check untracked files without staging them, run
`pre-commit run --files <paths>`. Both commands require a Git checkout.

`just check` builds a collection in a disposable directory, verifies its
identity and archive contents, and installs it locally without resolving
dependencies.

Packaging checks contact no Windows hosts. They do not establish target
compatibility. Add behavior tests with each implementation, and record the
runtime each test exercises. Follow the [compatibility contract](compatibility.md)
for target execution and parity evidence.

## Commit hooks

In a Git checkout, install the hooks explicitly:

```console
just setup
```

Entering the Nix shell does not install hooks. Run commits inside the shell so
the hooks can find the Nix-provided tools. Do not install hooks into a parent
repository when working in a nested source directory.

Pre-commit loads hooks from the upstream repositories pinned in
`.pre-commit-config.yaml`. Its first run needs network access to fetch those
repositories. Executable hooks use the tools provided by Nix rather than
installing separate Python environments. Nix also needs access to its inputs
and package downloads when first preparing the environment.

## Python tooling

`pyproject.toml` holds tool settings; it does not declare a Python package.
Ansible collection identity and dependencies belong in `galaxy.yml`.

| Code                                                             | Formatting and static checks                                                                 |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Windows payloads in `plugins/modules` and `plugins/module_utils` | Black and Pylint target Python 3.4; Vermin checks for newer syntax and library requirements. |
| Controller plugins                                               | Black, Pylint, and Mypy use the controller Python floor in the tooling configuration.        |
| Developer scripts and tests                                      | Tools use the Python interpreter supplied by the locked Nix environment.                     |

The controller floor follows the locked `ansible-core` version's Python
requirement; revisit it when updating that toolchain. `meta/runtime.yml`
declares the minimum `ansible-core` version. These are compatibility
requirements, not evidence of tested controller or Windows support. Record
tested combinations in the
[support record](status.md).

Isort orders imports with Black-compatible formatting. Its Python 3 standard
library classification does not establish target compatibility. Mypy checks
controller and developer code; it does not support analyzing Python 3.4.
Static target checks likewise do not replace execution under Python 3.4.4 on
Windows.

The environment also supplies Pytest for behavior tests, Codespell for spelling,
Ansible-lint for Ansible content, and checks for YAML, Markdown, Nix, and file
hygiene. Rumdl lints and formats Markdown through the commit hooks, including
aligning table columns. Use the checked-in hook and tool configuration for the
exact enabled checks and exclusions.

## Code and tests

- `plugins/modules`: Windows module implementations and their Ansible interface
  documentation.
- `plugins/module_utils`: helpers imported by target modules; their imports must
  also support Python 3.4.4.
- `plugins/action`: action plugins executed by the Ansible controller.
- `tests/unit`: focused tests of observable behavior and failures.
- `tests/integration/targets`: Windows execution tests on authorized hosts.
- `scripts`: tools run by developers, using the Nix environment's Python.

Keep controller and developer dependencies out of code sent to Windows. The
workstation Python version does not determine the supported controller or
Windows Python versions.

Follow the source tree's `AGENTS.md` for demonstrations, review, and contribution
guardrails. Keep support claims and module availability in
[the support record](status.md), with links to the corresponding module
reference and test evidence. Changes to source checks belong in the tooling
configuration and this guide rather than in the user README.
