# Development

## Environment

Install Nix on x86-64 Linux with the `nix-command` and `flakes` features enabled.
Enter the standalone environment from this checkout:

```console
nix --extra-experimental-features 'nix-command flakes' develop path:.
```

`flake.lock` pins developer tools. The `path:.` form includes files that
have not been added to Git. A separate virtual environment is not needed.
The Nix Python interpreter is for development, not the Windows target runtime.

## Build and check

Inside the Nix shell:

```console
just build
just lint check
pytest
```

`just build` writes the collection archive to `dist/`, replacing an archive
of the same version. Archives contain plugins and user documentation, not
tests, developer tools, or private files.

`just lint` checks tracked and untracked nonignored files through pre-commit.
Some hooks format files. For focused work, use
`pre-commit run --files <paths>`. Neither command stages files.

`just check` builds in a disposable directory, verifies all plugin paths and
bytes, checks licenses and private-file exclusions, and installs offline.
Check an existing archive with:

```console
python scripts/check_collection.py --artifact dist/sustainablelobster-legacy_windows-1.0.0.tar.gz
```

Pytest exercises controller and developer behavior using Nix Python.
Routine checks do not contact Windows or establish target compatibility.
The Ansible-lint hook refreshes the checkout's offline installation under
`.ansible/collections`; do not use that changing installation for live tests.

Install commit hooks explicitly if you want them:

```console
just setup
```

Entering the Nix shell does not install hooks. The first Nix or pre-commit
setup can download pinned dependencies. Do not change global Git or Nix
configuration to make checks pass.

## GitHub CI and releases

The source checkout's `.github/workflows/ci.yml` runs on pull requests, pushes
to `main` and `v1`, tags beginning with `v`, and manual dispatch. All jobs use
Ubuntu 24.04 x86-64 and the development environment pinned by `flake.lock`.
The three quality jobs run in parallel:

- **Lint** runs `just lint` and rejects tracked-file changes from hooks.
- **Unit tests** runs the full `pytest -ra` suite, including its skip summary,
  and records JUnit results.
- **Package** runs `just build`, checks that exact archive, and installs it
  offline. It does not rebuild the archive during verification.

CI does not contact Windows hosts or the lab. These checks establish controller
and packaging behavior, not legacy Windows execution or target compatibility.
Windows integration remains a separate, explicitly invoked workflow below.

The workflow caches Nix dependencies and pre-commit environments using hashes
of the locked toolchain and hook configuration. Only trusted branch pushes save
caches; test outcomes are never cached. Pre-commit caches, test reports and
release bundles use directories under `RUNNER_TEMP`, outside the checkout.
Superseded branch and pull-request runs are canceled, but tag runs and active
publication are not. Explicit test reports and the verified package bundle are
retained for 30 days. Private inventories and whole workspaces are not uploaded.

### Repository setup

After committing and pushing the complete reviewed source, configure branch
rules to require the `Lint`, `Unit tests`, and `Package` checks for `main` and
`v1` where used. Protect `v*` tags against unauthorized creation, updates, and
deletion. Review workflow changes as release-sensitive code.

Actions are pinned to full commit SHAs; update each pin to a verified release
from its original repository and retain its version comment. `actionlint` and
ShellCheck are included in the Nix environment and local hooks. Workflow YAML
is excluded only from Ansible-lint, not from the other applicable checks.

The workflow uses read-only repository permissions by default and does not
persist checkout credentials. Only publication receives `contents: write`.
The built-in `GITHUB_TOKEN` is sufficient; no personal token or lab credential
is required once the release's workflow files are present on the repository's
default branch. [GitHub requires workflow-write permission](https://docs.github.com/en/rest/releases/releases#create-a-release)
to release a commit whose workflow files differ from that branch, which
`GITHUB_TOKEN` cannot receive. Merge workflow changes into the default branch
before tagging a release, including this first CI implementation. Manual
dispatch and pull requests never publish.

### Publish a version

Update `galaxy.yml` and add a nonempty matching `## X.Y.Z` section to
`CHANGELOG.md`. Complete review and local checks, commit the complete intended
source, push it, and verify branch CI before creating the release tag. For
version 1.0.0, the final authorized release operations are:

```console
git tag -a v1.0.0 -m 'Release 1.0.0'
git push origin v1.0.0
```

Pushing a stable `vX.Y.Z` tag in the originating repository automatically
publishes after all three quality jobs pass. Tags must exactly match both
`galaxy.yml` and the archive manifest. Leading-zero versions, prereleases, and
build metadata are rejected. The workflow never rewrites versions or creates
tags itself, and it does not publish to Ansible Galaxy.

`scripts/ci_release.py` prepares the verified archive, checksum, release notes,
and a manifest recording its tested commit. Publication downloads this exact
bundle and checks the archive against the package job's recorded SHA-256. It
also confirms that the remote tag still resolves to the tested commit. A draft
GitHub Release becomes public only after its archive and checksum attachments
are complete. Download the collection archive attachment for installation;
GitHub's automatic source archives are not collection packages.

### Retry publication

If publication fails, rerun only the failed publication job while its verified
package artifact is retained. Matching draft assets can be reused; conflicting
assets are never overwritten. An already published matching release is a no-op.

Collection archives are not byte-reproducible: rebuilding the same source can
change archive timestamps and its SHA-256. A full workflow rerun can therefore
conflict with an existing draft or release. Do not move the tag or replace
published assets to force a retry. Diagnose the failure using the original
artifact; a different published package needs a new reviewed version.

## Windows integration tests

Use only authorized hosts. Prepare a private inventory using the
[connection example](../README.md#connect-and-run-a-task). Choose a playbook
whose prerequisites and mutations fit the target; inspect its variables first.
Integration playbooks target the `legacy_windows` inventory group. Use that
group name instead of `windows` in the README example inventory. Keep the
inventory outside the checkout and replace `/path/to/private/inventory.yml`
below with its location.

Install into a dedicated directory and keep it unchanged until the test and
cleanup finish:

```console
integration_collections="$(mktemp -d)"
ansible-galaxy collection install . --offline --no-deps --force --collections-path "$integration_collections"
ANSIBLE_COLLECTIONS_PATH="$integration_collections" ansible-playbook -i /path/to/private/inventory.yml tests/integration/release_smoke.yml --limit legacy_windows
```

The release smoke exercises connectivity, commands, temporary paths,
Unicode/binary copying, metadata, file reads, idempotence and check mode.
Other playbooks exercise individual modules. Integration fixtures themselves
must remain compatible with the minimum target version, Python 3.4.4. The
release smoke accepts Python 3.4.4 or newer; probes specifically verifying
the compatibility floor still require the actual 3.4.4 runtime.

Coordinate exclusive access when tests mutate or inspect shared guest state.
Hold access through cleanup and connection closure. Servicing tests need a
restorable baseline appropriate to their changes. Do not substitute fake
providers or controller checks for Windows execution.

After tests and target cleanup finish, remove the disposable installation:

```console
rm -rf -- "$integration_collections"
```

Keep inventories, connection settings, logs, captures and snapshots outside the
checkout and collection archives. Preserve failed captures and recovery records.
Historical development records are not product restrictions or release
requirements.

## Code and compatibility

- `plugins/modules` and `plugins/module_utils`: Windows payloads and helpers,
  including their Python 3.4.4-compatible imports.
- `plugins/action`, `plugins/plugin_utils` and `plugins/filter`: controller code.
- `tests/unit`: local behavior tests.
- `tests/integration`: explicitly invoked Windows tests.
- `scripts`: developer tools.

The reference release is `ansible.windows` 3.8.0, tag `3.8.0`, commit
`ff0ac96011ee196742901f34c0dd134acddbe89a`. Preserve familiar interfaces where
practical; use the standard library and native Windows APIs rather than
recreating PowerShell or .NET internals.

`meta/runtime.yml` is Ansible collection metadata. Its `requires_ansible`
field declares the minimum controller `ansible-core` version, not a Windows
version, target Python version, or connection-plugin allowlist.

Static target checks use the Python 3.4 floor. Controller checks use the Python
floor required by the supported Ansible release. Neither replaces execution
with actual Python 3.4.4 on Windows.

Before claiming a workflow works, demonstrate observable results on Windows,
including repeat runs, check mode where applicable, failures and cleanup.
Record the controller, Windows build, architecture, interpreter and connection
with the evidence; these observations do not form an allowlist. Retain valid
evidence when executable behavior and dependencies are unchanged.

Follow the source checkout's `AGENTS.md` for review and contribution rules.
