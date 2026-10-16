# Development

This checkout contains three independently versioned Galaxy collections:
`legacy_windows/`, `legacy_ad/` and `legacy_community_windows/`. Development
tools and tests live at the repository root. Run the commands below there.

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

`just build` writes all collection archives to `dist/`, replacing archives
of the same version. Pass a collection directory name, such as
`just build legacy_community_windows`, to select one.
Archives contain plugins and user documentation, not
tests, developer tools, or private files.

`just lint` checks tracked and untracked nonignored files through pre-commit.
Some hooks format files. For focused work, use
`pre-commit run --files <paths>`. Neither command stages files.

`just check` builds all three in a disposable directory, verifies all plugin paths
and bytes, checks licenses and private-file exclusions, and installs offline
with dependency resolution enabled. Selecting either consumer includes only
that consumer and its Windows runtime; `just check legacy_windows` checks
Windows alone. Community verification also requires every module and lookup
interface and the adapted routing from its recorded released baseline. An
incomplete implementation fails verification even when its current slice builds.
Check an existing Windows archive with:

```console
python scripts/check_collection.py --collection legacy_windows --artifact dist/sustainablelobster-legacy_windows-1.2.0.tar.gz
```

To check an existing consumer archive, supply it and the compatible
Windows runtime archive using repeated `--artifact` arguments. The checker
installs those exact archives together; it does not rebuild them or bypass
dependency resolution.

Pytest exercises controller and developer behavior using Nix Python.
Routine checks do not contact Windows or establish target compatibility.
Pytest exposes the current checkout through a disposable collection namespace
before initializing Ansible's shared loader. It does not require an installed
copy of the collection or a prior lint run.
Pre-commit refreshes all collections under `.ansible/collections` before
running lint and type-check tools. These tools resolve collection imports
through that offline installation; do not use it for live tests.

Install commit hooks explicitly if you want them:

```console
just setup
```

Entering the Nix shell does not install hooks. The first Nix or pre-commit
setup can download pinned dependencies. Do not change global Git or Nix
configuration to make checks pass.

## GitHub CI and releases

The source checkout's `.github/workflows/ci.yml` runs on pull requests, pushes
to `main` and `v1`, tags matching `legacy_windows/v*`, `legacy_ad/v*` or
`legacy_community_windows/v*`, and manual dispatch.
All jobs use Ubuntu 24.04 x86-64 and the development environment pinned by
`flake.lock`.
The three quality jobs run in parallel:

- **Lint** runs `just lint` and rejects tracked-file changes from hooks.
- **Unit tests** runs the full `pytest -ra` suite, including its skip summary,
  and records JUnit results.
- **Package** runs `just build`, checks all exact archives and their offline
  dependency resolution, then retains one verified release bundle per
  collection. It does not rebuild archives during verification.

CI does not contact Windows hosts or the lab. These checks establish controller
and packaging behavior, not legacy Windows execution or target compatibility.
Windows integration remains a separate, explicitly invoked workflow below.

The workflow caches Nix dependencies and pre-commit environments using hashes
of the locked toolchain and hook configuration. Only trusted branch pushes save
caches; test outcomes are never cached. Pre-commit caches, test reports and
release bundles use directories under `RUNNER_TEMP`, outside the checkout.
Superseded branch and pull-request runs are canceled, but tag runs and active
publication are not. Test reports and the three verified package bundles are
retained for 30 days. Private inventories and whole workspaces are not uploaded.

### Repository setup

After committing and pushing the complete reviewed source, configure branch
rules to require the `Lint`, `Unit tests`, and `Package` checks for `main` and
`v1` where used. Protect `legacy_windows/v*`, `legacy_ad/v*` and
`legacy_community_windows/v*` tags against unauthorized creation, updates and
deletion. Review workflow changes as release-sensitive code.

Actions are pinned to full commit SHAs; update each pin to a verified release
from its original repository and retain its version comment. `actionlint` and
ShellCheck are included in the Nix environment and local hooks. Workflow YAML
is excluded only from Ansible-lint, not from the other applicable checks.

The workflow uses read-only repository permissions by default and does not
persist checkout credentials. Only publication receives `contents: write`.
The built-in `GITHUB_TOKEN` is sufficient for GitHub Releases; no GitHub personal
token or lab credential is required once the release's workflow files are
present on the repository's default branch.
[GitHub requires workflow-write permission](https://docs.github.com/en/rest/releases/releases#create-a-release)
to release a commit whose workflow files differ from that branch, which
`GITHUB_TOKEN` cannot receive. Merge workflow changes into the default branch
before tagging a release. Manual dispatch and pull requests never publish.

For Galaxy, obtain an API token from an account authorized to publish in the
`sustainablelobster` namespace and store it as the repository Actions secret
`GALAXY_API_KEY`. See [Ansible's namespace and token setup](https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_collections_distributing.html#initial-configuration-of-your-distribution-server-or-servers).
Only the tag-publication step receives this secret, through its environment;
it is not placed in command arguments or package files. A missing or blank
secret fails before either GitHub or Galaxy publication begins.

### Publish a version

Update the selected collection's `galaxy.yml` and add a nonempty matching
`## X.Y.Z` section to its `CHANGELOG.md`. Complete review, local checks and
required Windows execution evidence before committing and publishing the
intended source. Verify branch CI before creating a release tag.

The collections have independent versions and tag names:

| Collection                                    | Metadata                              | Release tag                       |
| --------------------------------------------- | ------------------------------------- | --------------------------------- |
| `sustainablelobster.legacy_windows`           | `legacy_windows/galaxy.yml`           | `legacy_windows/vX.Y.Z`           |
| `sustainablelobster.legacy_ad`                | `legacy_ad/galaxy.yml`                | `legacy_ad/vX.Y.Z`                |
| `sustainablelobster.legacy_community_windows` | `legacy_community_windows/galaxy.yml` | `legacy_community_windows/vX.Y.Z` |

For example, a reviewed Windows 1.2.0 release uses:

```console
git tag -a legacy_windows/v1.2.0 -m 'Release legacy_windows 1.2.0'
git push origin legacy_windows/v1.2.0
```

For AD 1.0.0, after that version is ready and its Windows runtime dependency
has been published to Galaxy:

```console
git tag -a legacy_ad/v1.0.0 -m 'Release legacy_ad 1.0.0'
git push origin legacy_ad/v1.0.0
```

Pushing a single stable tag in the originating repository publishes that
collection to GitHub Releases and Galaxy after all three quality jobs pass.
For coordinated releases, use the procedure below. Each tag must exactly match
its collection's metadata and archive manifest.
Leading-zero versions, prereleases and build metadata are rejected. The
workflow never rewrites versions or creates tags itself.
Bare `vX.Y.Z` tags no longer trigger releases. Existing historical tags and
releases are not renamed or removed.

`scripts/ci_release.py` prepares the verified archive, checksum, release notes,
and a manifest recording its collection identity and tested commit. Candidate
preparation uses `package --collection <collection-directory>`, with `--artifact`,
an empty `--output-dir` and an optional matching `--tag`.

Publication downloads all bundles using their exact artifact IDs, preserving
their separate directories and package-job SHA-256 values. The `publish-tagged`
command selects the eligible releases and confirms that each selected
remote tag still resolves to the tested commit. It never rebuilds an archive.
Before consumer publication, `preflight` checks its declared Windows dependency
against stable versions already published to Galaxy; an uploaded CI candidate
does not satisfy this prerequisite. Discovery, authentication and lookup
failures stop publication. Both publishing commands repeat their own required
guards when invoked independently.
The `preflight`, `publish` and `publish-galaxy` commands take `--package-dir`
and the verified package job's `--sha256`; they never rebuild the collection.

A draft GitHub Release becomes public only after its archive and checksum
attachments are complete. Download the collection archive attachment for
installation; GitHub's automatic source archives are not collection packages.

Galaxy receives the same verified archive after GitHub publication. The script
uses the Galaxy client supplied by the locked Ansible dependency, applies a
ten-minute import timeout, and verifies the published version's SHA-256 against
the package job. Upload acceptance alone does not count as successful publication.

### Publish collections together

Create the intended version tags on the same reviewed commit, then use an
[atomic push](https://git-scm.com/docs/git-push#Documentation/git-push.txt---atomic).
The following commands create the annotated tags at the current commit:

```console
git tag -a legacy_windows/v1.2.0 -m 'Release legacy_windows 1.2.0'
git tag -a legacy_ad/v1.0.0 -m 'Release legacy_ad 1.0.0'
git tag -a legacy_community_windows/v1.0.0 -m 'Release legacy_community_windows 1.0.0'
git push --atomic origin legacy_windows/v1.2.0 legacy_ad/v1.0.0 legacy_community_windows/v1.0.0
```

GitHub's [tag-push triggers](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push)
can create separate CI runs. Publication is serialized by tested commit, and
the [concurrency queue](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
retains pending publication jobs so a third tag cannot discard the coordinator.
The community-tagged run coordinates when present, otherwise the AD-tagged run,
otherwise Windows alone. Lower-priority tagged runs defer instead of publishing
independently rebuilt archives. The coordinator validates all selected bundles,
same-commit tags and dependency compatibility, then:

1. Publishes the checked Windows archive to GitHub and Galaxy.
2. Waits for successful Galaxy import and verifies the published archive hash.
3. Runs each tagged consumer's dependency preflight, then publishes its checked
   archive to GitHub and Galaxy, AD before community.

Any subset of the three tags is supported. Untagged collections are not
published; consumers without a same-commit Windows tag require a compatible
runtime already on Galaxy. A failure stops later publication. Selected tags
must match source versions at the same commit; different-commit tags remain
independent releases. No workflow creates or moves tags. Manual dispatch and
pull requests never publish.

If the exact Windows version has already reached Galaxy from a standalone
release, a consumer run uses that published dependency rather than republishing
its newly built Windows archive. Already-published companion consumers are
likewise not republished. If an earlier standalone release stopped partway,
retry its original publication job and artifacts before retrying the coordinator.
Matching partial publication from the coordinator's own retained bundle can be
resumed without replacing assets.

### Retry publication

If publication fails, rerun only the failed publication job while its verified
package artifact is retained. Matching draft assets can be reused; conflicting
assets are never overwritten. An already published matching GitHub release or
Galaxy version is a no-op; different archive bytes for the same version fail
without replacement. Galaxy authentication, network and import failures fail
the job rather than being treated as an absent version.

The two destinations are not transactional: if Galaxy fails after GitHub
publication, the GitHub Release stays published. Correct the token or server
failure and rerun the failed publication job; it reuses the matching GitHub
release before retrying Galaxy. If an import times out, check its Galaxy task
status before retrying. A completed matching version is accepted on retry.

Collection archives are not byte-reproducible: rebuilding the same source can
change archive timestamps and its SHA-256. A full workflow rerun can therefore
conflict with an existing draft, release or Galaxy version. Do not move the tag
or replace published assets to force a retry. Diagnose the failure using the
original artifact; a different published package needs a new reviewed version.

## Windows integration tests

Use only authorized hosts. Prepare a private inventory using the
[connection example](../legacy_windows/README.md#connect-and-run-a-task).
Choose a playbook whose prerequisites and mutations fit the target; inspect its
variables first.
The Windows release smoke targets `legacy_windows`; AD directory playbooks
target `legacy_ad`, and membership tests target `legacy_ad_members`. Check the
chosen playbook's `hosts` and variables when preparing inventory. Keep it out
of version control and collection artifacts, and replace
`/path/to/private/inventory.yml` below with its private location.

AD promotion, membership and servicing tests require disposable fixtures and
appropriate recovery plans. Use an isolated test network for directory
services. Guest access does not by itself authorize changes to host networking
or unrelated systems. Routine local checks and hosted CI never invoke these
tests automatically.

The offline-join fixture also requires `nltest` on the designated member's
`PATH`. It uses `nltest /sc_query` to observe the resulting secure-channel
status independently of the module. This is a test prerequisite, not a
collection runtime dependency; the module uses native Windows APIs.

Configurable controller evidence directories default to temporary storage
(`TMPDIR`, or `/tmp` when it is unset). To retain captures in a chosen directory,
set the playbook's `evidence_dir` or module-specific evidence/output variable;
inspect its variables first. These paths are independent of the checkout and do
not change the permissions of the system temporary directory.

Tests that consume external DSC, hotfix or package fixtures need a directory
supplied with `-e integration_artifact_dir=/path/to/fixtures` or the
`LEGACY_WINDOWS_TEST_ARTIFACTS` environment variable. Individual fixture-path
variables can override this directory. Required binaries are not bundled with
the repository, and the tests do not download them automatically.

Install into a dedicated directory and keep it unchanged until the test and
cleanup finish:

```console
integration_collections="$(mktemp -d)"
ansible-galaxy collection install ./legacy_windows ./legacy_ad ./legacy_community_windows --offline --force --collections-path "$integration_collections"
ANSIBLE_COLLECTIONS_PATH="$integration_collections" ansible-playbook -i /path/to/private/inventory.yml tests/integration/release_smoke.yml --limit legacy_windows
```

The release smoke exercises connectivity, commands, temporary paths,
Unicode/binary copying, metadata, file reads, idempotence and check mode.
Other playbooks exercise individual modules; for an existing AD directory,
`tests/integration/legacy_ad_object_info.yml` performs read-only directory
queries and minimum-runtime checks. Supply its directory connection variables
in the private inventory. Integration fixtures themselves must remain
compatible with the minimum target version, Python 3.4.4. The release smoke
accepts Python 3.4.4 or newer; probes specifically verifying
the compatibility floor still require the actual 3.4.4 runtime.

Coordinate exclusive access when tests mutate or inspect shared guest state.
Hold access through cleanup and connection closure. Servicing tests need a
restorable baseline appropriate to their changes. Do not substitute fake
providers or controller checks for Windows execution.

After tests and target cleanup finish, remove the disposable installation:

```console
rm -rf -- "$integration_collections"
```

Keep inventories, connection settings, logs, captures and snapshots in private
storage or the session's designated ignored workspace, never in version
control or collection archives. Preserve failed captures and recovery records.
Historical development records are not product restrictions or release
requirements.

## Code and compatibility

- Each collection's `plugins/modules`: module interfaces and Windows payloads
  where applicable. AD's `debug_ldap_client` and community's `psexec` run on the
  controller, as do lookup plugins. `psexec.py` is explicitly included in
  controller lint/type checks, not target Python compatibility checks.
- Each collection's `plugins/module_utils`: Windows helpers and their
  Python 3.4.4-compatible imports.
- Each collection's `plugins/action`, `plugins/plugin_utils`, `plugins/filter`,
  `plugins/inventory` and `plugins/lookup`, where present: controller code.
- `tests/unit`: local behavior tests.
- `tests/integration`: explicitly invoked Windows tests.
- `scripts`: developer tools.

The recorded reference releases are:

- `ansible.windows` 3.8.0, tag `3.8.0`, commit
  `ff0ac96011ee196742901f34c0dd134acddbe89a`.
- `microsoft.ad` 1.12.1, tag `1.12.1`, commit
  `0449b870af3054ea8b02c5d5b70764138ce34bb7`.
- `community.windows` 3.3.0, tag `3.3.0`, commit
  `20464e72482c5d4c75af13a2fd62966339cf5ffc`.

Preserve familiar interfaces where practical; use the standard library and
native Windows APIs rather than recreating PowerShell or .NET internals.
Windows owns the shared
[execution runtime](../legacy_windows/docs/runtime.md). Each consumer imports
that controller contract and stages its own native helpers alongside Windows
helpers. Optional controller LDAP/SMB dependencies must not become Windows
payload imports; keep controller helpers under `plugin_utils`, not
`module_utils`. Installing a collection does not install optional Python libraries.

Each collection's `meta/runtime.yml` is Ansible metadata. Its `requires_ansible`
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
