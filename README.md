# Legacy Windows Ansible collections

Ansible collections for legacy Windows management, Active Directory and
community Windows integrations, using Python 3.4.4-compatible payloads and native
Windows APIs. This checkout contains three independently versioned collections:

| Collection                                                                        | Checkout version | Purpose                      | Upstream reference        |
| --------------------------------------------------------------------------------- | ---------------- | ---------------------------- | ------------------------- |
| [sustainablelobster.legacy_windows](legacy_windows/README.md)                     | 1.2.0            | Windows management           | `ansible.windows` 3.8.0   |
| [sustainablelobster.legacy_ad](legacy_ad/README.md)                               | 1.0.0            | Active Directory automation  | `microsoft.ad` 1.12.1     |
| [sustainablelobster.legacy_community_windows](legacy_community_windows/README.md) | 1.0.0            | Community Windows automation | `community.windows` 3.3.0 |

`legacy_windows` supplies the shared Windows execution runtime; `legacy_ad` and
`legacy_community_windows` depend on it. Familiar upstream module names and
interfaces are retained where practical. Each collection's README provides its
scope and installation examples. Use the guides below for prerequisites,
meaningful differences and verified workflows:

- [Windows usage](legacy_windows/docs/usage.md)
- [Active Directory usage](legacy_ad/docs/usage.md) and
  [execution coverage](legacy_ad/docs/coverage.md)
- [Community Windows usage](legacy_community_windows/docs/usage.md) and
  [execution coverage](legacy_community_windows/docs/coverage.md)

Controller-side inventory, lookup and execution integrations have their own
optional dependencies, documented in those guides. Interface coverage does not
mean every option has been tested on every Windows environment.

## Requirements

- Controller: `ansible-core` 2.21 or newer and its required Python version.
- Windows payloads: Python 3.4.4 or newer and the capabilities needed by the task.
- Connection: an Ansible connection plugin that can execute the configured
  Python interpreter and transfer files. The Windows collection supplies a
  Command Prompt shell plugin; the collections do not configure a connection service.

## Install and get started

For published releases on Ansible Galaxy, install whichever collections you need:

```console
ansible-galaxy collection install sustainablelobster.legacy_windows
ansible-galaxy collection install sustainablelobster.legacy_ad
ansible-galaxy collection install sustainablelobster.legacy_community_windows
```

Installing AD or Community Windows also installs a compatible Windows runtime;
you do not need to install it separately. Galaxy installs published versions,
which may differ from the checkout versions listed above.

To use this checkout before publication, enter the
[Nix development environment](docs/development.md#environment), then build and
install the local archives from the repository root:

```console
just build
ansible-galaxy collection install ./dist/sustainablelobster-legacy_windows-1.2.0.tar.gz ./dist/sustainablelobster-legacy_ad-1.0.0.tar.gz ./dist/sustainablelobster-legacy_community_windows-1.0.0.tar.gz --offline
```

See [Build and check](docs/development.md#build-and-check) for verification and
the collection READMEs for installing only the archives you need.

Start with the [Windows connection example](legacy_windows/README.md#connect-and-run-a-task),
the [AD task example](legacy_ad/README.md#run-a-task), or
[Community Windows module help](legacy_community_windows/README.md#module-help).
Use fully qualified collection names in playbooks.

For development, local checks, Windows integration tests and coordinated tag
releases, see the [development guide](docs/development.md).

## License

Original contributions use [GNU GPL version 3 or later](LICENSE). Each
collection includes its license and applicable upstream and third-party notices.

Microsoft, Windows and Active Directory are trademarks of the Microsoft group
of companies. This project is not affiliated with or endorsed by Microsoft.
