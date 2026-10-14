# Legacy Windows and Active Directory collections

Manage legacy Windows and Active Directory with Ansible, Python 3.4.4-compatible
payloads and native Windows APIs. The two collections share an execution runtime
but are packaged and versioned independently:

| Collection                                                    | Version | Purpose                     | Upstream reference      |
| ------------------------------------------------------------- | ------- | --------------------------- | ----------------------- |
| [sustainablelobster.legacy_windows](legacy_windows/README.md) | 1.1.0   | Windows management          | `ansible.windows` 3.8.0 |
| [sustainablelobster.legacy_ad](legacy_ad/README.md)           | 1.0.0   | Active Directory automation | `microsoft.ad` 1.12.1   |

Familiar upstream module names and interfaces are retained where practical.
The AD collection includes all 25 first-party module interfaces, six filters and
LDAP inventory from its recorded reference release. See each collection's usage
guide for prerequisites and meaningful differences:

- [Windows usage](legacy_windows/docs/usage.md)
- [Active Directory usage](legacy_ad/docs/usage.md) and
  [execution coverage](legacy_ad/docs/coverage.md)

## Requirements

- Controller: `ansible-core` 2.21 or newer and its required Python version.
- Windows targets: Python 3.4.4 or newer and the capabilities needed by the task.
- Connection: an Ansible connection plugin that can execute the configured
  Python interpreter and transfer files. The Windows collection supplies a
  Command Prompt shell plugin; neither collection configures a connection service.

## Install and get started

For released versions on Ansible Galaxy, install the collection you need:

```console
ansible-galaxy collection install sustainablelobster.legacy_windows:1.1.0
ansible-galaxy collection install sustainablelobster.legacy_ad:1.0.0
```

Installing AD also installs its compatible Windows runtime dependency
(`>=1.1.0,<2.0.0`). You do not need to install Windows separately when using AD.
For local archives before publication, follow the
[build and check instructions](docs/development.md#build-and-check) and each
collection's installation example.

Start with the [Windows connection example](legacy_windows/README.md#connect-and-run-a-task)
or the [AD task example](legacy_ad/README.md#run-a-task). Use fully qualified
collection names in playbooks.

## License

Original contributions use [GNU GPL version 3 or later](LICENSE). Each
collection includes its license and applicable upstream and third-party notices.

Microsoft, Windows and Active Directory are trademarks of the Microsoft group
of companies. This project is not affiliated with or endorsed by Microsoft.
