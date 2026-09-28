# sustainablelobster.legacy_windows

An Ansible collection for managing legacy Windows machines with Python 3.4.4.

Check [module availability and tested combinations](docs/status.md) before
installation or use.

## Requirements

| System             | Requirement                                                                                                                        |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| Ansible controller | An `ansible-core` version meeting the [collection's minimum requirement](meta/runtime.yml), with Python supported by that release. |
| Windows target     | Python **3.4.4**, with a Windows version and connection method verified in the [tested combinations](docs/status.md).              |

Install the collection on the Ansible controller. A collection installation
does not provision Python on Windows or configure a connection to a target.
Check the tested combinations for the complete controller and target setup.

## Install

Install from Ansible Galaxy on your Ansible controller:

```console
ansible-galaxy collection install sustainablelobster.legacy_windows
```

Alternatively, download the
`sustainablelobster-legacy_windows-<version>.tar.gz` release asset from
[GitHub Releases](https://github.com/sustainablelobster/ansible-legacy-windows/releases)
to your controller. Replace `<version>` with the archive's version and adjust
the path to its location:

```console
ansible-galaxy collection install './sustainablelobster-legacy_windows-<version>.tar.gz'
```

After either installation method, verify the installed version and location:

```console
ansible-galaxy collection list sustainablelobster.legacy_windows
```

## Find module documentation

List the modules available in your installed version:

```console
ansible-doc --list sustainablelobster.legacy_windows
```

Use fully qualified names in playbooks:
`sustainablelobster.legacy_windows.<module_name>`. Replace `<module_name>` with
a name from the module list. To read its arguments, examples, and return values:

```console
ansible-doc 'sustainablelobster.legacy_windows.<module_name>'
```

Use the collection's documentation and tested combinations when adapting an
`ansible.windows` playbook. Matching a module name alone does not establish
that a Windows version or connection method supports the same behavior.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Trademarks

Microsoft and Windows are trademarks of the Microsoft group of companies.
This project is not affiliated with or endorsed by Microsoft.

[Developer documentation](docs/development.md)
