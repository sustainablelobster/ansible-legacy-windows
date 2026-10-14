# sustainablelobster.legacy_ad

Native Active Directory automation with Python 3.4.4-compatible Windows
payloads, using the execution runtime from `sustainablelobster.legacy_windows`.

Version 1.0.0 implements all 25 first-party module interfaces, six filters and
LDAP inventory in the recorded upstream release. See [Coverage](docs/coverage.md)
for verified workflows and independent black-box results, and [Usage](docs/usage.md)
for capability requirements and meaningful differences. Execution observations
are not a Windows-version allowlist or a claim that every option was tested.

## Requirements

- Controller: `ansible-core` 2.21 or newer and its required Python version.
- Windows payloads: Python 3.4.4 or newer and the directory capabilities needed
  by the task.
- Execution runtime: `sustainablelobster.legacy_windows` 1.1.0 or newer, below 2.0.
- LDAP inventory: controller-only `sansldap` and `pyspnego`; see
  [Usage](docs/usage.md) for optional discovery and authentication dependencies.

Use the existing Windows collection's connection configuration and Command
Prompt shell. The AD collection does not configure a connection service.

## Install

Install a released version from Ansible Galaxy:

```console
ansible-galaxy collection install sustainablelobster.legacy_ad:1.0.0
```

Galaxy also installs the compatible Windows runtime dependency. To install
locally built or downloaded archives without contacting Galaxy, supply both:

```console
ansible-galaxy collection install ./sustainablelobster-legacy_windows-1.1.0.tar.gz ./sustainablelobster-legacy_ad-1.0.0.tar.gz --offline
```

The repository's
[development guide](https://github.com/sustainablelobster/ansible-legacy-windows/blob/main/docs/development.md)
describes building the archives from source.

## Run a task

Configure a private inventory using the
[Windows connection example](https://github.com/sustainablelobster/ansible-legacy-windows/blob/main/legacy_windows/README.md#connect-and-run-a-task).
The account needs directory permissions for the requested operation. Run
directory tasks on a Windows host that can reach the directory:

```yaml
- name: Manage Active Directory
  hosts: windows
  gather_facts: false
  tasks:
    - name: Ensure an organizational unit exists
      sustainablelobster.legacy_ad.ou:
        name: Applications
        path: DC=example,DC=com
        domain_server: dc.example.com
        domain_username: '{{ vault_ad_username }}'
        domain_password: '{{ vault_ad_password }}'
        state: present
```

Replace the example server and directory path with your own, and define
`vault_ad_username` and `vault_ad_password` in Ansible Vault. Run it with
`ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass`, or use your
existing Vault configuration. Module help describes directory credentials and
cross-forest lookup; [Usage](docs/usage.md) covers capability requirements and
optional inventory dependencies.

## Module reference

```console
ansible-doc --list sustainablelobster.legacy_ad
ansible-doc sustainablelobster.legacy_ad.ou
ansible-doc -t inventory sustainablelobster.legacy_ad.ldap
```

## Reference and release scope

The reference is `microsoft.ad` 1.12.1, commit
`0449b870af3054ea8b02c5d5b70764138ce34bb7`. Familiar interfaces are retained
where legacy directory capabilities permit. See [Coverage](docs/coverage.md)
for implementation and execution status and [Usage](docs/usage.md) for
meaningful differences and prerequisites.

## License

The collection is licensed under [GNU GPL version 3 or later](LICENSE).
Released upstream material retains its attribution and
[license](LICENSES/microsoft-ad-GPL-3.0-or-later.txt); see [NOTICE](NOTICE).

Microsoft, Windows and Active Directory are trademarks of the Microsoft group
of companies. This project is not affiliated with or endorsed by Microsoft.
