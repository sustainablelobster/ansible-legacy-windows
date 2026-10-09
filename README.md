# sustainablelobster.legacy_windows

Manage Windows with Ansible and Python, including systems too old to run
modern PowerShell. The collection provides familiar `ansible.windows` module
names with Python 3.4.4-compatible payloads and native Windows APIs.

## Requirements

- Ansible controller: `ansible-core` 2.21 or newer, with the Python version
  required by that release.
- Windows target: Python 3.4.4 or newer and the Windows features needed by
  your tasks.
- Connection: an Ansible connection plugin that can execute the configured
  Python interpreter and transfer files. The collection supplies a Command
  Prompt shell plugin; it does not configure a connection service.

## Install

Install the collection archive on your Ansible controller:

```console
ansible-galaxy collection install ./sustainablelobster-legacy_windows-1.0.0.tar.gz --offline --no-deps
```

To build an archive from this checkout, see [Development](docs/development.md).

## Connect and run a task

This SSH example assumes an existing server that executes commands through
`cmd.exe` and supports SFTP. Replace the address and account with your own.
Install Python on Windows before connecting.

```yaml
# inventory.yml
all:
  children:
    windows:
      hosts:
        workstation:
          ansible_host: 192.0.2.10
      vars:
        ansible_user: your_windows_account
        ansible_connection: ssh
        ansible_shell_type: sustainablelobster.legacy_windows.cmd
        ansible_python_interpreter: 'C:\Python34\python.exe'
        ansible_ssh_transfer_method: sftp
```

Keep credentials in your private inventory or Ansible Vault. Use your normal
SSH authentication and host-key verification.

```console
ansible -i inventory.yml windows -m sustainablelobster.legacy_windows.win_ping
```

Use fully qualified module names in playbooks:

```yaml
- name: Manage Windows
  hosts: windows
  gather_facts: false
  tasks:
    - name: Create an application directory
      sustainablelobster.legacy_windows.win_file:
        path: C:\Application
        state: directory
```

Run it with `ansible-playbook -i inventory.yml playbook.yml`.

[Usage](docs/usage.md) covers facts, privilege escalation, background jobs,
and known issues.

## Module reference

```console
ansible-doc --list sustainablelobster.legacy_windows
ansible-doc sustainablelobster.legacy_windows.win_file
ansible-doc -t filter sustainablelobster.legacy_windows.quote
```

The interfaces follow `ansible.windows` where practical. They do not reproduce
every PowerShell or .NET behavior; see each module's arguments and prerequisites.

## License

The collection and original contributions are licensed under
[GNU GPL version 3 or later](LICENSE), matching the `ansible.windows` baseline.
The [upstream license](LICENSES/ansible-windows-GPL-3.0-or-later.txt) is included.
Upstream attribution, incorporated MIT-licensed code, and Unicode data retain
their notices and licenses in [NOTICE](NOTICE) and [LICENSES](LICENSES).

Microsoft and Windows are trademarks of the Microsoft group of companies.
This project is not affiliated with or endorsed by Microsoft.
