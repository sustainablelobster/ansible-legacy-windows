# sustainablelobster.legacy_community_windows

Community Windows automation with Python 3.4.4-compatible Windows payloads,
using the execution runtime from `sustainablelobster.legacy_windows`.

Version 1.0.0 implements the 55 module interfaces, LAPS lookup, redirects and
removed-module notices from `community.windows` 3.3.0, commit
`20464e72482c5d4c75af13a2fd62966339cf5ffc`.
See [Coverage](docs/coverage.md) for tested workflows and [Usage](docs/usage.md)
for prerequisites and meaningful differences. Interface coverage does not mean
every option has been tested on every Windows version.

## Requirements

- Controller: `ansible-core` 2.21 or newer and its required Python version.
- Windows payloads: Python 3.4.4 or newer and the capabilities needed by the task.
- Execution runtime: `sustainablelobster.legacy_windows` 1.2.0 or newer, below 2.0.
- Optional controller integrations have separate dependencies; see [Usage](docs/usage.md).

## Build and install locally

Use the repository's
[development guide](https://github.com/sustainablelobster/ansible-legacy-windows/blob/main/docs/development.md)
to build collection archives. Install both this collection and its compatible
Windows runtime archive without contacting Galaxy:

```console
ansible-galaxy collection install ./sustainablelobster-legacy_windows-1.2.0.tar.gz ./sustainablelobster-legacy_community_windows-1.0.0.tar.gz --offline
```

Use the existing
[Windows connection example](https://github.com/sustainablelobster/ansible-legacy-windows/blob/main/legacy_windows/README.md#connect-and-run-a-task).
This collection does not configure a connection service.

## Module help

```console
ansible-doc --list sustainablelobster.legacy_community_windows
ansible-doc sustainablelobster.legacy_community_windows.win_lineinfile
ansible-doc -t lookup sustainablelobster.legacy_community_windows.laps_password
```

## License

The collection is licensed under [GNU GPL version 3 or later](LICENSE).
Released upstream material retains its attribution and
[license](LICENSES/community-windows-GPL-3.0-or-later.txt); see [NOTICE](NOTICE).

Microsoft, Windows and Active Directory are trademarks of the Microsoft group
of companies. This project is not affiliated with or endorsed by Microsoft.
