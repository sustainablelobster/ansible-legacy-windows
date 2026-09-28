# Compatibility contract

The collection aims for parity with all first-party `ansible.windows`
functionality, using Python 3.4.4 for code executed on legacy Windows targets.
[Availability and tested combinations](status.md) records the selected upstream
baseline, implemented interfaces, and verified environments.

## What parity means

For each module, preserve the selected upstream release's module name,
arguments and defaults, return values, idempotence, check-mode behavior, and
documented failures. Use the collection name `sustainablelobster.legacy_windows`
in place of `ansible.windows`.

Measure parity against an exact upstream collection release. Use the matching
[collection reference](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/index.html)
and [upstream source](https://github.com/ansible-collections/ansible.windows)
to establish those contracts; a moving `latest` page is not a fixed
specification.

When a legacy Windows version lacks a required feature, document the affected
module, Windows version, and behavior explicitly. Do not silently omit an
argument, approximate a result, or claim parity for unverified behavior.

## Python and execution

The Python 3.4.4 constraint covers each Windows payload and every helper it
imports, including third-party code. Syntax compatibility alone is insufficient:
standard-library APIs, binary dependencies, and Windows APIs must also work on
the selected target.

Controller-side plugins must support the controller Python versions declared
by the collection. Development tools run on the Python supplied by Nix. Neither
environment's interpreter establishes compatibility with Python 3.4.4 on
Windows. Keep target imports separate from controller and development code.

Ansible's [Windows module development guide](https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_modules_general_windows.html)
describes PowerShell modules in `.ps1` files with documentation in `.py` files.
A Python implementation needs a verified execution approach; adding Python
files to a collection does not establish one.

Demonstrate the execution path with an actual task reaching an authorized
Windows host, executing Python 3.4.4, and returning an Ansible result. Record the
connection method, controller versions, Windows version, architecture, and
interpreter path with the tested combinations.

## Evidence required

- Packaging checks establish that the collection builds and installs locally.
- Unit tests establish only the behavior and runtime exercised by those tests.
- A support claim requires execution with Python 3.4.4 on the claimed Windows
  version, including the payload's imported helpers.
- Module parity requires observable tests of normal behavior, repeated runs,
  check mode where supported upstream, return values, and documented failures.

Record skipped scenarios and limitations alongside the results.
