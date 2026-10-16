# Windows integration tests

Maintained playbooks live in the [parent integration directory](..), with
supporting `tasks/`, `vars/` and `fixtures/` directories. Add new cases there;
see the [development guide](../../../docs/development.md#windows-integration-tests)
for installation, inventory and execution instructions.

Each target should verify the selected upstream behavior, including repeated
runs, check mode where supported, returned values, and documented failures.
Record the Windows version, architecture, actual Python interpreter version,
connection method, and controller versions used. Python 3.4.4 is the minimum
target version; compatibility-floor evidence specifically requires that runtime.

Run only against explicitly authorized hosts. Keep credentials and private
inventories outside the collection artifact and version control. Clean up
resources created by the tests and report skipped scenarios. Routine local
checks must not contact these hosts.
