# Windows integration targets

Place Windows integration targets for implemented modules here.

Each target should verify the selected upstream behavior, including repeated
runs, check mode where supported, returned values, and documented failures.
Record the Windows version, architecture, Python 3.4.4 interpreter, connection
method, and controller versions used.

Run only against explicitly authorized hosts. Keep credentials and private
inventories outside the collection artifact and version control. Clean up
resources created by the tests and report skipped scenarios. Routine local
checks must not contact these hosts.
