# Availability and tested combinations

No modules or action plugins are implemented, and no controller-to-Windows
execution path is provided. No Windows version, connection method, or
controller and target combination has been verified. There are no Windows
runtime tests.

The exact upstream `ansible.windows` release used to measure parity has not
been selected. The intended target runtime is Python 3.4.4; that requirement
is not a support claim.

Use the collection for source development and packaging checks only until a
verified combination and working module are documented here. Installing an
archive does not enable Windows tasks.

Record the following here as implementation and testing establish them:

- The exact upstream release used as the parity baseline.
- Available modules and plugins, with links to their documentation and any
  differences from the baseline.
- Tested Windows versions and architectures, Python interpreter paths,
  connection methods, Ansible releases, and controller Python versions.
- Known limitations and untested scenarios.
