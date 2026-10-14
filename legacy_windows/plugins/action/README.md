# Action plugins

Controller actions stage the Python helpers needed by each Windows payload.
They use Ansible's normal connection and task lifecycle rather than providing
a separate transport.

Keep controller dependencies out of code sent to Windows. See
[Development](https://github.com/sustainablelobster/ansible-legacy-windows/blob/main/docs/development.md) for runtime boundaries and
[Usage](../../docs/usage.md) for facts, Runas and background jobs.
