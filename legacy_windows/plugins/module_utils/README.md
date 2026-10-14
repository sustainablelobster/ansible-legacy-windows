# Module utilities

Helpers imported by Windows payloads, including their dependencies, must remain
compatible with Python 3.4.4 and newer. Use the standard library and native
Windows APIs; keep controller-only dependencies out of target imports.

Add shared helpers only for a concrete module need. See
[Development](https://github.com/sustainablelobster/ansible-legacy-windows/blob/main/docs/development.md)
for testing and runtime boundaries.
