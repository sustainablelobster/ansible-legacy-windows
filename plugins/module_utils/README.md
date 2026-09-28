# Module utilities

Place helpers shared by modules here when a concrete module needs them.

Every helper imported on Windows, including its dependencies, must run under
Python 3.4.4. Keep controller-only dependencies out of target imports. See the
[compatibility contract](../../docs/compatibility.md).
