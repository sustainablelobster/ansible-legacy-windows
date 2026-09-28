# Action plugins

Place controller-side action plugins here when an implemented feature needs
one. Support the controller Python versions declared by the collection.

Any payload or helper sent to Windows must satisfy the Python 3.4.4 requirement.
Keep controller dependencies out of target imports, and base execution changes
on verified Ansible and Windows behavior. See the
[compatibility contract](../../docs/compatibility.md).
