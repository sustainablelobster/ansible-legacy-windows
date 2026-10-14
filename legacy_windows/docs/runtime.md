# Shared Windows execution runtime

`sustainablelobster.legacy_windows` 1.1.0 introduces a supported controller
extension for native Python payloads in dependent collections:

```python
from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):
    EXTRA_MODULE_UTILS = ("legacy_windows_account.py",)
    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1] / "module_utils" / "legacy_ad_ldap.py",
    )
```

`EXTRA_MODULE_UTILS` lists Windows-owned helper filenames.
`COLLECTION_MODULE_UTILS` lists explicit source paths owned by the dependent
collection. The runtime stages both alongside the payload. Distinct sources
cannot share a filename on Windows, including case-only differences; those
conflicts fail before file transfer. Repeated identical sources are transferred
once. Declare every helper imported by the payload and its helpers explicitly.

The common JSON helper, privilege-escalation closure and native async wrapper
remain Windows-owned. Do not redirect their source directory to the dependent
collection. Payloads use ordinary adjacent imports such as
`legacy_windows_module` and never import controller dependencies.

All staged payloads and helpers must remain compatible with Python 3.4.4.
The controller class runs under the Python version required by Ansible.
The class preserves Ansible's connection, task-directory ownership, cleanup,
Runas and async lifecycle; it does not implement another transport.

Continue using `sustainablelobster.legacy_windows.cmd`, the existing native
async-status action, and the documented automatic-polling configuration.
Dependent actions enable async only for module workflows that actually support
it. Reboot-capable workflows should invoke the existing Windows reboot action
and preserve its reconnection and readiness checks.

Declare the runtime collection dependency in the dependent collection's
metadata. Source-checkout tests do not establish that a user's installed runtime
version satisfies that dependency.
