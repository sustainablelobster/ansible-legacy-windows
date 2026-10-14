"""Stage native Windows fact collectors before normal module execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any, cast

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Gather Windows facts through the existing connection and Python runtime."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_async_native.py",
        "legacy_windows_account.py",
        "legacy_windows_group.py",
        "legacy_windows_calendar.py",
        "legacy_windows_time.py",
        "legacy_windows_uformat.py",
        "legacy_windows_certificate.py",
        "legacy_windows_setup_date.py",
        "legacy_windows_setup_native.py",
        "legacy_windows_setup_network.py",
        "legacy_windows_setup_winrm.py",
        "legacy_windows_setup.py",
    )

    def _compute_environment_string(
        self, raw_environment_out: dict[str, Any] | None = None
    ) -> str:
        # Source PowerShell initializes its process before core applies task
        # overrides. Use core's existing prefix hook after helper staging, with
        # the same shell launcher; no new module argument or transport is needed.
        environment: dict[str, Any] = {}
        super()._compute_environment_string(environment)
        if isinstance(raw_environment_out, dict):
            raw_environment_out.clear()
            raw_environment_out.update(environment)
        shell = self._connection._shell  # pylint: disable=protected-access
        # Native SetEnvironmentVariableW keeps inherited Win32 name casing.
        # Rebuilding dict(os.environ) uppercases every name on Python 3.4.
        overrides = {name: str(value) for name, value in environment.items()}
        script = (
            "import subprocess, sys\n"
            f"sys.path.insert(0, {shell.tmpdir!r})\n"
            "import legacy_windows_setup_native as setup_native\n"
            f"setup_native.initialize_environment({overrides!r})\n"
            "sys.exit(subprocess.call(sys.argv[1:]))\n"
        )
        prefix = shell._python_command(script)  # pylint: disable=protected-access
        return cast(str, prefix)
