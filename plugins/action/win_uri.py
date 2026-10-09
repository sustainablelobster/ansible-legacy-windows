"""Stage the URI payload and its native HTTP/certificate helper closure."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's maintained action hierarchy supplies the staging/connection contract.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Send target-native web requests and preserve released response behavior."""

    # Both web actions explicitly stage their shared request/certificate closure;
    # a registry would conceal which target dependencies each payload imports.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_calendar.py",
        "legacy_windows_file.py",
        "legacy_windows_stat.py",
        "legacy_windows_time.py",
        "legacy_windows_copy.py",
        "legacy_windows_certificate_store.py",
        "legacy_windows_get_url_ftp.py",
        "legacy_windows_get_url_http.py",
        "legacy_windows_get_url.py",
        "legacy_windows_uri.py",
    )
    # pylint: enable=duplicate-code
