"""Stage the download payload and its native and standard-library helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Download through target HTTP libraries and native certificate APIs."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_calendar.py",
        "legacy_windows_file.py",
        "legacy_windows_stat.py",
        "legacy_windows_time.py",
        "legacy_windows_copy.py",
        "legacy_windows_certificate_store.py",
        "legacy_windows_http_certificate.py",
        "legacy_windows_get_url_ftp.py",
        "legacy_windows_get_url_http.py",
        "legacy_windows_get_url.py",
    )
    # pylint: enable=duplicate-code
