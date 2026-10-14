"""Stage native package management and its Python 3.4-compatible helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute local or HTTP-served packages."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_text.py",
        "legacy_windows_process.py",
        "legacy_windows_account.py",
        "legacy_windows_group.py",
        "legacy_windows_owner.py",
        "legacy_windows_link.py",
        "legacy_windows_acl_inheritance.py",
        "legacy_windows_acl.py",
        "legacy_windows_package_msi.py",
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
        "legacy_windows_package_url.py",
        "legacy_windows_regex.py",
        "legacy_windows_find_match.py",
        "legacy_windows_service_config.py",
        "legacy_windows_service_info.py",
        "legacy_windows_package_signature.py",
        "legacy_windows_package_children.py",
        "legacy_windows_package_msix.py",
        "legacy_windows_package.py",
    )
    # pylint: enable=duplicate-code
