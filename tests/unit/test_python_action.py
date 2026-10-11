"""Exercise controller staging and normal-action lifecycle without a target."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ntpath
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest

# Ansible's controller interfaces have no distributed typing metadata.
from ansible import constants as ansible_constants  # type: ignore[import-untyped]
from ansible._internal._templating._engine import (  # type: ignore[import-untyped]
    TemplateEngine,
)
from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleActionFail,
    AnsibleError,
)
from ansible.executor.module_common import modify_module  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.playbook.block import Block  # type: ignore[import-untyped]
from ansible.playbook.play import Play  # type: ignore[import-untyped]
from ansible.playbook.task import Task  # type: ignore[import-untyped]
from ansible.plugins.loader import (  # type: ignore[import-untyped]
    action_loader,
    init_plugin_loader,
)
from ansible.template import Templar  # type: ignore[import-untyped]

# The checkout's source-only plugin namespace is resolved by pytest's pythonpath.
from plugins.plugin_utils._module import (  # pylint: disable=import-error
    PythonModuleAction,
)
from tests.unit.python_action_helpers import EXPECTED_HELPERS

_ROOT = Path(__file__).resolve().parents[2]
_REMOTE_TMP = r"C:\Users\Test User\Temp\ansible-tmp-test"
_MODULES = (
    "setup",
    "win_ping",
    "win_command",
    "win_tempfile",
    "slurp",
    "win_shell",
    "win_file",
    "win_file_compression",
    "win_owner",
    "win_acl_inheritance",
    "win_acl",
    "win_stat",
    "win_find",
    "win_environment",
    "win_reg_stat",
    "win_regedit",
    "win_path",
    "win_group",
    "win_group_membership",
    "win_user",
    "win_wait_for",
    "win_service_info",
    "win_reboot_info",
    "win_whoami",
    "win_listen_ports_facts",
    "win_product_facts",
    "win_certificate_info",
    "win_hosts",
    "win_computer_description",
    "win_timezone",
    "win_hostname",
    "win_http_proxy",
    "win_inet_proxy",
    "win_auto_logon",
    "win_user_right",
    "win_share",
    "win_mapped_drive",
    "win_credential",
    "win_dns_client",
    "win_dhcp_lease",
    "win_eventlog",
    "win_service",
    "win_route",
    "win_firewall",
    "win_audit_policy_system",
    "win_audit_rule",
    "win_optional_feature",
    "win_region",
    "win_capability_info",
    "win_user_profile",
    "win_capability",
    "win_certificate_store",
    "win_feature_info",
    "win_get_url",
    "win_uri",
    "win_hotfix",
    "win_package",
    "win_dns_record",
    "win_dns_zone",
    "win_dsc",
    "win_powershell",
    "win_feature",
)


@pytest.fixture(name="collection_actions", scope="module")
def load_collection_actions(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, type[PythonModuleAction]]:
    """Load action plugins through Ansible's actual collection namespace.

    :param tmp_path_factory: Pytest's scoped temporary-directory factory.
    :returns: The loaded native Python action classes.
    """
    collections = tmp_path_factory.mktemp("action-collections")
    namespace = collections / "ansible_collections" / "sustainablelobster"
    namespace.mkdir(parents=True)
    (namespace / "legacy_windows").symlink_to(_ROOT, target_is_directory=True)
    init_plugin_loader([str(collections)])
    return {
        name: cast(
            type[PythonModuleAction],
            action_loader.get(
                f"sustainablelobster.legacy_windows.{name}", class_only=True
            ),
        )
        for name in _MODULES + ("win_copy",)
    }


def _action(
    action_type: type[PythonModuleAction],
    monkeypatch: pytest.MonkeyPatch,
    *,
    async_val: int = 0,
    become: object = None,
    existing_tmp: str | None = None,
) -> tuple[PythonModuleAction, SimpleNamespace, list[tuple[object, ...]]]:
    monkeypatch.setattr(ansible_constants, "DEFAULT_KEEP_REMOTE_FILES", False)
    events: list[tuple[object, ...]] = []
    shell = SimpleNamespace(
        tmpdir=existing_tmp,
        join_path=ntpath.join,
        remove=lambda path, recurse: ("remove", path, recurse),
    )
    connection = SimpleNamespace(_shell=shell, become=become)
    task = SimpleNamespace(
        action="sustainablelobster.legacy_windows.win_ping",
        args={},
        async_val=async_val,
        check_mode=False,
    )
    action = action_type(task, connection, None, DataLoader(), TemplateEngine())

    def _make_tmp() -> str:
        events.append(("mkdir",))
        shell.tmpdir = _REMOTE_TMP
        # Match the ownership flag set by Ansible's successful directory creation.
        action._cleanup_remote_tmp = True  # pylint: disable=protected-access
        return _REMOTE_TMP

    def _transfer(source: str, target: str) -> str:
        events.append(("transfer", source, target))
        return target

    def _execute_module(**kwargs: object) -> dict[str, object]:
        events.append(("module", kwargs))
        return {"changed": False, "ping": "pong"}

    def _execute_cleanup(command: object, **kwargs: object) -> dict[str, object]:
        events.append(("cleanup", command, kwargs))
        return {"rc": 0}

    monkeypatch.setattr(action, "_make_tmp_path", _make_tmp)
    monkeypatch.setattr(action, "_transfer_file", _transfer)
    monkeypatch.setattr(action, "_execute_module", _execute_module)
    monkeypatch.setattr(action, "_low_level_execute_command", _execute_cleanup)
    return action, shell, events


@pytest.mark.parametrize("module", _MODULES)
def test_stages_only_required_helpers_and_normal_action_cleans_once(
    collection_actions: dict[str, type[PythonModuleAction]],
    monkeypatch: pytest.MonkeyPatch,
    module: str,
) -> None:
    action, shell, events = _action(collection_actions[module], monkeypatch)
    variables: dict[str, object] = {"example": "value"}
    extra_helpers = EXPECTED_HELPERS
    helpers = ["legacy_windows_module.py", *extra_helpers.get(module, [])]

    assert action.run(task_vars=variables) == {"changed": False, "ping": "pong"}
    assert events == [
        ("mkdir",),
        *[
            (
                "transfer",
                str(_ROOT / "plugins/module_utils" / name),
                ntpath.join(_REMOTE_TMP, name),
            )
            for name in helpers
        ],
        ("module", {"task_vars": variables, "wrap_async": 0}),
        ("cleanup", ("remove", _REMOTE_TMP, True), {"sudoable": False}),
    ]
    assert shell.tmpdir is None


@pytest.mark.parametrize("failure_step", ["_transfer_file", "_execute_module"])
@pytest.mark.parametrize("keep_files", [False, True])
@pytest.mark.parametrize("module", _MODULES)
def test_failure_cleanup_respects_keep_remote_files(
    collection_actions: dict[str, type[PythonModuleAction]],
    monkeypatch: pytest.MonkeyPatch,
    failure_step: str,
    keep_files: bool,
    module: str,
) -> None:
    action, shell, events = _action(collection_actions[module], monkeypatch)
    monkeypatch.setattr(ansible_constants, "DEFAULT_KEEP_REMOTE_FILES", keep_files)
    monkeypatch.setattr(
        action, failure_step, Mock(side_effect=OSError("broken transfer"))
    )

    with pytest.raises(OSError, match="broken transfer"):
        action.run()

    assert sum(event[0] == "cleanup" for event in events) == int(not keep_files)
    assert shell.tmpdir == (_REMOTE_TMP if keep_files else None)


@pytest.mark.parametrize("module", _MODULES)
def test_success_respects_keep_remote_files(
    collection_actions: dict[str, type[PythonModuleAction]],
    monkeypatch: pytest.MonkeyPatch,
    module: str,
) -> None:
    action, shell, events = _action(collection_actions[module], monkeypatch)
    monkeypatch.setattr(ansible_constants, "DEFAULT_KEEP_REMOTE_FILES", True)

    assert action.run()["ping"] == "pong"
    assert shell.tmpdir == _REMOTE_TMP
    assert not any(event[0] == "cleanup" for event in events)


@pytest.mark.parametrize("module", _MODULES)
def test_existing_directory_is_neither_recreated_nor_owned(
    collection_actions: dict[str, type[PythonModuleAction]],
    monkeypatch: pytest.MonkeyPatch,
    module: str,
) -> None:
    action, shell, events = _action(
        collection_actions[module], monkeypatch, existing_tmp=_REMOTE_TMP
    )

    assert action.run()["ping"] == "pong"
    assert shell.tmpdir == _REMOTE_TMP
    transfers = 1 + len(EXPECTED_HELPERS.get(module, []))
    assert [event[0] for event in events] == ["transfer"] * transfers + ["module"]


@pytest.mark.parametrize(
    "case",
    [
        ("setup", "legacy_windows_wmi.py", 1),
        ("setup", "legacy_windows_async_native.py", 2),
        ("setup", "legacy_windows_account.py", 3),
        ("setup", "legacy_windows_group.py", 4),
        ("setup", "legacy_windows_calendar.py", 5),
        ("setup", "legacy_windows_time.py", 6),
        ("setup", "legacy_windows_uformat.py", 7),
        ("setup", "legacy_windows_certificate.py", 8),
        ("setup", "legacy_windows_setup_date.py", 9),
        ("setup", "legacy_windows_setup_native.py", 10),
        ("setup", "legacy_windows_setup_network.py", 11),
        ("setup", "legacy_windows_setup_winrm.py", 12),
        ("setup", "legacy_windows_setup.py", 13),
        ("win_command", "legacy_windows_process.py", 1),
        ("win_command", "legacy_windows_text.py", 2),
        ("win_shell", "legacy_windows_process.py", 1),
        ("win_shell", "legacy_windows_text.py", 2),
        ("win_file", "legacy_windows_file.py", 1),
        ("win_file", "legacy_windows_time.py", 2),
        ("win_file", "legacy_windows_calendar.py", 3),
        ("win_file", "legacy_windows_datetime.py", 4),
        ("win_file_compression", "legacy_windows_file.py", 1),
        ("win_file_compression", "legacy_windows_wmi.py", 2),
        ("win_file_compression", "legacy_windows_compression.py", 3),
        ("win_owner", "legacy_windows_account.py", 1),
        ("win_owner", "legacy_windows_group.py", 2),
        ("win_owner", "legacy_windows_file.py", 3),
        ("win_owner", "legacy_windows_owner.py", 4),
        ("win_stat", "legacy_windows_stat.py", 1),
        ("win_stat", "legacy_windows_link.py", 2),
        ("win_find", "legacy_windows_stat.py", 1),
        ("win_find", "legacy_windows_link.py", 2),
        ("win_find", "legacy_windows_time.py", 3),
        ("win_find", "legacy_windows_find_match.py", 4),
        ("win_find", "legacy_windows_regex.py", 5),
        ("win_find", "legacy_windows_regex_categories.py", 6),
        ("win_wait_for", "legacy_windows_wait.py", 1),
        ("win_wait_for", "legacy_windows_regex.py", 2),
        ("win_wait_for", "legacy_windows_regex_categories.py", 3),
        ("win_wait_for", "legacy_windows_text.py", 4),
        ("win_service_info", "legacy_windows_account.py", 1),
        ("win_service_info", "legacy_windows_regex.py", 2),
        ("win_service_info", "legacy_windows_find_match.py", 3),
        ("win_service_info", "legacy_windows_service_config.py", 4),
        ("win_service_info", "legacy_windows_service_info.py", 5),
        ("win_reboot_info", "legacy_windows_reg_stat.py", 1),
        ("win_reboot_info", "legacy_windows_wmi.py", 2),
        ("win_reboot_info", "legacy_windows_boot.py", 3),
        ("win_reboot_info", "legacy_windows_time.py", 4),
        ("win_reboot_info", "legacy_windows_reboot.py", 5),
        ("win_whoami", "legacy_windows_account.py", 1),
        ("win_whoami", "legacy_windows_time.py", 2),
        ("win_whoami", "legacy_windows_token.py", 3),
        ("win_whoami", "legacy_windows_logon.py", 4),
        ("win_listen_ports_facts", "legacy_windows_wmi.py", 1),
        ("win_listen_ports_facts", "legacy_windows_process_info.py", 2),
        ("win_listen_ports_facts", "legacy_windows_ports.py", 3),
        ("win_listen_ports_facts", "legacy_windows_calendar.py", 4),
        ("win_listen_ports_facts", "legacy_windows_time.py", 5),
        ("win_listen_ports_facts", "legacy_windows_uformat.py", 6),
        ("win_product_facts", "legacy_windows_wmi.py", 1),
        ("win_product_facts", "legacy_windows_product_key.py", 2),
        ("win_product_facts", "legacy_windows_product.py", 3),
        ("win_certificate_info", "legacy_windows_calendar.py", 1),
        ("win_certificate_info", "legacy_windows_certificate.py", 2),
        ("win_environment", "legacy_windows_environment.py", 1),
        ("win_hosts", "legacy_windows_environment.py", 1),
        ("win_hosts", "legacy_windows_text.py", 2),
        ("win_hosts", "legacy_windows_hosts.py", 3),
        ("win_computer_description", "legacy_windows_wmi.py", 1),
        ("win_computer_description", "legacy_windows_computer_description.py", 2),
        ("win_timezone", "legacy_windows_account.py", 1),
        ("win_timezone", "legacy_windows_group.py", 2),
        ("win_timezone", "legacy_windows_owner.py", 3),
        ("win_timezone", "legacy_windows_time.py", 4),
        ("win_timezone", "legacy_windows_environment.py", 5),
        ("win_timezone", "legacy_windows_timezone.py", 6),
        ("win_hostname", "legacy_windows_wmi.py", 1),
        ("win_hostname", "legacy_windows_environment.py", 2),
        ("win_hostname", "legacy_windows_hostname.py", 3),
        ("win_http_proxy", "legacy_windows_environment.py", 1),
        ("win_http_proxy", "legacy_windows_http_proxy.py", 2),
        ("win_inet_proxy", "legacy_windows_environment.py", 1),
        ("win_inet_proxy", "legacy_windows_inet_proxy.py", 2),
        ("win_auto_logon", "legacy_windows_account.py", 1),
        ("win_auto_logon", "legacy_windows_environment.py", 2),
        ("win_auto_logon", "legacy_windows_auto_logon.py", 3),
        ("win_user_right", "legacy_windows_account.py", 1),
        ("win_user_right", "legacy_windows_group.py", 2),
        ("win_user_right", "legacy_windows_owner.py", 3),
        ("win_user_right", "legacy_windows_user_right.py", 4),
        ("win_share", "legacy_windows_account.py", 1),
        ("win_share", "legacy_windows_environment.py", 2),
        ("win_share", "legacy_windows_group.py", 3),
        ("win_share", "legacy_windows_owner.py", 4),
        ("win_share", "legacy_windows_share.py", 5),
        ("win_mapped_drive", "legacy_windows_account.py", 1),
        ("win_mapped_drive", "legacy_windows_environment.py", 2),
        ("win_mapped_drive", "legacy_windows_mapped_drive.py", 3),
        ("win_credential", "legacy_windows_credential.py", 1),
        ("win_credential", "legacy_windows_environment.py", 2),
        ("win_dns_client", "legacy_windows_wmi.py", 1),
        ("win_dns_client", "legacy_windows_dns_client.py", 2),
        pytest.param(
            ("win_dhcp_lease", "legacy_windows_wmi.py", 1),
            id="win_dhcp_lease-wmi",
        ),
        pytest.param(
            ("win_dhcp_lease", "legacy_windows_time.py", 2),
            id="win_dhcp_lease-time",
        ),
        pytest.param(
            ("win_dhcp_lease", "legacy_windows_environment.py", 3),
            id="win_dhcp_lease-environment",
        ),
        pytest.param(
            ("win_dhcp_lease", "legacy_windows_dhcp_api.py", 4),
            id="win_dhcp_lease-native-api",
        ),
        pytest.param(
            ("win_dhcp_lease", "legacy_windows_dhcp_lease.py", 5),
            id="win_dhcp_lease-provider",
        ),
        ("win_route", "legacy_windows_wmi.py", 1),
        ("win_route", "legacy_windows_route.py", 2),
        ("win_firewall", "legacy_windows_wmi.py", 1),
        ("win_firewall", "legacy_windows_firewall.py", 2),
        ("win_audit_policy_system", "legacy_windows_environment.py", 1),
        ("win_audit_policy_system", "legacy_windows_process.py", 2),
        ("win_audit_policy_system", "legacy_windows_text.py", 3),
        ("win_audit_policy_system", "legacy_windows_audit_policy.py", 4),
        ("win_audit_rule", "legacy_windows_account.py", 1),
        ("win_audit_rule", "legacy_windows_group.py", 2),
        ("win_audit_rule", "legacy_windows_owner.py", 3),
        ("win_audit_rule", "legacy_windows_link.py", 4),
        ("win_audit_rule", "legacy_windows_acl_inheritance.py", 5),
        ("win_audit_rule", "legacy_windows_acl.py", 6),
        ("win_audit_rule", "legacy_windows_regex.py", 7),
        ("win_audit_rule", "legacy_windows_find_match.py", 8),
        ("win_audit_rule", "legacy_windows_audit_rule.py", 9),
        ("win_optional_feature", "legacy_windows_optional_feature.py", 1),
        ("win_region", "legacy_windows_environment.py", 1),
        ("win_region", "legacy_windows_region.py", 2),
        ("win_capability_info", "legacy_windows_regex.py", 1),
        ("win_capability_info", "legacy_windows_find_match.py", 2),
        ("win_capability_info", "legacy_windows_capability.py", 3),
        ("win_user_profile", "legacy_windows_account.py", 1),
        ("win_user_profile", "legacy_windows_environment.py", 2),
        ("win_user_profile", "legacy_windows_user_profile.py", 3),
        ("win_capability", "legacy_windows_regex.py", 1),
        ("win_capability", "legacy_windows_find_match.py", 2),
        ("win_capability", "legacy_windows_capability.py", 3),
        ("win_capability", "legacy_windows_capability_manage.py", 4),
        ("win_certificate_store", "legacy_windows_certificate_store.py", 1),
        ("win_feature_info", "legacy_windows_regex.py", 1),
        ("win_feature_info", "legacy_windows_find_match.py", 2),
        ("win_feature_info", "legacy_windows_wmi.py", 3),
        ("win_feature_info", "legacy_windows_feature_legacy.py", 4),
        ("win_feature_info", "legacy_windows_feature_info.py", 5),
        pytest.param(
            ("win_get_url", "legacy_windows_calendar.py", 1),
            id="win_get_url-calendar",
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_file.py", 2), id="win_get_url-file"
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_stat.py", 3), id="win_get_url-stat"
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_time.py", 4), id="win_get_url-time"
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_copy.py", 5), id="win_get_url-copy"
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_certificate_store.py", 6),
            id="win_get_url-certificate-store",
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_http_certificate.py", 7),
            id="win_get_url-http-certificate",
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_get_url_ftp.py", 8),
            id="win_get_url-ftp",
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_get_url_http.py", 9),
            id="win_get_url-plain-http",
        ),
        pytest.param(
            ("win_get_url", "legacy_windows_get_url.py", 10),
            id="win_get_url-http-file",
        ),
        ("win_uri", "legacy_windows_calendar.py", 1),
        ("win_uri", "legacy_windows_file.py", 2),
        ("win_uri", "legacy_windows_stat.py", 3),
        ("win_uri", "legacy_windows_time.py", 4),
        ("win_uri", "legacy_windows_copy.py", 5),
        ("win_uri", "legacy_windows_certificate_store.py", 6),
        ("win_uri", "legacy_windows_http_certificate.py", 7),
        ("win_uri", "legacy_windows_get_url_ftp.py", 8),
        ("win_uri", "legacy_windows_get_url_http.py", 9),
        ("win_uri", "legacy_windows_get_url.py", 10),
        ("win_uri", "legacy_windows_uri.py", 11),
        ("win_hotfix", "legacy_windows_regex.py", 1),
        ("win_hotfix", "legacy_windows_find_match.py", 2),
        ("win_hotfix", "legacy_windows_wmi.py", 3),
        ("win_hotfix", "legacy_windows_hotfix_command.py", 4),
        ("win_hotfix", "legacy_windows_hotfix.py", 5),
        ("win_package", "legacy_windows_text.py", 1),
        ("win_package", "legacy_windows_process.py", 2),
        ("win_package", "legacy_windows_account.py", 3),
        ("win_package", "legacy_windows_group.py", 4),
        ("win_package", "legacy_windows_owner.py", 5),
        ("win_package", "legacy_windows_link.py", 6),
        ("win_package", "legacy_windows_acl_inheritance.py", 7),
        ("win_package", "legacy_windows_acl.py", 8),
        ("win_package", "legacy_windows_package_msi.py", 9),
        ("win_package", "legacy_windows_calendar.py", 10),
        ("win_package", "legacy_windows_file.py", 11),
        ("win_package", "legacy_windows_stat.py", 12),
        ("win_package", "legacy_windows_time.py", 13),
        ("win_package", "legacy_windows_copy.py", 14),
        ("win_package", "legacy_windows_certificate_store.py", 15),
        ("win_package", "legacy_windows_http_certificate.py", 16),
        ("win_package", "legacy_windows_get_url_ftp.py", 17),
        ("win_package", "legacy_windows_get_url_http.py", 18),
        ("win_package", "legacy_windows_get_url.py", 19),
        ("win_package", "legacy_windows_package_url.py", 20),
        ("win_package", "legacy_windows_regex.py", 21),
        ("win_package", "legacy_windows_find_match.py", 22),
        ("win_package", "legacy_windows_service_config.py", 23),
        ("win_package", "legacy_windows_service_info.py", 24),
        ("win_package", "legacy_windows_package_signature.py", 25),
        ("win_package", "legacy_windows_package_children.py", 26),
        ("win_package", "legacy_windows_package_msix.py", 27),
        ("win_package", "legacy_windows_package.py", 28),
        ("win_dns_record", "legacy_windows_wmi.py", 1),
        ("win_dns_record", "legacy_windows_dns_classic.py", 2),
        ("win_dns_record", "legacy_windows_dns_record.py", 3),
        ("win_dns_zone", "legacy_windows_wmi.py", 1),
        ("win_dns_zone", "legacy_windows_dns_classic.py", 2),
        ("win_dns_zone", "legacy_windows_dns_zone.py", 3),
        ("win_dsc", "legacy_windows_dsc_engine.py", 1),
        ("win_dsc", "legacy_windows_dsc.py", 2),
        ("win_powershell", "legacy_windows_powershell_engine.py", 1),
        ("win_powershell", "legacy_windows_powershell.py", 2),
        ("win_feature", "legacy_windows_regex.py", 1),
        ("win_feature", "legacy_windows_find_match.py", 2),
        ("win_feature", "legacy_windows_wmi.py", 3),
        ("win_feature", "legacy_windows_feature_legacy.py", 4),
        ("win_feature", "legacy_windows_feature_info.py", 5),
        ("win_feature", "legacy_windows_feature_manage.py", 6),
        ("win_eventlog", "legacy_windows_environment.py", 1),
        ("win_eventlog", "legacy_windows_eventlog.py", 2),
        ("win_service", "legacy_windows_service.py", 1),
        ("win_service", "legacy_windows_environment.py", 2),
        ("win_service", "legacy_windows_account.py", 3),
        ("win_reg_stat", "legacy_windows_reg_stat.py", 1),
        ("win_regedit", "legacy_windows_reg_stat.py", 1),
        ("win_regedit", "legacy_windows_regedit.py", 2),
        ("win_regedit", "legacy_windows_regedit_data.py", 3),
        ("win_path", "legacy_windows_environment.py", 1),
        ("win_path", "legacy_windows_reg_stat.py", 2),
        ("win_path", "legacy_windows_path.py", 3),
        ("win_group", "legacy_windows_account.py", 1),
        ("win_group", "legacy_windows_environment.py", 2),
        ("win_group", "legacy_windows_group.py", 3),
        ("win_group_membership", "legacy_windows_account.py", 1),
        ("win_group_membership", "legacy_windows_environment.py", 2),
        ("win_group_membership", "legacy_windows_group.py", 3),
        ("win_user", "legacy_windows_account.py", 1),
        ("win_user", "legacy_windows_calendar.py", 2),
        ("win_user", "legacy_windows_datetime.py", 3),
        ("win_user", "legacy_windows_environment.py", 4),
        ("win_user", "legacy_windows_group.py", 5),
        ("win_user", "legacy_windows_time.py", 6),
        ("win_user", "legacy_windows_user.py", 7),
        ("win_user", "legacy_windows_user_time.py", 8),
    ],
)
@pytest.mark.parametrize("keep_files", [False, True])
def test_additional_helper_failure_cleans_the_partially_staged_directory(
    collection_actions: dict[str, type[PythonModuleAction]],
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[str, str, int],
    keep_files: bool,
) -> None:
    module, helper, staged = case
    action, shell, events = _action(collection_actions[module], monkeypatch)
    monkeypatch.setattr(ansible_constants, "DEFAULT_KEEP_REMOTE_FILES", keep_files)
    # Exercise the real staging order while replacing only the transfer boundary.
    transfer = action._transfer_file  # pylint: disable=protected-access

    def _fail_helper_transfer(source: str, target: str) -> str:
        if Path(source).name == helper:
            raise OSError("helper transfer failed")
        return cast(str, transfer(source, target))

    monkeypatch.setattr(action, "_transfer_file", _fail_helper_transfer)

    with pytest.raises(OSError, match="helper transfer failed"):
        action.run()

    assert sum(event[0] == "transfer" for event in events) == staged
    assert not any(event[0] == "module" for event in events)
    assert sum(event[0] == "cleanup" for event in events) == int(not keep_files)
    assert shell.tmpdir == (_REMOTE_TMP if keep_files else None)


@pytest.mark.parametrize("module", _MODULES)
@pytest.mark.parametrize(
    ("options", "message"),
    [({"async_val": 10}, "async"), ({"become": object()}, "privilege escalation")],
)
def test_unsupported_features_fail_before_remote_effects(
    collection_actions: dict[str, type[PythonModuleAction]],
    monkeypatch: pytest.MonkeyPatch,
    module: str,
    options: dict[str, object],
    message: str,
) -> None:
    action, shell, events = _action(
        collection_actions[module],
        monkeypatch,
        async_val=cast(int, options.get("async_val", 0)),
        become=options.get("become"),
    )

    with pytest.raises(AnsibleActionFail, match=message):
        action.run()

    assert not events
    assert shell.tmpdir is None


@pytest.mark.parametrize("module", _MODULES + ("win_copy",))
def test_ansible_task_validation_preserves_only_process_free_form(
    collection_actions: dict[str, type[PythonModuleAction]], module: str
) -> None:
    assert module in collection_actions
    command = 'C:\\Python34\\python.exe -c "print(42)"'
    task = Task.load(
        {f"sustainablelobster.legacy_windows.{module}": command},
        block=Block(play=Play()),
    )

    if module in ("win_command", "win_shell"):
        task.post_validate(TemplateEngine())
        assert task.args == {"_raw_params": command}
    else:
        with pytest.raises(AnsibleError, match="does not support raw params"):
            task.post_validate(TemplateEngine())


@pytest.mark.parametrize("module", _MODULES + ("win_copy",))
def test_ansible_preserves_native_payload_without_modern_python_wrapper(
    collection_actions: dict[str, type[PythonModuleAction]], module: str
) -> None:
    assert module in collection_actions
    module_path = _ROOT / "plugins" / "modules" / f"{module}.py"
    built = modify_module(
        module_name=f"sustainablelobster.legacy_windows.{module}",
        module_path=str(module_path),
        module_args={},
        templar=Templar(),
        task_vars={"ansible_python_interpreter": r"C:\Python34\python.exe"},
        shell_plugin=SimpleNamespace(_IS_WINDOWS=True),
    )

    assert built.module_style == "non_native_want_json"
    assert built.shebang == r"#!C:\Python34\python.exe"
    assert (
        built.b_module_data.split(b"\n", 1)[1]
        == module_path.read_bytes().split(b"\n", 1)[1]
    )
