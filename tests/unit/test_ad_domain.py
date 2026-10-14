"""Exercise concrete promotion workflows without contacting directory hosts."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native engine and Windows reads are independently supplied boundary fixtures.
# pylint: disable=protected-access

import importlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

_DOMAIN = "example.test"
_ADMIN = "administrator@example.test"
_PASSWORD = "FixtureDomainSecret1!"
_SAFE = "FixtureSafeModeSecret2!"
_LOCAL = "FixtureLocalSecret3!"
_DOMAIN_ARGS = {"dns_domain_name": _DOMAIN, "safe_mode_password": _SAFE}
_CHILD_ARGS = {
    "dns_domain_name": "child." + _DOMAIN,
    "domain_admin_user": _ADMIN,
    "domain_admin_password": _PASSWORD,
    "safe_mode_password": _SAFE,
}
_CONTROLLER_ARGS = {
    "state": "domain_controller",
    "dns_domain_name": _DOMAIN,
    "domain_admin_user": _ADMIN,
    "domain_admin_password": _PASSWORD,
    "safe_mode_password": _SAFE,
}
_HELP_FIELDS = (
    "ReplicaOrNewDomain",
    "NewDomain",
    "NewDomainDNSName",
    "ChildName",
    "ParentDomainDNSName",
    "ReplicaDomainDNSName",
    "RebootOnCompletion",
    "RebootOnSuccess",
    "SafeModeAdminPassword",
    "UserName",
    "UserDomain",
    "Password",
    "DomainNetbiosName",
    "DatabasePath",
    "LogPath",
    "SYSVOLPath",
    "InstallDNS",
    "CreateDNSDelegation",
    "SiteName",
    "ReplicationSourceDC",
    "ReplicationSourcePath",
    "AdministratorPassword",
    "IsLastDCInDomain",
)


@pytest.fixture(name="runtime")
def runtime_fixture(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Load production workflows with only Windows/engine boundaries replaced.

    :param monkeypatch: Scoped import paths and native boundary replacements.
    :returns: Production payloads, independent engine help, and boundary spies.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    native = importlib.import_module("legacy_ad_domain_native")
    engine = native.PromotionEngine.__new__(native.PromotionEngine)
    engine.path = r"C:\Windows\System32\dcpromo.exe"
    engine.legacy_answer_format = False
    engine.help = (
        "\n".join(_HELP_FIELDS)
        + "\nDomainLevel:{0|2|3|4}\nForestLevel:{0|2|3|4}\nReadOnlyReplica"
    )
    engine.run = Mock(return_value=(2, "operation completed"))
    engine.ensure_dns_installed = Mock()
    engine_factory = Mock(return_value=engine)
    current = Mock(
        return_value={"hostname": "Server", "domain": "WORKGROUP", "role": 2}
    )
    forest = Mock(return_value=False)
    roles = Mock(return_value=[])
    netlogon = Mock()
    active_controller = Mock(return_value=False)
    complete_levels = Mock()
    monkeypatch.setattr(native, "PromotionEngine", engine_factory)
    monkeypatch.setattr(native, "current_state", current)
    monkeypatch.setattr(native, "forest_exists", forest)
    monkeypatch.setattr(native, "assigned_roles", roles)
    monkeypatch.setattr(native, "start_netlogon", netlogon)
    monkeypatch.setattr(native, "is_domain_controller", active_controller)
    monkeypatch.setattr(native, "complete_legacy_levels", complete_levels)
    payloads = {
        name: load_module(
            ROOT / "legacy_ad/plugins/modules" / (name + ".py"), "tested_" + name
        )
        for name in ("domain", "domain_child", "domain_controller")
    }
    return SimpleNamespace(
        native=native,
        engine=engine,
        engine_factory=engine_factory,
        current=current,
        forest=forest,
        roles=roles,
        netlogon=netlogon,
        active_controller=active_controller,
        complete_levels=complete_levels,
        payloads=payloads,
    )


@pytest.fixture(name="run_request")
def request_fixture(
    runtime: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[..., Any]:
    """Invoke a public module's actual JSON entry point with owned arguments.

    :param runtime: Real payloads and native boundary spies.
    :param monkeypatch: Scoped process argument replacement.
    :param tmp_path: Owned argument-file directory.
    :param capsys: Captured Ansible JSON.
    :returns: Module-name and public-arguments invocation callable.
    """
    argument_file = tmp_path / "domain-arguments.json"

    def _run(name: str, arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [name + ".py", str(argument_file)])
        return invoke_payload(runtime.payloads[name], capsys)

    return _run


def test_new_forest_uses_available_functional_defaults_and_disables_automatic_reboot(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    assert run_request("domain", _DOMAIN_ARGS) == (
        0,
        {"changed": True, "reboot_required": True, "_do_action_reboot": False},
    )
    settings = runtime.engine.run.call_args[0][0]
    assert settings == {
        "ReplicaOrNewDomain": "Domain",
        "NewDomain": "Forest",
        "NewDomainDNSName": _DOMAIN,
        "SafeModeAdminPassword": _SAFE,
        "InstallDNS": "Yes",
        "DomainLevel": "4",
        "ForestLevel": "4",
        "RebootOnCompletion": "No",
        "RebootOnSuccess": "NoAndNoPromptEither",
    }
    runtime.netlogon.assert_called_once_with()
    runtime.engine.ensure_dns_installed.assert_not_called()


def test_existing_reachable_forest_on_a_controller_is_idempotent(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    runtime.current.return_value.update(role=5, domain=_DOMAIN)
    runtime.active_controller.return_value = True
    runtime.forest.return_value = True
    assert run_request("domain", _DOMAIN_ARGS) == (
        0,
        {"changed": False, "reboot_required": False, "_do_action_reboot": False},
    )
    runtime.engine_factory.assert_not_called()


def test_reachable_forest_does_not_turn_a_member_server_into_an_idempotent_noop(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    runtime.forest.return_value = True
    code, result = run_request("domain", _DOMAIN_ARGS)
    assert code == 0 and result["changed"]
    runtime.engine.run.assert_called_once()


def test_pending_computer_role_does_not_replace_the_active_os_controller_signal(
    run_request: Callable[..., Any], runtime: SimpleNamespace
) -> None:
    runtime.current.return_value.update(role=5, domain=_DOMAIN)
    runtime.active_controller.return_value = False
    runtime.forest.return_value = True
    code, result = run_request("domain", _DOMAIN_ARGS)
    assert code == 0 and result["changed"] is True
    runtime.engine.run.assert_called_once()


def test_new_forest_optional_settings_and_released_mode_names_are_preserved(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    code, result = run_request(
        "domain",
        dict(
            _DOMAIN_ARGS,
            domain_mode="Win2008",
            forest_mode="win2003",
            domain_netbios_name="EXAMPLE",
            create_dns_delegation=False,
            install_dns=False,
            database_path=r"D:\Database",
            log_path=r"D:\Logs",
            sysvol_path=r"D:\Sysvol",
        ),
    )
    assert code == 0 and result["changed"]
    settings = runtime.engine.run.call_args[0][0]
    assert settings["DomainLevel"] == "3" and settings["ForestLevel"] == "2"
    assert (
        settings["DomainNetbiosName"] == "EXAMPLE"
        and settings["CreateDNSDelegation"] == "No"
    )
    assert settings["InstallDNS"] == "No" and settings["DatabasePath"] == r"D:\Database"
    assert settings["LogPath"] == r"D:\Logs" and settings["SYSVOLPath"] == r"D:\Sysvol"


@pytest.mark.parametrize("install_dns", [False, True])
def test_legacy_forest_uses_native_dns_and_noninteractive_reboot_fields(
    run_request: Callable[..., Any], runtime: SimpleNamespace, install_dns: bool
) -> None:
    runtime.engine.help = "\n".join(runtime.native._LEGACY_ANSWER_FIELDS)
    code, result = run_request("domain", dict(_DOMAIN_ARGS, install_dns=install_dns))
    assert code == 0 and result["changed"] and result["reboot_required"]
    assert "level-0 domain and forest" in result["warnings"][0]
    assert "_legacy_ad_complete_promotion" not in result
    expected = {
        "RebootOnSuccess": "NoAndNoPromptEither",
        "ReplicaOrNewDomain": "Domain",
        "NewDomain": "Forest",
        "NewDomainDNSName": _DOMAIN,
        "SafeModeAdminPassword": _SAFE,
        "AutoConfigDNS": "Yes" if install_dns else "No",
    }
    if install_dns:
        expected["DNSOnNetwork"] = "No"
    assert runtime.engine.run.call_args.args[0] == expected
    assert runtime.engine.ensure_dns_installed.call_count == int(install_dns)


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("option", ["domain_mode", "forest_mode"])
def test_legacy_explicit_level_without_reboot_fails_before_promotion(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    check: bool,
    option: str,
) -> None:
    runtime.engine.help = "\n".join(runtime.native._LEGACY_ANSWER_FIELDS)
    code, result = run_request(
        "domain",
        dict(_DOMAIN_ARGS, **{option: "Win2003", "_ansible_check_mode": check}),
    )
    assert code == 1 and not result["changed"]
    assert option in result["msg"] and "reboot=true" in result["msg"]
    runtime.engine.run.assert_not_called()


@pytest.mark.parametrize("level", [None, "Win2003"])
def test_legacy_forest_requests_one_completion_pass_after_explicit_reboot(
    run_request: Callable[..., Any], runtime: SimpleNamespace, level: str | None
) -> None:
    runtime.engine.help = "\n".join(runtime.native._LEGACY_ANSWER_FIELDS)
    code, result = run_request(
        "domain", dict(_DOMAIN_ARGS, domain_mode=level, forest_mode=level, reboot=True)
    )
    assert code == 0 and result["_legacy_ad_complete_promotion"] is True
    assert "DomainLevel" not in runtime.engine.run.call_args.args[0]
    assert "ForestLevel" not in runtime.engine.run.call_args.args[0]


@pytest.mark.parametrize("option", ["domain_mode", "forest_mode"])
def test_legacy_unavailable_level_fails_even_when_reboot_is_requested(
    run_request: Callable[..., Any], runtime: SimpleNamespace, option: str
) -> None:
    runtime.engine.help = "\n".join(runtime.native._LEGACY_ANSWER_FIELDS)
    code, result = run_request(
        "domain", dict(_DOMAIN_ARGS, **{option: "Win2008", "reboot": True})
    )
    assert code == 1 and result["changed"] is False
    assert "normal Win2003" in result["msg"]
    runtime.engine.run.assert_not_called()


@pytest.mark.parametrize(
    "module_name,arguments,forest",
    [
        ("domain", _DOMAIN_ARGS, True),
        ("domain_child", _CHILD_ARGS, False),
    ],
)
def test_controller_completion_does_not_repeat_the_native_role_change(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    module_name: str,
    arguments: dict[str, Any],
    forest: bool,
) -> None:
    code, result = run_request(
        module_name, dict(arguments, _ansible_legacy_ad_complete_promotion=True)
    )
    assert code == 0 and result["reboot_required"] is False
    runtime.complete_levels.assert_called_once_with(
        arguments["dns_domain_name"], forest, result
    )
    runtime.engine_factory.assert_not_called()
    runtime.forest.assert_not_called()


@pytest.mark.parametrize(
    "module_name,arguments",
    [
        ("domain", _DOMAIN_ARGS),
        ("domain_child", _CHILD_ARGS),
        ("domain_controller", _CONTROLLER_ARGS),
    ],
)
@pytest.mark.parametrize("legacy", [False, True])
def test_check_mode_validates_capabilities_without_writing_an_answer_or_running_promotion(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    module_name: str,
    arguments: dict[str, Any],
    legacy: bool,
) -> None:
    if legacy:
        runtime.engine.help = "\n".join(runtime.native._LEGACY_ANSWER_FIELDS)
    code, result = run_request(module_name, dict(arguments, _ansible_check_mode=True))
    assert code == 0 and result["changed"] and result["reboot_required"]
    runtime.engine.run.assert_not_called()
    runtime.netlogon.assert_not_called()
    runtime.engine.ensure_dns_installed.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        ("child", "east.example.test", None, "Child"),
        ("tree", "partner.test", _DOMAIN, "Tree"),
    ],
)
def test_child_and_tree_creation_pass_only_concrete_domain_and_credential_fields(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    case: tuple[str, str, str | None, str],
) -> None:
    domain_type, dns_name, parent, new_domain = case
    code, result = run_request(
        "domain_child",
        dict(
            _CHILD_ARGS,
            domain_type=domain_type,
            dns_domain_name=dns_name,
            parent_domain_name=parent,
            site_name="Example-Site",
            replication_source_dc="dc01.example.test",
        ),
    )
    assert code == 0 and result["changed"]
    settings = runtime.engine.run.call_args[0][0]
    assert (
        settings["NewDomain"] == new_domain and settings["NewDomainDNSName"] == dns_name
    )
    assert settings["ParentDomainDNSName"] == _DOMAIN
    assert (settings.get("ChildName") == "east") is (domain_type == "child")
    assert settings["UserName"] == "administrator" and settings["UserDomain"] == _DOMAIN
    assert (
        settings["Password"] == _PASSWORD and settings["SafeModeAdminPassword"] == _SAFE
    )
    assert settings["SiteName"] == "Example-Site" and "InstallDNS" not in settings


@pytest.mark.parametrize(
    "module_name,arguments",
    [("domain_child", _CHILD_ARGS), ("domain_controller", _CONTROLLER_ARGS)],
)
def test_controller_for_a_different_domain_fails_before_engine_access(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    module_name: str,
    arguments: dict[str, Any],
) -> None:
    runtime.current.return_value.update(role=4, domain="other.test")
    code, result = run_request(module_name, arguments)
    assert code == 1 and not result["changed"] and "domain" in result["msg"]
    runtime.engine_factory.assert_not_called()


@pytest.mark.parametrize(
    "module_name,arguments",
    [("domain_child", _CHILD_ARGS), ("domain_controller", _CONTROLLER_ARGS)],
)
def test_existing_matching_controller_does_not_reapply_creation_only_options(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    module_name: str,
    arguments: dict[str, Any],
) -> None:
    runtime.current.return_value.update(
        role=4, domain=arguments["dns_domain_name"].upper()
    )
    code, result = run_request(module_name, arguments)
    assert code == 0 and not result["changed"] and not result["reboot_required"]
    runtime.engine_factory.assert_not_called()


def test_replica_promotion_uses_readonly_media_and_replication_options_when_available(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    code, result = run_request(
        "domain_controller",
        dict(
            _CONTROLLER_ARGS,
            read_only=True,
            site_name="Example-Site",
            install_media_path=r"D:\Media",
            domain_log_path=r"D:\Logs",
            replication_source_dc="dc01.example.test",
            install_dns=True,
        ),
    )
    assert code == 0 and result["changed"]
    settings = runtime.engine.run.call_args[0][0]
    assert settings["ReplicaOrNewDomain"] == "ReadOnlyReplica"
    assert (
        settings["ReplicaDomainDNSName"] == _DOMAIN
        and settings["ReplicationSourcePath"] == r"D:\Media"
    )
    assert settings["SiteName"] == "Example-Site" and settings["InstallDNS"] == "Yes"
    assert settings["LogPath"] == r"D:\Logs"


def test_demoting_a_noncontroller_is_idempotent_without_feature_or_directory_queries(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    assert run_request(
        "domain_controller",
        dict(_CONTROLLER_ARGS, state="member_server", local_admin_password=_LOCAL),
    ) == (0, {"changed": False, "reboot_required": False, "_do_action_reboot": False})
    runtime.engine_factory.assert_not_called()
    runtime.roles.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_demotion_refuses_operation_master_roles_even_in_check_mode(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    check: bool,
) -> None:
    runtime.current.return_value.update(role=4, domain=_DOMAIN)
    runtime.roles.return_value = ["PDCEmulator", "RIDMaster"]
    code, result = run_request(
        "domain_controller",
        dict(
            _CONTROLLER_ARGS,
            state="member_server",
            local_admin_password=_LOCAL,
            _ansible_check_mode=check,
        ),
    )
    assert (
        code == 1
        and not result["changed"]
        and "PDCEmulator, RIDMaster" in result["msg"]
    )
    runtime.roles.assert_called_once_with("Server")
    runtime.engine_factory.assert_not_called()


def test_demotion_preserves_domain_credentials_and_protects_against_last_domain_removal(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    runtime.current.return_value.update(role=4, domain=_DOMAIN)
    code, result = run_request(
        "domain_controller",
        dict(
            _CONTROLLER_ARGS,
            state="member_server",
            domain_admin_user=r"EXAMPLE\administrator",
            local_admin_password=_LOCAL,
        ),
    )
    assert code == 0 and result["changed"] and result["reboot_required"]
    runtime.engine_factory.assert_called_once_with(demotion=True)
    settings = runtime.engine.run.call_args[0][0]
    assert (
        settings["AdministratorPassword"] == _LOCAL
        and settings["IsLastDCInDomain"] == "No"
    )
    assert (
        settings["UserName"] == "administrator" and settings["UserDomain"] == "EXAMPLE"
    )


@pytest.mark.parametrize("code", [1, 2, 3, 4, 15, 19, 65])
def test_native_exit_codes_preserve_reboot_recovery_failure_and_secret_redaction(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    code: int,
) -> None:
    runtime.engine.run.return_value = (code, "Diagnostic " + _SAFE)
    status, result = run_request(
        "domain", dict(_DOMAIN_ARGS, _ansible_inject_invocation=True)
    )
    assert _SAFE not in json.dumps(result)
    assert status == int(code not in (1, 2, 3, 4))
    assert result["changed"] is (code in (1, 2, 3, 4))
    assert result["reboot_required"] is (code in (1, 2, 3, 4, 15, 19))
    assert result["_do_action_reboot"] is (code in (15, 19))
    assert bool(result.get("warnings")) is (code in (3, 4))
    assert runtime.netlogon.call_count == int(code in (1, 2, 3, 4))


def test_netlogon_failure_is_a_warning_after_successful_promotion(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    runtime.netlogon.side_effect = OSError("Denied " + _SAFE)
    code, result = run_request("domain", _DOMAIN_ARGS)
    assert code == 0 and result["changed"] and result["reboot_required"]
    assert "manual reboot" in result["warnings"][0] and _SAFE not in json.dumps(result)


@pytest.mark.parametrize("completed", [False, True])
def test_engine_failure_preserves_known_role_change_and_redacts_secrets(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    completed: bool,
) -> None:
    error = OSError("Native runner or owned cleanup failed " + _SAFE)
    if completed:
        error.promotion_completed = True  # type: ignore[attr-defined]
    runtime.engine.run.side_effect = error
    code, result = run_request("domain", _DOMAIN_ARGS)
    assert code == 1 and result["failed"] is True
    assert result["changed"] is completed
    assert result["reboot_required"] is completed
    assert _SAFE not in json.dumps(result)
    runtime.netlogon.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        dict(_DOMAIN_ARGS, forest_mode="Win2025"),
        dict(_DOMAIN_ARGS, domain_mode="Win2003", forest_mode="Win2008"),
        dict(_DOMAIN_ARGS, domain_mode="Unknown"),
        dict(_DOMAIN_ARGS, safe_mode_password="secret\nInstallDNS=Yes"),
        dict(_DOMAIN_ARGS, safe_mode_password="*"),
    ],
)
def test_unsupported_or_unrepresentable_requests_fail_before_role_changes(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    arguments: dict[str, Any],
) -> None:
    code, result = run_request("domain", arguments)
    assert code == 1 and not result["changed"]
    runtime.engine.run.assert_not_called()
    runtime.netlogon.assert_not_called()


def test_unicode_password_reaches_the_native_engine_without_loss(
    run_request: Callable[..., Any], runtime: SimpleNamespace
) -> None:
    password = _SAFE + "é中"
    code, result = run_request(
        "domain", dict(_DOMAIN_ARGS, safe_mode_password=password)
    )
    assert code == 0 and result["changed"] and result["reboot_required"]
    assert runtime.engine.run.call_args[0][0]["SafeModeAdminPassword"] == password
    assert password not in json.dumps(result)


def test_legacy_unicode_database_path_fails_before_role_changes(
    run_request: Callable[..., Any], runtime: SimpleNamespace
) -> None:
    runtime.engine.legacy_answer_format = True
    code, result = run_request(
        "domain", dict(_DOMAIN_ARGS, database_path=r"C:\AD-é中\NTDS")
    )
    assert code == 1 and not result["changed"]
    assert "database_path" in result["msg"]
    runtime.engine.run.assert_not_called()
    runtime.netlogon.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        ("domain_child", dict(_CHILD_ARGS, domain_type="CHILD"), "NewDomain", "Child"),
        (
            "domain_controller",
            dict(_CONTROLLER_ARGS, state="DOMAIN_CONTROLLER"),
            "ReplicaOrNewDomain",
            "Replica",
        ),
    ],
)
def test_role_choices_are_case_insensitive(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    case: tuple[str, dict[str, Any], str, str],
) -> None:
    module_name, arguments, expected_field, expected_value = case
    code, result = run_request(module_name, arguments)
    assert code == 0 and result["changed"]
    assert runtime.engine.run.call_args[0][0][expected_field] == expected_value


@pytest.mark.parametrize(
    "module_name,arguments,fragment",
    [
        ("domain", {}, "dns_domain_name"),
        ("domain", dict(_DOMAIN_ARGS, domain_netbios_name="X" * 16), "15 characters"),
        (
            "domain_child",
            dict(_CHILD_ARGS, parent_domain_name=_DOMAIN),
            "must not be set",
        ),
        (
            "domain_child",
            dict(_CHILD_ARGS, domain_type="tree"),
            "parent_domain_name is required",
        ),
        ("domain_controller", dict(_CONTROLLER_ARGS, state="other"), "state must be"),
        (
            "domain_controller",
            dict(_CONTROLLER_ARGS, state="member_server"),
            "local_admin_password",
        ),
    ],
)
def test_invalid_options_fail_before_local_role_reads(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
    module_name: str,
    arguments: dict[str, Any],
    fragment: str,
) -> None:
    code, result = run_request(module_name, arguments)
    assert code == 1 and not result["changed"] and fragment in result["msg"]
    runtime.current.assert_not_called()
    runtime.active_controller.assert_not_called()


def test_replica_rejects_unqualified_credentials_before_native_engine_access(
    run_request: Callable[..., Any],
    runtime: SimpleNamespace,
) -> None:
    code, result = run_request(
        "domain_controller", dict(_CONTROLLER_ARGS, domain_admin_user="administrator")
    )
    assert code == 1 and not result["changed"] and "domain\\user" in result["msg"]
    runtime.engine_factory.assert_not_called()


@pytest.fixture(name="native_helper")
def native_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load native boundaries without initializing any Windows libraries.

    :param monkeypatch: Scoped target import paths.
    :returns: The unmodified promotion runner and native role readers.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_ad/plugins/module_utils/legacy_ad_domain_native.py",
        "tested_ad_domain_native",
    )


@pytest.mark.parametrize("forest", [False, True])
@pytest.mark.parametrize("already_complete", [False, True])
def test_native_postreboot_levels_use_documented_order_and_do_not_lower_or_repeat(
    native_helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    forest: bool,
    already_complete: bool,
) -> None:
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.naming_context.side_effect = [
        "DC=example,DC=test",
        "CN=Configuration,DC=example,DC=test",
    ]
    connection.search.side_effect = [
        [{"attributes": {"domainControllerFunctionality": [b"2"]}}],
        [
            {
                "attributes": {
                    "nTMixedDomain": [b"0" if already_complete else b"1"],
                    "msDS-Behavior-Version": [b"2" if already_complete else b"0"],
                }
            }
        ],
        [
            {
                "attributes": {
                    "msDS-Behavior-Version": [b"2" if already_complete else b"0"]
                }
            }
        ],
    ]
    monkeypatch.setattr(
        native_helper,
        "current_state",
        lambda: {"role": 5, "hostname": "LocalDC", "domain": _DOMAIN},
    )
    monkeypatch.setattr(native_helper, "LDAPConnection", Mock(return_value=connection))
    result = {"changed": False}
    native_helper.complete_legacy_levels(_DOMAIN, forest, result)
    assert result["changed"] is not already_complete
    expected = (
        []
        if already_complete
        else [
            call("DC=example,DC=test", [(2, "nTMixedDomain", [b"0"])]),
            call("DC=example,DC=test", [(2, "msDS-Behavior-Version", [b"2"])]),
        ]
    )
    if forest and not already_complete:
        expected.append(
            call(
                "CN=Partitions,CN=Configuration,DC=example,DC=test",
                [(2, "msDS-Behavior-Version", [b"2"])],
            )
        )
    assert connection.modify.call_args_list == expected


def test_native_postreboot_level_failure_retains_completed_transition(
    native_helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.naming_context.side_effect = [
        "DC=example,DC=test",
        "CN=Configuration,DC=example,DC=test",
    ]
    connection.search.side_effect = [
        [{"attributes": {"domainControllerFunctionality": [b"2"]}}],
        [{"attributes": {"nTMixedDomain": [b"1"], "msDS-Behavior-Version": [b"0"]}}],
    ]
    connection.modify.side_effect = [None, OSError("Domain-level write rejected")]
    monkeypatch.setattr(
        native_helper,
        "current_state",
        lambda: {"role": 5, "hostname": "LocalDC", "domain": _DOMAIN},
    )
    monkeypatch.setattr(native_helper, "LDAPConnection", Mock(return_value=connection))
    result = {"changed": False}
    with pytest.raises(OSError, match="Domain-level write rejected"):
        native_helper.complete_legacy_levels(_DOMAIN, True, result)
    assert result["changed"] is True
    assert connection.modify.call_count == 2


def test_native_role_reader_closes_wmi_and_returns_running_not_requested_role(
    native_helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.query.return_value = [
        {"Name": "LocalDC", "Domain": _DOMAIN, "DomainRole": 4}
    ]
    monkeypatch.setattr(native_helper, "WmiConnection", Mock(return_value=connection))
    assert native_helper.current_state() == {
        "hostname": "LocalDC",
        "domain": _DOMAIN,
        "role": 4,
    }
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize("code", [1355, 1908, 1722])
def test_native_forest_discovery_uses_gc_request_flags_and_reports_absence(
    native_helper: ModuleType, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    library = Mock()
    library.DsGetDcNameW.return_value = code
    monkeypatch.setattr(
        native_helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    assert native_helper.forest_exists(_DOMAIN) is False
    # DS_GC_FLAG=4 describes a returned controller; the request flag is 0x40.
    assert library.DsGetDcNameW.call_args.args[4] == 0x40020050
    library.NetApiBufferFree.assert_not_called()


@pytest.mark.parametrize("forest,exists", [(_DOMAIN, True), ("other.test", False)])
def test_native_forest_discovery_checks_identity_and_frees_the_result(
    native_helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    forest: str,
    exists: bool,
) -> None:
    library = Mock()
    information = native_helper._ControllerInformation()
    information.forest_name = forest

    def discover(*arguments: Any) -> int:
        """Supply one owned native controller-information allocation.

        :param arguments: Native controller lookup arguments.
        :returns: Successful native status.
        :rtype: int
        """
        arguments[-1]._obj.value = native_helper.ctypes.addressof(information)
        return 0

    library.DsGetDcNameW.side_effect = discover
    monkeypatch.setattr(
        native_helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    assert native_helper.forest_exists(_DOMAIN) is exists
    library.NetApiBufferFree.assert_called_once()


def test_functional_level_choices_come_from_engine_help_not_host_version(
    native_helper: ModuleType,
) -> None:
    engine = native_helper.PromotionEngine.__new__(native_helper.PromotionEngine)
    engine.help = "/DomainLevel:{0 | 2 | 3}\n/ForestLevel:{0 | 2}"
    assert engine.functional_level(None, "DomainLevel") == "3"
    assert engine.functional_level("Default", "ForestLevel") == "2"
    assert engine.functional_level("win2003", "ForestLevel") == "2"
    with pytest.raises(ValueError, match="does not support"):
        engine.functional_level("Win2008R2", "DomainLevel")


@pytest.mark.parametrize("demotion", [False, True])
def test_older_native_engine_does_not_launch_gui_help(
    native_helper: ModuleType, monkeypatch: pytest.MonkeyPatch, demotion: bool
) -> None:
    monkeypatch.setattr(native_helper, "_engine_path", lambda: "native-dcpromo.exe")
    monkeypatch.setattr(
        native_helper.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=5, minor=2),
        raising=False,
    )
    help_request = Mock(side_effect=AssertionError("GUI help must not be started"))
    monkeypatch.setattr(native_helper, "_help", help_request)
    engine = native_helper.PromotionEngine(demotion=demotion)
    assert engine.supports("AutoConfigDNS")
    assert engine.supports("RebootOnSuccess")
    assert not engine.supports("RebootOnCompletion")
    assert not engine.supports("DomainLevel")
    assert not engine.supports("ReadOnlyReplica")
    help_request.assert_not_called()


@pytest.mark.parametrize("demotion", [False, True])
def test_console_engine_still_uses_its_own_operation_help(
    native_helper: ModuleType, monkeypatch: pytest.MonkeyPatch, demotion: bool
) -> None:
    monkeypatch.setattr(native_helper, "_engine_path", lambda: "native-dcpromo.exe")
    monkeypatch.setattr(
        native_helper.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=6, minor=1),
        raising=False,
    )
    help_request = Mock(return_value="InstallDNS\nDomainLevel:{0|2|3|4}")
    monkeypatch.setattr(native_helper, "_help", help_request)
    engine = native_helper.PromotionEngine(demotion=demotion)
    assert engine.supports("InstallDNS")
    assert not engine.supports("AutoConfigDNS")
    assert engine.functional_level(None, "DomainLevel") == "4"
    help_request.assert_called_once_with(
        "native-dcpromo.exe", "Demotion" if demotion else "Promotion"
    )


@pytest.mark.parametrize("code", [1, 2, 3, 4, 15, 19, 65])
def test_native_runner_retains_exit_status_when_answer_cleanup_fails(
    native_helper: ModuleType, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    engine = native_helper.PromotionEngine.__new__(native_helper.PromotionEngine)
    engine.path, engine.help = "native-dcpromo.exe", "SafeModeAdminPassword"
    engine.legacy_answer_format = False
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value = (b"Completed", None)
    process.returncode = code
    start = Mock(return_value=process)
    monkeypatch.setattr(native_helper.subprocess, "Popen", start)

    @contextmanager
    def _answer(_settings: dict[str, str]) -> Any:
        yield "restricted-answer.ini"
        raise OSError("Owned answer cleanup failed")

    monkeypatch.setattr(native_helper, "_private_answer", _answer)
    with pytest.raises(OSError) as caught:
        engine.run({"SafeModeAdminPassword": _SAFE})
    assert bool(getattr(caught.value, "promotion_completed", False)) is (
        code in (1, 2, 3, 4)
    )
    assert start.call_args[0][0] == [
        "native-dcpromo.exe",
        "/answer:restricted-answer.ini",
    ]
    assert _SAFE not in json.dumps(start.call_args[0][0])
    process.__exit__.assert_called_once()


def test_operation_master_check_reads_this_exact_controller_and_all_five_owners(
    native_helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = (
        "CN=NTDS Settings,CN=LocalDC,CN=Servers,CN=Site,CN=Sites,CN=Configuration,"
        + _DOMAIN
    )
    other = (
        "CN=NTDS Settings,CN=OtherDC,CN=Servers,CN=Site,CN=Sites,CN=Configuration,"
        + _DOMAIN
    )
    domain = "DC=example,DC=test"
    configuration = "CN=Configuration," + domain
    schema = "CN=Schema," + configuration
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.naming_context.side_effect = lambda name="defaultNamingContext": {
        "defaultNamingContext": domain,
        "configurationNamingContext": configuration,
        "schemaNamingContext": schema,
    }[name]
    connection.search.side_effect = [
        [{"attributes": {"dsServiceName": [local.encode()]}}],
        [{"attributes": {"fSMORoleOwner": [local.upper().encode()]}}],
        [{"attributes": {"fSMORoleOwner": [other.encode()]}}],
        [{"attributes": {"fSMORoleOwner": [other.encode()]}}],
        [{"attributes": {"fSMORoleOwner": [local.encode()]}}],
        [{"attributes": {"fSMORoleOwner": [other.encode()]}}],
    ]
    create = Mock(return_value=connection)
    monkeypatch.setattr(native_helper, "LDAPConnection", create)
    assert native_helper.assigned_roles("LocalDC") == ["PDCEmulator", "SchemaMaster"]
    create.assert_called_once_with("LocalDC")
    assert [call.args[0] for call in connection.search.call_args_list] == [
        "",
        domain,
        "CN=RID Manager$,CN=System," + domain,
        "CN=Infrastructure," + domain,
        schema,
        "CN=Partitions," + configuration,
    ]
    connection.__exit__.assert_called_once()


def test_installation_media_remains_in_the_restricted_native_answer(
    native_helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = native_helper.PromotionEngine.__new__(native_helper.PromotionEngine)
    engine.path, engine.help = "native-dcpromo.exe", "ReplicationSourcePath"
    engine.legacy_answer_format = False
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value, process.returncode = (b"Completed", None), 2
    start = Mock(return_value=process)
    monkeypatch.setattr(native_helper.subprocess, "Popen", start)

    @contextmanager
    def _answer(settings: dict[str, str]) -> Any:
        assert settings == {"ReplicationSourcePath": r"D:\Media"}
        yield "restricted-answer.ini"

    monkeypatch.setattr(native_helper, "_private_answer", _answer)
    assert engine.run({"ReplicationSourcePath": r"D:\Media"}) == (2, "Completed")
    assert start.call_args[0][0] == [
        "native-dcpromo.exe",
        "/answer:restricted-answer.ini",
    ]
