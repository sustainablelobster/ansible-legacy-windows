"""Verify released choice and Int32 contracts before native AD operations."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Public payload and action boundary tests intentionally inspect owned internals.
# pylint: disable=protected-access
# Separate pytest inputs describe the public requests without hiding their fields.
# pylint: disable=too-many-arguments,too-many-positional-arguments

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest
from ansible_collections.sustainablelobster.legacy_ad.plugins.action.membership import (
    ActionModule,
)

from tests.unit.payload_support import ROOT, invoke_payload, load_module
from tests.unit.test_python_action import _action

_INVALID = [
    True,
    False,
    42.0,
    1.2,
    float("inf"),
    "1_0",
    "42.0",
    "0x10",
    "٤٢",
    "\u00a042\u00a0",
    "\u200342\u2003",
    2147483648,
    -2147483649,
    "",
    None,
]


@pytest.fixture(name="helpers")
def _helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))


@pytest.mark.usefixtures("helpers")
@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0),
        (42, 42),
        (-2147483648, -2147483648),
        (2147483647, 2147483647),
        (" +42 ", 42),
        ("\t-42\r\n", -42),
        ("00042", 42),
        ("42\0", 42),
    ],
)
def test_decimal_int32_accepts_upstream_values(value: Any, expected: int) -> None:
    helper = importlib.import_module("legacy_ad_arguments")
    assert helper.as_int32(value, "option") == expected


@pytest.mark.usefixtures("helpers")
@pytest.mark.parametrize("value", _INVALID)
def test_decimal_int32_rejects_non_integer_json_and_python_extensions(
    value: Any,
) -> None:
    helper = importlib.import_module("legacy_ad_arguments")
    with pytest.raises(ValueError, match="option must"):
        helper.as_int32(value, "option")


@pytest.mark.usefixtures("helpers")
@pytest.mark.parametrize(
    "module_name, option, base",
    [
        ("pso", "precedence", {"name": "Policy"}),
        ("pso", "min_password_length", {"name": "Policy", "precedence": 1}),
        ("pso", "lockout_threshold", {"name": "Policy", "precedence": 1}),
        ("gpo", "order", {"name": "Policy", "target": "DC=example,DC=test"}),
        ("site_link", "cost", {"name": "Link"}),
        ("site_link", "replication_frequency", {"name": "Link"}),
        ("cs_template", "key_size", {"name": "Template"}),
        ("cs_template", "validity_period_days", {"name": "Template"}),
        ("cs_template", "renewal_period_days", {"name": "Template"}),
        ("cs_template", "schema_version", {"name": "Template"}),
        (
            "membership",
            "reboot_timeout",
            {"state": "domain", "offline_join_blob": "AA=="},
        ),
    ],
)
@pytest.mark.parametrize("value", [True, 42.0, 1.2, "1_0", "0x10", "٤٢", 2147483648])
def test_public_integer_requests_fail_before_native_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    module_name: str,
    option: str,
    base: dict[str, Any],
    value: Any,
) -> None:
    module = load_module(
        ROOT / "legacy_ad/plugins/modules" / (module_name + ".py"),
        "argument_contract_" + module_name,
    )
    native = Mock(side_effect=AssertionError("Invalid request reached Windows."))
    for helper_name in (
        "legacy_ad_policy_pso",
        "legacy_ad_policy_gpo",
        "legacy_ad_topology",
        "legacy_ad_cs_template",
        "legacy_ad_membership",
    ):
        helper = sys.modules.get(helper_name)
        if helper is not None:
            for boundary in ("DirectorySession", "LDAPConnection", "current_state"):
                if hasattr(helper, boundary):
                    monkeypatch.setattr(helper, boundary, native)
    request = tmp_path / "arguments.json"
    request.write_text(json.dumps(dict(base, **{option: value})), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(module.__file__), str(request)])
    status, result = invoke_payload(module, capsys)
    assert status == 1 and result["failed"] is True
    assert option + " must" in result["msg"]
    native.assert_not_called()


@pytest.mark.usefixtures("helpers")
@pytest.mark.parametrize(
    "module_name, raw, error",
    [
        ("gpo", {"name": "Policy", "target": "DN", "state": ""}, "state must"),
        ("cs_template", {"name": "Template", "state": ""}, "state must"),
        ("domain_trust", {"name": "peer.test", "state": ""}, "state must"),
        (
            "site_link",
            {"name": "Link", "intersite_transport_protocol": ""},
            "intersite_transport_protocol must",
        ),
    ],
)
def test_empty_choices_fail_instead_of_becoming_defaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    module_name: str,
    raw: dict[str, Any],
    error: str,
) -> None:
    module = load_module(
        ROOT / "legacy_ad/plugins/modules" / (module_name + ".py"),
        "empty_choice_" + module_name,
    )
    request = tmp_path / "arguments.json"
    request.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(module.__file__), str(request)])
    status, result = invoke_payload(module, capsys)
    assert status == 1 and result["failed"] is True and error in result["msg"]


@pytest.mark.usefixtures("helpers")
def test_choice_normalizers_accept_mixed_case_and_preserve_nonchoices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trust = importlib.import_module("legacy_ad_trust")
    raw = dict.fromkeys(trust.PARAMETERS)
    raw.update(
        name="UPPER.example",
        state="PRESENT",
        direction="BiDiReCtIoNaL",
        type="FOREST",
        trust_password="KeepCASE",
    )
    monkeypatch.setattr(trust, "read_arguments", lambda *_: raw.copy())
    arguments = trust.trust_arguments()
    assert arguments["state"] == "present" and arguments["direction"] == "bidirectional"
    assert arguments["type"] == "forest" and arguments["trust_password"] == "KeepCASE"
    assert arguments["name"] == "UPPER.example"

    topology = importlib.import_module("legacy_ad_topology")
    monkeypatch.setattr(
        topology,
        "object_arguments",
        lambda *_: {
            "intersite_transport_protocol": "sMtP",
            "cost": " +42 ",
            "replication_frequency": None,
            "sites_included": None,
        },
    )
    link = topology.topology_arguments("site_link")
    assert link["intersite_transport_protocol"] == "SMTP" and link["cost"] == 42

    gpo = importlib.import_module("legacy_ad_policy_gpo")
    assert (
        gpo.parameters(
            {"name": "KeepCASE", "target": "DN", "state": "ABSENT", "order": " +42 "}
        )["state"]
        == "absent"
    )
    template = importlib.import_module("legacy_ad_cs_template")
    monkeypatch.setattr(
        template,
        "read_arguments",
        lambda *_: {
            "name": "KeepCASE",
            "state": "ABSENT",
            "key_size": "2048",
        },
    )
    options = template.template_arguments()
    assert options["state"] == "absent" and options["key_size"] == 2048
    assert options["name"] == "KeepCASE"
    # Stored template flags intentionally use a different hexadecimal parser.
    assert template._int32("0x80000000", "flag") == -2147483648


@pytest.mark.usefixtures("helpers")
def test_group_choices_are_normalized_before_opening_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group = importlib.import_module("legacy_ad_group")
    boundary = Mock(side_effect=RuntimeError("directory boundary"))
    monkeypatch.setattr(group, "DirectorySession", boundary)
    arguments = {"scope": "GLOBAL", "category": "SECURITY"}
    with pytest.raises(RuntimeError, match="directory boundary"):
        group.manage_group(arguments, {})
    assert arguments == {"scope": "global", "category": "security"}
    boundary.assert_called_once_with(arguments)


@pytest.mark.usefixtures("helpers")
def test_membership_and_object_info_normalize_public_choices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    membership = load_module(
        ROOT / "legacy_ad/plugins/modules/membership.py", "choice_membership"
    )
    options = membership._parameters(
        {
            "state": "WORKGROUP",
            "workgroup_name": "KeepCASE",
            "domain_admin_user": "User",
            "domain_admin_password": "KeepCASE",
        }
    )
    assert options["state"] == "workgroup" and options["workgroup_name"] == "KeepCASE"
    info = load_module(ROOT / "legacy_ad/plugins/modules/object_info.py", "choice_info")
    monkeypatch.setattr(
        info,
        "read_arguments",
        lambda *_: {"ldap_filter": "(objectClass=*)", "search_scope": "BASE"},
    )
    assert info._arguments()["search_scope"] == "base"


@pytest.mark.parametrize("value", [True, 42.0, "1_0", "0x10", "٤٢", 2147483648])
def test_reboot_action_rejects_invalid_timeout_before_staging(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    action, _, events = _action(ActionModule, monkeypatch)
    action._task.args = {"reboot_timeout": value}
    with pytest.raises(ValueError, match="reboot_timeout must"):
        action.run()
    assert not events


@pytest.mark.parametrize(
    "name",
    [
        "site",
        "site_link",
        "site_subnet",
        "pso",
        "gpo",
        "cs_template",
        "membership",
    ],
)
def test_dependent_actions_stage_public_integer_helper_once(name: str) -> None:
    action: ModuleType = importlib.import_module(
        "ansible_collections.sustainablelobster.legacy_ad.plugins.action." + name
    )
    helpers = [path.name for path in action.ActionModule.COLLECTION_MODULE_UTILS]
    assert helpers.count("legacy_ad_arguments.py") == 1
