"""Exercise public AD FS contracts against independently observed vendor state."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests substitute only vendor commands and observe state, not payload decisions.
# pylint: disable=protected-access

import copy
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from ansible.plugins.loader import action_loader  # type: ignore[import-untyped]

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module
from tests.unit.test_python_action import _action

AD = ROOT / "legacy_ad/plugins"


# This boundary fixture has one command entry point; adding an unused public
# method would obscure the observed state behind a testing-only interface.
class Vendor:  # pylint: disable=too-few-public-methods
    """Record commands and expose independent persisted trust observations."""

    def __init__(self) -> None:
        properties = [
            "MonitoringEnabled",
            "AutoUpdateEnabled",
            "TokenLifetime",
            "Notes",
            "AccessControlPolicyName",
            "SignatureAlgorithm",
            "EncryptClaims",
        ]
        self.commands = {
            "Add-AdfsRelyingPartyTrust": properties
            + [
                "Name",
                "Identifier",
                "MetadataUrl",
                "MetadataFile",
                "WSFedEndpoint",
                "SamlEndpoint",
                "Enabled",
                "Confirm",
            ],
            "Set-AdfsRelyingPartyTrust": properties
            + ["TargetName", "IssuanceTransformRules", "IssuanceAuthorizationRules"],
            "Enable-AdfsRelyingPartyTrust": ["TargetName"],
            "Disable-AdfsRelyingPartyTrust": ["TargetName"],
            "Remove-AdfsRelyingPartyTrust": ["TargetName", "Confirm"],
            "New-AdfsSamlEndpoint": ["Binding", "Protocol", "Uri"],
        }
        self.trust: dict[str, Any] | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_on: str | None = None

    def run(self, operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Persist vendor writes, allowing an independently injected failure.

        :param operation: Requested vendor command boundary.
        :param parameters: Data-only command parameters.
        :returns: Copied persisted observations, not predicted module results.
        :raises OSError: When the requested operation is the injected failure.
        """
        self.calls.append((operation, copy.deepcopy(parameters)))
        if operation == self.fail_on:
            raise OSError("vendor failure")
        if operation == "inspect":
            return {
                "trust": copy.deepcopy(self.trust),
                "commands": copy.deepcopy(self.commands),
            }
        if operation == "create":
            self.trust = {
                "Identifier": ["https://metadata.example/"],
                "Enabled": True,
                "MonitoringEnabled": False,
                "AutoUpdateEnabled": False,
                "TokenLifetime": 60,
                "Notes": "",
                "EncryptClaims": True,
                "AccessControlPolicyName": None,
                "SignatureAlgorithm": "",
                "IssuanceTransformRules": "",
                "IssuanceAuthorizationRules": "",
            }
            self.trust.update(parameters)
            self.trust.pop("Name", None)
        elif operation == "update":
            assert self.trust is not None
            self.trust.update(
                {key: value for key, value in parameters.items() if key != "TargetName"}
            )
        elif operation in ("enable", "disable"):
            assert self.trust is not None
            self.trust["Enabled"] = operation == "enable"
        elif operation == "remove":
            self.trust = None
        else:
            assert operation == "probe_metadata"
        return {}


@pytest.fixture(name="vendor")
def vendor_fixture(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Vendor]:
    """Load the actual helper while substituting only its vendor command boundary.

    :param monkeypatch: Scoped module import and subprocess substitutes.
    :returns: Actual Python helper and independent vendor state.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(AD / "module_utils"))
    helper = load_module(AD / "module_utils/legacy_ad_adfs.py", "tested_adfs_helper")
    native = Vendor()
    monkeypatch.setattr(helper, "run_vendor", native.run)
    monkeypatch.setitem(sys.modules, "legacy_ad_adfs", helper)
    return helper, native


def _run(
    name: str,
    arguments: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, Any]]:
    argument_file = tmp_path / "arguments.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [name + ".py", str(argument_file)])
    payload = load_module(AD / "modules" / (name + ".py"), "tested_" + name)
    return invoke_payload(payload, capsys)


def test_trust_accepts_upstream_case_insensitive_choices(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, state = vendor
    inputs = {
        "name": "Owned",
        "state": "PrEsEnT",
        "identifier": ["https://owned.example/"],
        "signature_algorithm": "RSA_SHA256",
    }
    assert _run("fs_trust", inputs, tmp_path, monkeypatch, capsys)[0] == 0
    assert state.trust is not None
    assert state.trust["SignatureAlgorithm"].endswith("rsa-sha256")
    assert not _run("fs_trust", inputs, tmp_path, monkeypatch, capsys)[1]["changed"]
    status, removed = _run(
        "fs_trust", {"name": "Owned", "state": "ABSENT"}, tmp_path, monkeypatch, capsys
    )
    assert status == 0 and removed["changed"] and state.trust is None


def test_claim_rules_accept_upstream_case_insensitive_choices(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, state = vendor
    assert (
        _run(
            "fs_trust",
            {"name": "Owned", "identifier": ["https://owned.example/"]},
            tmp_path,
            monkeypatch,
            capsys,
        )[0]
        == 0
    )
    for update, rule in (("SeT", "first ;"), ("APPEND", "second ;")):
        inputs = {
            "name": "Owned",
            "state": "PRESENT",
            "transform_rules": {"value": [rule], "update": update},
        }
        status, changed = _run("fs_claim_rule", inputs, tmp_path, monkeypatch, capsys)
        assert status == 0 and changed["changed"]
        assert not _run("fs_claim_rule", inputs, tmp_path, monkeypatch, capsys)[1][
            "changed"
        ]
    assert state.trust is not None
    assert state.trust["IssuanceTransformRules"] == "first ;\nsecond ;"
    status, cleared = _run(
        "fs_claim_rule",
        {"name": "Owned", "state": "AbSeNt"},
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert status == 0 and cleared["changed"]
    assert state.trust["IssuanceTransformRules"] == ""


@pytest.mark.parametrize(
    "value",
    [
        True,
        1.2,
        42.0,
        "1_0",
        "42.0",
        "٤٢",
        "\u00a042\u00a0",
        "\u200342\u2003",
        2**31,
        -(2**31) - 1,
    ],
)
def test_token_lifetime_rejects_invalid_upstream_integers_before_vendor_access(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: Any,
) -> None:
    _, state = vendor
    status, result = _run(
        "fs_trust",
        {
            "name": "Owned",
            "identifier": ["https://owned.example/"],
            "token_lifetime": value,
        },
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert status == 1 and not result["changed"]
    assert "token_lifetime" in result["msg"] and state.calls == []


@pytest.mark.parametrize(
    "case", [(42, 42), (" +42 ", 42), ("-42", -42), ("\t42\r\n", 42), ("42\0", 42)]
)
def test_token_lifetime_preserves_signed_upstream_integer_conversion(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[Any, int],
) -> None:
    _, state = vendor
    value, expected = case
    status, _ = _run(
        "fs_trust",
        {
            "name": "Owned",
            "identifier": ["https://owned.example/"],
            "token_lifetime": value,
        },
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert status == 0 and state.trust is not None
    assert state.trust["TokenLifetime"] == expected


def test_trust_create_repeat_preview_options_delete(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, state = vendor
    request = {
        "name": "Owned",
        "identifier": ["https://owned.example/"],
        "enabled": False,
        "notes": "Original",
        "token_lifetime": "42",
        "signature_algorithm": "rsa_sha256",
    }
    status, preview = _run(
        "fs_trust",
        dict(request, _ansible_check_mode=True),
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert status == 0 and preview == {
        "changed": True,
        "identifier": [],
        "enabled": None,
        "monitoring_enabled": None,
    }
    assert state.run("inspect", {"Name": "Owned"})["trust"] is None
    status, created = _run("fs_trust", request, tmp_path, monkeypatch, capsys)
    assert (
        status == 0
        and created["changed"]
        and created["identifier"] == request["identifier"]
    )
    assert created["enabled"] is False
    assert state.trust is not None and state.trust["TokenLifetime"] == 42
    assert state.trust["SignatureAlgorithm"].endswith("rsa-sha256")
    assert not _run("fs_trust", request, tmp_path, monkeypatch, capsys)[1]["changed"]
    updated = dict(request, enabled=True, notes="Changed")
    status, update_preview = _run(
        "fs_trust",
        dict(updated, _ansible_check_mode=True),
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert status == 0 and update_preview["changed"] and not update_preview["enabled"]
    assert state.trust["Notes"] == "Original"
    assert _run("fs_trust", updated, tmp_path, monkeypatch, capsys)[1]["enabled"]
    assert not _run("fs_trust", updated, tmp_path, monkeypatch, capsys)[1]["changed"]
    assert _run(
        "fs_trust",
        {"name": "Owned", "state": "absent", "_ansible_check_mode": True},
        tmp_path,
        monkeypatch,
        capsys,
    )[1]["changed"]
    assert state.trust is not None
    assert _run(
        "fs_trust", {"name": "Owned", "state": "absent"}, tmp_path, monkeypatch, capsys
    )[1]["changed"]
    assert state.run("inspect", {"Name": "Owned"})["trust"] is None
    assert not _run(
        "fs_trust", {"name": "Owned", "state": "absent"}, tmp_path, monkeypatch, capsys
    )[1]["changed"]


def test_creation_only_identifier_and_endpoints_are_not_reconciled(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, state = vendor
    request = {
        "name": "Owned",
        "identifier": ["https://first.example/"],
        "saml_endpoint": ["https://first.example/acs"],
    }
    assert _run("fs_trust", request, tmp_path, monkeypatch, capsys)[0] == 0
    status, response = _run(
        "fs_trust",
        dict(
            request,
            identifier=["https://other.example/"],
            saml_endpoint=["https://other.example/acs"],
        ),
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert (
        status == 0
        and not response["changed"]
        and response["identifier"] == request["identifier"]
    )
    assert state.calls[-1][0] == "inspect"


def test_absent_trust_preserves_the_upstream_initialized_return_envelope(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, state = vendor
    absent = {"name": "Owned", "state": "absent"}
    status, result = _run("fs_trust", absent, tmp_path, monkeypatch, capsys)
    assert status == 0 and result == {
        "changed": False,
        "identifier": [],
        "enabled": None,
        "monitoring_enabled": None,
    }
    _run(
        "fs_trust",
        {"name": "Owned", "identifier": ["https://owned.example/"]},
        tmp_path,
        monkeypatch,
        capsys,
    )
    status, result = _run("fs_trust", absent, tmp_path, monkeypatch, capsys)
    assert status == 0 and result == {
        "changed": True,
        "identifier": [],
        "enabled": None,
        "monitoring_enabled": None,
    }
    assert state.trust is None


@pytest.mark.parametrize("check", [False, True])
def test_missing_optional_capability_rejects_before_any_write(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    check: bool,
) -> None:
    _, state = vendor
    state.commands["Add-AdfsRelyingPartyTrust"].remove("AccessControlPolicyName")
    request = {
        "name": "Owned",
        "identifier": ["https://owned.example/"],
        "access_control_policy_name": "Permit everyone",
        "_ansible_check_mode": check,
    }
    status, result = _run("fs_trust", request, tmp_path, monkeypatch, capsys)
    assert (
        status == 1
        and not result["changed"]
        and "AccessControlPolicyName" in result["msg"]
    )
    assert [op for op, _ in state.calls] == ["inspect"]
    del request["access_control_policy_name"]
    assert _run("fs_trust", request, tmp_path, monkeypatch, capsys)[0] == 0


@pytest.mark.parametrize("operation", ["create", "update", "enable", "remove"])
def test_vendor_failure_retains_attempted_write_state(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
) -> None:
    _, state = vendor
    request: dict[str, Any] = {
        "name": "Owned",
        "identifier": ["https://owned.example/"],
    }
    if operation != "create":
        assert (
            _run(
                "fs_trust", dict(request, enabled=False), tmp_path, monkeypatch, capsys
            )[0]
            == 0
        )
    if operation == "update":
        request["notes"] = "new"
    elif operation == "enable":
        request["enabled"] = True
    elif operation == "remove":
        request["state"] = "absent"
    state.fail_on = operation
    status, result = _run("fs_trust", request, tmp_path, monkeypatch, capsys)
    assert status == 1 and result["changed"] and "vendor failure" in result["msg"]


@pytest.mark.parametrize("source", ["metadata_url", "metadata_file"])
def test_metadata_creation_and_preview_are_qualified_before_mutation(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    source: str,
) -> None:
    _, state = vendor
    request = {
        "name": "Owned",
        source: (
            "https://metadata.example/"
            if source == "metadata_url"
            else str(tmp_path / "metadata.xml")
        ),
    }
    if source == "metadata_file":
        status, response = _run("fs_trust", request, tmp_path, monkeypatch, capsys)
        assert (
            status == 1
            and not response["changed"]
            and "Metadata file not found" in response["msg"]
        )
        (tmp_path / "metadata.xml").write_text("fixture", encoding="utf-8")
    else:
        state.fail_on = "probe_metadata"
        status, response = _run("fs_trust", request, tmp_path, monkeypatch, capsys)
        assert (
            status == 1
            and not response["changed"]
            and "Cannot reach metadata URL" in response["msg"]
        )
        state.fail_on = None
    assert (
        _run(
            "fs_trust",
            dict(request, _ansible_check_mode=True),
            tmp_path,
            monkeypatch,
            capsys,
        )[0]
        == 0
    )
    assert state.trust is None
    assert _run("fs_trust", request, tmp_path, monkeypatch, capsys)[0] == 0


def test_claim_rule_set_append_clear_diff_and_preview(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, state = vendor
    assert (
        _run(
            "fs_trust",
            {"name": "Owned", "identifier": ["https://owned.example/"]},
            tmp_path,
            monkeypatch,
            capsys,
        )[0]
        == 0
    )
    request = {"name": "Owned", "transform_rules": {"value": ["first ;", "second ;"]}}
    status, preview = _run(
        "fs_claim_rule",
        dict(request, _ansible_check_mode=True),
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert (
        status == 0
        and preview["changed"]
        and preview["transform_rules"] == "first ;\nsecond ;"
    )
    assert preview["diff"] == {
        "before": {"transform_rules": ""},
        "after": {"transform_rules": "first ;\nsecond ;"},
    }
    assert state.trust is not None and state.trust["IssuanceTransformRules"] == ""
    assert _run("fs_claim_rule", request, tmp_path, monkeypatch, capsys)[1]["changed"]
    assert not _run("fs_claim_rule", request, tmp_path, monkeypatch, capsys)[1][
        "changed"
    ]
    request["transform_rules"] = {"value": ["third ;"], "update": "append"}
    response = _run("fs_claim_rule", request, tmp_path, monkeypatch, capsys)[1]
    assert response["transform_rules"] == "first ;\nsecond ;\nthird ;"
    assert not _run("fs_claim_rule", request, tmp_path, monkeypatch, capsys)[1][
        "changed"
    ]
    request["transform_rules"] = {"value": [" FIRST  ; second ; third ; "]}
    assert not _run("fs_claim_rule", request, tmp_path, monkeypatch, capsys)[1][
        "changed"
    ]
    status, response = _run(
        "fs_claim_rule",
        {"name": "Owned", "state": "absent"},
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert (
        status == 0
        and response["changed"]
        and response["transform_rules"] == response["authorization_rules"] == ""
    )
    assert not _run(
        "fs_claim_rule",
        {"name": "Owned", "state": "absent"},
        tmp_path,
        monkeypatch,
        capsys,
    )[1]["changed"]


def test_missing_trust_and_vendor_rule_failure_are_public_json(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, state = vendor
    request = {"name": "Owned", "authorization_rules": {"value": ["bad syntax"]}}
    status, response = _run("fs_claim_rule", request, tmp_path, monkeypatch, capsys)
    assert status == 1 and not response["changed"] and "not found" in response["msg"]
    _run(
        "fs_trust",
        {"name": "Owned", "identifier": ["https://owned.example/"]},
        tmp_path,
        monkeypatch,
        capsys,
    )
    state.fail_on = "update"
    status, response = _run("fs_claim_rule", request, tmp_path, monkeypatch, capsys)
    assert (
        status == 1
        and response["changed"]
        and "Failed to set claim rules" in response["msg"]
    )
    assert state.trust is not None and state.trust["IssuanceAuthorizationRules"] == ""


@pytest.mark.parametrize(
    "sources",
    [
        {"metadata_url": None, "identifier": ["https://review.invalid/"]},
        {"metadata_file": None, "identifier": ["https://review.invalid/"]},
        {"identifier": None, "metadata_url": "https://review.invalid/metadata"},
        {"identifier": None, "metadata_file": "owned-metadata.xml"},
        {"metadata_url": None, "metadata_file": "owned-metadata.xml"},
        {"metadata_file": None, "metadata_url": "https://review.invalid/metadata"},
        {"metadata_url": None, "metadata_file": None, "state": "absent"},
    ],
)
def test_supplied_null_creation_sources_remain_mutually_exclusive(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sources: dict[str, Any],
) -> None:
    _, state = vendor
    status, result = _run(
        "fs_trust", dict(sources, name="Review"), tmp_path, monkeypatch, capsys
    )
    assert status == 1 and result["failed"] and not result["changed"]
    assert "mutually exclusive" in result["msg"]
    assert state.calls == [] and state.trust is None


@pytest.mark.parametrize(
    "module,inputs",
    [
        ("fs_trust", {}),
        ("fs_trust", {"name": "Owned"}),
        (
            "fs_trust",
            {"name": "Owned", "identifier": [], "metadata_url": "https://other/"},
        ),
        ("fs_trust", {"name": "Owned", "identifier": [], "signature_algorithm": "bad"}),
        ("fs_claim_rule", {"name": "Owned"}),
        ("fs_claim_rule", {"name": "Owned", "transform_rules": {"update": "set"}}),
        (
            "fs_claim_rule",
            {"name": "Owned", "transform_rules": {"value": [], "update": "bad"}},
        ),
        (
            "fs_claim_rule",
            {"name": "Owned", "transform_rules": {"value": [], "unknown": True}},
        ),
    ],
)
# Pytest supplies independent behavior inputs alongside its scoped fixtures.
# pylint: disable=too-many-arguments,too-many-positional-arguments
def test_invalid_public_inputs_never_call_vendor(
    vendor: tuple[Any, Vendor],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    module: str,
    inputs: dict[str, Any],
) -> None:
    _, state = vendor
    status, response = _run(module, inputs, tmp_path, monkeypatch, capsys)
    assert status == 1 and not response["changed"] and state.calls == []


# pylint: enable=too-many-arguments,too-many-positional-arguments


@pytest.mark.parametrize("name", ["fs_trust", "fs_claim_rule"])
def test_actions_stage_the_complete_ps2_adapter_closure(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_class = action_loader.get(
        "sustainablelobster.legacy_ad." + name, class_only=True
    )
    action, _, events = _action(action_class, monkeypatch)
    action.run()
    assert [Path(str(event[1])).name for event in events if event[0] == "transfer"] == [
        "legacy_windows_module.py",
        "legacy_ad_result.py",
        "legacy_ad_arguments.py",
        "legacy_ad_adfs.py",
    ]


def test_vendor_bridge_passes_untrusted_values_only_on_standard_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    helper = load_module(AD / "module_utils/legacy_ad_adfs.py", "adfs_process_boundary")
    process = Mock(returncode=0)
    process.__enter__ = Mock(return_value=process)
    process.__exit__ = Mock(return_value=False)
    process.communicate.return_value = (b"{}", b"")
    popen = Mock(return_value=process)
    monkeypatch.setattr(helper.subprocess, "Popen", popen)
    malicious = "'; Write-Output unexpected; # \u2603"
    assert helper.run_vendor("update", {"Notes": malicious}) == {}
    command = popen.call_args.args[0]
    assert command[command.index("-InputFormat") + 1] == "Text"
    assert malicious not in " ".join(command)
    request = json.loads(process.communicate.call_args.args[0])
    assert request == {"operation": "update", "parameters": {"Notes": malicious}}
    assert "ConvertTo-Json" not in helper._VENDOR_SCRIPT
    assert "Invoke-Expression" not in helper._VENDOR_SCRIPT
    assert "Microsoft.Adfs.PowerShell" in helper._VENDOR_SCRIPT
    assert "($input | Out-String)" in helper._VENDOR_SCRIPT
    assert "Console]::In" not in helper._VENDOR_SCRIPT


@pytest.mark.parametrize(
    "stdout,rc",
    [
        (b"not json", 1),
        (b"[]", 0),
        (b'{"failed":true,"message":"vendor error"}', 1),
        (b"{}", 1),
    ],
)
def test_vendor_bridge_failures_are_actionable(
    monkeypatch: pytest.MonkeyPatch, stdout: bytes, rc: int
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    helper = load_module(AD / "module_utils/legacy_ad_adfs.py", "adfs_process_failure")
    process = Mock(returncode=rc)
    process.__enter__ = Mock(return_value=process)
    process.__exit__ = Mock(return_value=False)
    process.communicate.return_value = (stdout, b"engine diagnostic")
    monkeypatch.setattr(helper.subprocess, "Popen", Mock(return_value=process))
    with pytest.raises(OSError):
        helper.run_vendor("inspect", {"Name": "Owned"})
