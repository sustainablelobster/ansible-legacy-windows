"""Exercise native auditpol argument, CSV, failure, and recovery boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later

from types import ModuleType
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="policy")
def native_policy(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the helper without invoking Windows or opening native libraries.

    :param monkeypatch: Scoped staged-helper import path.
    :returns: Audit-policy helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_audit_policy.py",
        "audit_policy_tested",
    )


def test_native_process_uses_individual_quoted_arguments_without_shell(
    policy: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = Mock(return_value={"rc": 0, "stdout": "complete", "stderr": ""})
    monkeypatch.setattr(policy, "run_command", process)
    assert (
        policy.run_auditpol(["/get", '/subcategory:File System "quoted"'])
        == process.return_value
    )
    process.assert_called_once_with(
        "auditpol.exe",
        'auditpol.exe /get "/subcategory:File System \\"quoted\\""',
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )


def test_catalogue_preserves_native_order_and_removes_category_rows(
    policy: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = Mock(
        side_effect=[
            {"rc": 0, "stdout": "Category/Subcategory\r\nSystem\r\nObject Access\r\n"},
            {
                "rc": 0,
                "stdout": (
                    "Category/Subcategory,GUID\r\nSystem,{system}\r\n"
                    "  IPsec Driver,{ipsec}\r\nObject Access,{object}\r\n"
                    "  File System,{filesystem}\r\n"
                ),
            },
        ]
    )
    monkeypatch.setattr(policy, "run_auditpol", command)
    assert policy.catalogue() == (
        ["System", "Object Access"],
        ["IPsec Driver", "File System"],
    )
    assert [entry.args[0] for entry in command.call_args_list] == [
        ["/list", "/category", "/r"],
        ["/list", "/subcategory:*", "/r"],
    ]


@pytest.mark.parametrize("failed_index", [0, 1])
def test_catalogue_failure_preserves_native_diagnostic_and_allows_retry(
    policy: ModuleType, monkeypatch: pytest.MonkeyPatch, failed_index: int
) -> None:
    results = [{"rc": 0, "stdout": "Category\nSystem\n"} for _ in range(2)]
    results[failed_index] = {"rc": 5, "stderr": "Access denied"}
    command = Mock(side_effect=results)
    monkeypatch.setattr(policy, "run_auditpol", command)
    with pytest.raises(OSError, match="Access denied"):
        policy.catalogue()
    assert command.call_count == 2
    command.side_effect = [{"rc": 0, "stdout": "Category\nSystem\n"} for _ in range(2)]
    assert policy.catalogue() == (["System"], [])


@pytest.mark.parametrize("header", ["Wrong", "Category,Category/Subcategory"])
def test_unexpected_catalogue_schema_does_not_invent_names(
    policy: ModuleType, monkeypatch: pytest.MonkeyPatch, header: str
) -> None:
    monkeypatch.setattr(
        policy, "run_auditpol", Mock(return_value={"rc": 0, "stdout": header + "\n"})
    )
    with pytest.raises(ValueError, match="unique Category"):
        policy.catalogue()


def test_policy_csv_preserves_complete_lowercase_mapping_and_native_values(
    policy: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = Mock(
        return_value={
            "rc": 0,
            "stdout": (
                "Machine Name,Subcategory,Inclusion Setting\r\n"
                "WIN,File System,Success and Failure\r\n"
                "WIN,IPsec Driver,No Auditing\r\n"
            ),
        }
    )
    monkeypatch.setattr(policy, "run_auditpol", command)
    assert policy.get_policy("category", "System") == {
        "file system": "success and failure",
        "ipsec driver": "no auditing",
    }
    command.assert_called_once_with(["/get", "/r", "/category:System"])


def test_get_failure_retains_raw_error_including_carriage_returns(
    policy: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = "Error 0x00000057 occurred:\r\r\nThe parameter is incorrect.\r\r\n\r\r\n"
    monkeypatch.setattr(
        policy, "run_auditpol", Mock(return_value={"rc": 87, "stderr": error})
    )
    assert policy.get_policy("subcategory", "") == error


@pytest.mark.parametrize(
    "output",
    [
        "Wrong\ntext\n",
        "Subcategory,Inclusion Setting\nFile System,Success\nFILE SYSTEM,Failure\n",
    ],
)
def test_missing_fields_or_duplicate_subcategories_fail_actionably(
    policy: ModuleType, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    monkeypatch.setattr(
        policy, "run_auditpol", Mock(return_value={"rc": 0, "stdout": output})
    )
    with pytest.raises(ValueError):
        policy.get_policy("subcategory", "File System")


@pytest.mark.parametrize("success", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_setter_explicitly_sets_both_flags_and_retains_failed_process_result(
    policy: ModuleType, monkeypatch: pytest.MonkeyPatch, success: bool, failure: bool
) -> None:
    command = Mock(return_value={"rc": 5, "stderr": "denied"})
    monkeypatch.setattr(policy, "run_auditpol", command)
    assert (
        policy.set_policy("subcategory", "File System", success, failure)
        == command.return_value
    )
    command.assert_called_once_with(
        [
            "/set",
            "/subcategory:File System",
            "/success:" + ("enable" if success else "disable"),
            "/failure:" + ("enable" if failure else "disable"),
        ]
    )
