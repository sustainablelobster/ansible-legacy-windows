"""Check MSI fixture ownership and literal cleanup without lab access."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/integration/vars/package_fixture.yml"


@pytest.fixture(name="fixture")
def package_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load maintained fixture contracts with native operations replaced locally.

    :param tmp_path: Owned journal directory.
    :param monkeypatch: Scoped native-import substitutions.
    :returns: Fixture namespace and mock recovery operations.
    """
    source = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))["package_program"]
    source = source[: source.rindex("\nvalidate_workspace()")]
    source = source.replace("assert sys.version_info[:3] == (3, 4, 4)\n", "")
    source = source.replace("assert sys.version_info[:3]==(3,4,4)\n", "")
    start = source.index("{% for")
    end = source.index("{% endfor %}") + len("{% endfor %}")
    source = source[:start] + source[end:]
    for name in (
        "legacy_windows_acl",
        "legacy_windows_package_msi",
        "legacy_windows_package",
        "legacy_windows_service",
        "legacy_windows_wmi",
        "winreg",
    ):
        module = ModuleType(name)
        if name == "legacy_windows_wmi":
            module.WmiConnection = Mock()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "cleanup"])
    namespace: dict[str, Any] = {}
    exec(compile(source, str(SOURCE), "exec"), namespace)  # pylint: disable=exec-used
    identifier = namespace["GOOD"]
    before = {
        "products": [{"id": "protected-product", "state": 5}],
        "states": {identifier: -1 for identifier in namespace["IDS"]},
        "pending": {"marker": None},
        "services": {"MSIServer": {"State": "Stopped", "StartMode": "Manual"}},
        "sources": {},
        "outputs": {},
        "uninstall_keys": {"protected-key": None},
    }
    record = {
        "workspace": str(tmp_path),
        "before": before,
        "complete": True,
        "verified": False,
        "sources": {},
    }
    namespace["write"](record)
    namespace["snapshot"] = lambda: copy.deepcopy(before)
    namespace["states"] = lambda: copy.deepcopy(before["states"])
    namespace["restore_source_acls"] = Mock()
    namespace["restore_service"] = Mock()
    namespace["original_installer_command"] = namespace["installer_command"]
    namespace["installer_command"] = Mock()
    return namespace


@pytest.mark.parametrize(
    "field",
    [
        "products",
        "states",
        "pending",
        "services",
        "sources",
        "outputs",
        "uninstall_keys",
    ],
)
def test_protected_difference_keeps_unverified_journal(
    fixture: dict[str, Any], field: str
) -> None:
    final = fixture["snapshot"]()
    final[field] = {"unexpected": "difference"}
    fixture["snapshot"] = lambda: final
    with pytest.raises((AssertionError, KeyError)):
        fixture["cleanup"]()
    assert Path(fixture["JOURNAL"]).exists()
    assert fixture["read"]()["verified"] is False


def test_verified_cleanup_precedes_journal_removal(fixture: dict[str, Any]) -> None:
    result = fixture["cleanup"]()
    assert result["before"] == result["after"]
    assert fixture["read"]()["verified"] is True
    fixture["installer_command"].assert_not_called()
    assert fixture["finalize"]() == {"finalized": True}
    assert not Path(fixture["JOURNAL"]).exists()


def test_finalize_rechecks_literal_state(fixture: dict[str, Any]) -> None:
    fixture["cleanup"]()
    fixture["snapshot"] = lambda: {"unexpected": "difference"}
    with pytest.raises(AssertionError):
        fixture["finalize"]()
    assert Path(fixture["JOURNAL"]).exists()


def test_missing_journal_rejects_unknown_partial_workspace(
    fixture: dict[str, Any],
) -> None:
    Path(fixture["JOURNAL"]).unlink()
    Path(fixture["ROOT"], "unknown").write_text("retain", encoding="utf-8")
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    with pytest.raises(AssertionError):
        fixture["finalize"]()
    fixture["installer_command"].assert_not_called()


def test_missing_journal_only_accepts_exactly_empty_workspace(
    fixture: dict[str, Any],
) -> None:
    Path(fixture["JOURNAL"]).unlink()
    assert fixture["cleanup"]() == {"restored": True, "journal_absent": True}
    assert fixture["finalize"]() == {"finalized": True, "journal_absent": True}


def test_journal_for_other_workspace_is_not_adopted(fixture: dict[str, Any]) -> None:
    record = fixture["read"]()
    record["workspace"] = "unrelated"
    Path(fixture["JOURNAL"]).write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    fixture["installer_command"].assert_not_called()


def test_raw_acl_bytes_round_trip_without_double_encoding(
    fixture: dict[str, Any],
) -> None:
    record = fixture["read"]()
    record["sources"] = {"good": {"acl": {"dacl": b"\x01\xff\x00"}}}
    fixture["write"](record)
    assert fixture["read"]() == record


@pytest.mark.parametrize("state", ["present", "absent"])
def test_msi_prerequisite_quotes_only_the_property_value(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    fixture["ROOT"] = r"C:\owned workspace"
    child = MagicMock(returncode=0)
    child.communicate.return_value = (b"", b"")
    popen = MagicMock()
    popen.return_value.__enter__.return_value = child
    monkeypatch.setattr(fixture["subprocess"], "Popen", popen)
    fixture["original_installer_command"](state)
    command = popen.call_args.args[0]
    assert isinstance(command, str)
    assert '"INSTALLDIR=' not in command
    directory = fixture["os"].path.join(fixture["ROOT"], "application")
    assert (' INSTALLDIR="' + directory + '"' in command) is (state == "present")
    assert "/qn /norestart /L*V" in command


@pytest.mark.parametrize("raw", [False, True])
def test_msi_argument_selection_preserves_the_default_and_explicit_raw_form(
    raw: bool,
) -> None:
    options = yaml.safe_load((ROOT / "tests/integration/vars/package.yml").read_text())
    environment = NativeEnvironment()
    environment.filters["bool"] = bool
    path = r"C:\owned workspace"
    value = environment.from_string(options["package_install_arguments"]).render(
        package_workspace={"path": path}, package_raw_msi_arguments=raw
    )
    expected = (
        'INSTALLDIR="' + path + '\\application"'
        if raw
        else ["INSTALLDIR=" + path + "\\application"]
    )
    assert value == expected
