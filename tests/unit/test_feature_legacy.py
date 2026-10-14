"""Exercise older Server Manager catalogues, native commands and public fallbacks."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Controller substitutes do not establish Windows execution support.
# pylint: disable=protected-access

import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def legacy_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target backend without opening Windows resources.

    :param monkeypatch: Scoped helper import path.
    :returns: Fresh older Server Manager helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_feature_legacy.py",
        "feature_legacy_tested",
    )


def _manager(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Any:
    manager = helper.ServerManager("ServerManagerCmd.exe")
    manager._workspace = str(tmp_path)
    connection = Mock()
    connection.query.return_value = [{"ID": 42, "Name": "Child display"}]
    context = MagicMock()
    context.__enter__.return_value = connection
    monkeypatch.setattr(helper, "WmiConnection", Mock(return_value=context))
    return manager


def test_catalogue_discovers_names_hierarchy_and_available_installed_ids(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manager = _manager(helper, monkeypatch, tmp_path)
    (tmp_path / "catalogue.xml").write_text(
        '<ServerManagerConfigurationQuery xmlns="native"><Role Id="UnlistedRole" '
        'DisplayName="Role display" Installed="false"><RoleService Id="UnlistedChild" '
        'DisplayName="Child display" Installed="true" Default="true"/></Role>'
        '<Feature Id="ArbitraryFeature" DisplayName="Feature display" Installed="false"/>'
        "</ServerManagerConfigurationQuery>"
    )
    manager._execute = Mock(return_value=(0, ""))
    rows = manager.catalogue()
    assert [row["UniqueName"] for row in rows] == [
        "UnlistedRole",
        "UnlistedChild",
        "ArbitraryFeature",
    ]
    assert [row["FeatureType"] for row in rows] == [0, 1, 2]
    assert rows[1]["ParentName"] == "UnlistedRole"
    assert rows[1]["InstallWithParentByDefault"]
    assert rows[1]["Installed"] == 1 and rows[1]["NumericId"] == 42
    assert rows[0]["NumericId"] is None and rows[0]["NonAncestorDependencies"] is None
    manager._execute.assert_called_once_with(
        ["-query", str(tmp_path / "catalogue.xml")]
    )


@pytest.mark.parametrize(
    "xml",
    [
        "<Query/>",
        '<Query><Feature Id="A" DisplayName="A" Installed="unknown"/></Query>',
        '<Query><Feature Id="A" DisplayName="A" Installed="false"/>'
        '<Feature Id="A" DisplayName="A" Installed="false"/></Query>',
    ],
)
def test_invalid_catalogue_is_not_guessed(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, xml: str
) -> None:
    manager = _manager(helper, monkeypatch, tmp_path)
    (tmp_path / "catalogue.xml").write_text(xml)
    manager._execute = Mock(return_value=(0, ""))
    with pytest.raises(ValueError, match="feature catalogue"):
        manager.catalogue()


def test_batch_uses_literal_names_and_never_requests_restart(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manager = _manager(helper, monkeypatch, tmp_path)
    manager._execute = Mock(return_value=(0, ""))
    assert manager.change(["RealRole", "RealChild"], True, True) == (0, "", None)
    manager._execute.assert_called_once_with(
        [
            "-install",
            "RealRole",
            "RealChild",
            "-allSubFeatures",
            "-resultpath",
            str(tmp_path / "result.xml"),
        ]
    )
    manager._execute.reset_mock()
    manager.change(["RealRole"], False, True)
    manager._execute.assert_called_once_with(
        ["-remove", "RealRole", "-resultpath", str(tmp_path / "result.xml")]
    )


@pytest.mark.parametrize("hresult", [0x80041010, 0x80041003])
def test_only_missing_installed_metadata_keeps_catalogue_with_null_ids(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    hresult: int,
) -> None:
    manager = _manager(helper, monkeypatch, tmp_path)
    (tmp_path / "catalogue.xml").write_text(
        '<Query><Feature Id="A" DisplayName="A" Installed="false"/></Query>'
    )
    manager._execute = Mock(return_value=(0, ""))
    failure = OSError("metadata unavailable")
    setattr(failure, "hresult", hresult)
    monkeypatch.setattr(helper, "WmiConnection", Mock(side_effect=failure))
    if hresult == 0x80041010:
        assert manager.catalogue()[0]["NumericId"] is None
    else:
        with pytest.raises(OSError, match="metadata unavailable"):
            manager.catalogue()


@pytest.mark.parametrize(
    "status,xml,expected",
    [
        (0, '<Result Success="true" RequiresReboot="false"/>', (True, False, False)),
        (3010, None, (True, True, False)),
        (1003, None, (False, False, False)),
        (1001, None, (True, True, True)),
        (1000, None, (True, False, True)),
        (0, '<Result Success="false"/>', (False, False, True)),
        (0, '<Result RequiresReboot="true"/>', (True, True, False)),
    ],
)
def test_native_servicing_exit_and_xml_preserve_changes_restart_and_failure(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    xml: str | None,
    expected: tuple[bool, bool, bool],
) -> None:
    changed, reboot, failed = expected
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    management = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_feature_manage.py",
        "feature_legacy_management_tested",
    )
    original = {
        "UniqueName": "RealFeature",
        "Installed": 0,
        "NumericId": None,
        "DisplayName": "Real feature",
    }
    manager = Mock()
    manager.change.return_value = (
        status,
        "native output",
        ET.fromstring(xml) if xml else None,
    )
    manager.catalogue.return_value = [dict(original, Installed=int(changed))]
    result = management._legacy_service(
        manager,
        [original],
        [original],
        {"state": "present", "include_sub_features": True},
    )
    assert result["changed"] is changed
    assert result["reboot_required"] is reboot
    assert result["failed"] is failed and result["success"] is not failed
    assert len(result["feature_result"]) == int(changed)
    manager.change.assert_called_once_with(["RealFeature"], True, True)
