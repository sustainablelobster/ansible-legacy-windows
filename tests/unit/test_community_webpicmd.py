"""Exercise the actual WebPI payload against independently selected CLI replies."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from types import ModuleType
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def payload_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the actual payload with shared native process helpers.

    :param monkeypatch: Scoped target helper imports.
    :returns: Maintained module without running main.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_webpicmd.py",
        "community_webpi",
    )
    monkeypatch.setattr(module, "_executable", lambda: r"C:\Vendor\webpicmd.exe")
    return module


def _vendor(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, replies: list[dict[str, Any]]
) -> list[list[str]]:
    calls = []

    def command(_executable: str, arguments: list[str]) -> dict[str, Any]:
        """Return independent status and output while retaining literal arguments.

        :param arguments: Released CLI operation.
        :returns: Independently chosen vendor response.
        """
        calls.append(arguments)
        return replies.pop(0)

    monkeypatch.setattr(payload, "_command", command)
    return calls


def test_already_installed_is_unchanged_and_never_installs(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _vendor(
        payload, monkeypatch, [{"rc": 0, "stdout": "Header\r\nURLRewrite2    2.1\r\n"}]
    )
    assert getattr(payload, "_execute")({"name": "urlrewrite2"}) == {"changed": False}
    assert calls == [["/list", "/listoption:installed"]]


@pytest.mark.parametrize(
    "output,changed",
    [("Install of Products: SUCCESS", True), ("Nothing installed", False)],
)
def test_install_retains_vendor_success_marker(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, output: str, changed: bool
) -> None:
    calls = _vendor(
        payload,
        monkeypatch,
        [{"rc": 0, "stdout": "Header"}, {"rc": 0, "stdout": output}],
    )
    assert getattr(payload, "_execute")({"name": "Fixture"}) == {"changed": changed}
    assert calls[1] == [
        "/install",
        "/products:Fixture",
        "/accepteula",
        "/suppressreboot",
    ]


@pytest.mark.parametrize("operation", ["list", "install"])
def test_failure_preserves_released_diagnostic_fields(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    replies = [{"rc": 23, "stdout": "native vendor diagnostic"}]
    if operation == "install":
        replies.insert(0, {"rc": 0, "stdout": "No installed products"})
    _vendor(payload, monkeypatch, replies)
    result = getattr(payload, "_execute")({"name": "Fixture"})
    assert result["failed"] is True and result["changed"] is False
    assert result["webpicmd_error_log"] == "native vendor diagnostic"
    assert result["webpicmd_error_cmd"] is None


def test_check_mode_does_not_discover_or_execute_webpi(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        payload,
        "_executable",
        lambda: pytest.fail("Check mode must not discover a vendor executable"),
    )
    result = getattr(payload, "_execute")(
        {"name": "Fixture", "_ansible_check_mode": True}
    )
    assert result["skipped"] is True and result["changed"] is False


def test_required_name_is_validated(payload: ModuleType) -> None:
    with pytest.raises(ValueError, match="name is required"):
        getattr(payload, "_execute")({})
