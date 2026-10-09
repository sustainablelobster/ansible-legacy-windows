"""Exercise public feature-info binding, projection, and native provider errors."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These substitutions do not establish Windows compatibility.

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def feature_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Bind public WANT_JSON arguments against a replaced native reader.

    :param monkeypatch: Scoped payload and native-reader replacements.
    :param capsys: Standard output capture.
    :returns: Request runner and the observed native boundary.
    """
    module = load_payload("win_feature_info", monkeypatch)
    records = [{"name": "DHCP", "installed": False}]
    native = Mock(return_value=records)
    monkeypatch.setattr(module.feature_info, "features", native)

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(module, "read_arguments", lambda *_args: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(run=_run, native=native, records=records)


@pytest.mark.parametrize("check", [False, True])
def test_default_selector_preserves_whole_metadata_and_is_read_only(
    runner: Any, check: bool
) -> None:
    assert runner.run({"_ansible_check_mode": check}) == (
        0,
        {"changed": False, "exists": True, "features": runner.records},
    )
    runner.native.assert_called_once_with("*")


@pytest.mark.parametrize(
    "value,expected",
    [
        (42, "42"),
        (False, "False"),
        ([], "System.Object[]"),
        ({}, "System.Collections.Hashtable"),
        ("DHCP ", "DHCP "),
    ],
)
def test_string_binding_does_not_split_or_trim(
    runner: Any, value: Any, expected: str
) -> None:
    assert runner.run({"name": value})[0] == 0
    runner.native.assert_called_once_with(expected)


@pytest.mark.parametrize("name", [None, ""])
def test_null_and_empty_selector_preserve_measured_upstream_failure(
    runner: Any, name: Any
) -> None:
    status, result = runner.run({"name": name})
    assert status == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": "Unhandled exception while executing module: Cannot validate "
        "argument on parameter 'Name'. The argument is null or empty. "
        "Provide an argument that is not null or empty, and then try the command again.",
    }
    runner.native.assert_not_called()


def test_unmatched_selector_returns_explicit_empty_features(runner: Any) -> None:
    runner.native.return_value = []
    assert runner.run({"name": "Missing*"}) == (
        0,
        {"changed": False, "exists": False, "features": []},
    )


@pytest.mark.parametrize("hresult", [0x8004100E])
def test_missing_provider_is_actionable_and_not_success(
    runner: Any, hresult: int
) -> None:
    error = OSError("native provider missing")
    setattr(error, "hresult", hresult)
    runner.native.side_effect = error
    assert runner.run({}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Windows Server Manager deployment provider is unavailable.",
        },
    )


def test_access_denied_is_not_misreported_as_unavailable(runner: Any) -> None:
    error = OSError("native access denied")
    setattr(error, "hresult", 0x80041003)
    runner.native.side_effect = error
    status, result = runner.run({})
    assert status == 1 and not result["changed"]
    assert result["msg"] == "native access denied"
