"""Bind public Route requests to persistent-route behavior without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

Request = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


@pytest.fixture(name="run_request")
def request_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run the real JSON entry point against replaceable native boundaries.

    :param monkeypatch: Scoped native and argument-file replacements.
    :param tmp_path: Isolated request directory.
    :param capsys: Captured JSON module responses.
    :returns: Request runner and native call recorder.
    """
    payload = load_payload("win_route", monkeypatch)
    native = Mock()
    native.persistent_routes.return_value = []
    native.prepare_add.return_value = "prepared-add"
    native.prepare_remove.return_value = "prepared-remove"
    for name in (
        "persistent_routes",
        "prepare_add",
        "prepare_remove",
        "add_route",
        "remove_route",
    ):
        monkeypatch.setattr(payload.route, name, getattr(native, name))
    path = tmp_path / "request.json"
    monkeypatch.setattr(sys, "argv", ["win_route.py", str(path)])

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run, native


def test_create_check_repeat_and_destination_only_preservation(
    run_request: Any,
) -> None:
    run, native = run_request
    arguments = {"destination": "192.0.2.73/32", "metric": 37}
    assert run(dict(arguments, _ansible_check_mode=True)) == (
        0,
        {"changed": True, "msg": "Route added"},
    )
    native.prepare_add.assert_called_once_with(arguments["destination"], "0.0.0.0")
    native.add_route.assert_not_called()
    assert run(arguments) == (0, {"changed": True, "msg": "Route added"})
    native.add_route.assert_called_once_with("prepared-add")
    native.persistent_routes.return_value = [{"Destination": "192.0.2.73"}]
    native.prepare_add.reset_mock()
    assert run(
        dict(arguments, destination="192.0.2.73/24", gateway="invalid", metric=-5)
    ) == (0, {"changed": False, "msg": "Static route already exists"})
    native.persistent_routes.assert_called_with("192.0.2.73")
    native.prepare_add.assert_not_called()


def test_remove_exact_prefix_check_repeat_and_ignored_gateway(run_request: Any) -> None:
    run, native = run_request
    args = {"destination": "192.0.2.73/32", "state": "absent", "gateway": "invalid"}
    assert run(args) == (0, {"changed": False, "msg": "No route to remove"})
    native.prepare_remove.assert_not_called()
    native.persistent_routes.return_value = [{}]
    assert run(dict(args, _ansible_check_mode=True)) == (
        0,
        {"changed": True, "msg": "Route removed"},
    )
    native.remove_route.assert_not_called()
    assert run(args) == (0, {"changed": True, "msg": "Route removed"})
    native.prepare_remove.assert_called_with(args["destination"])
    native.remove_route.assert_called_once_with("prepared-remove")


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("state", ["present", "absent"])
def test_native_failure_retains_changed_false_and_public_context(
    run_request: Any, check: bool, state: str
) -> None:
    run, native = run_request
    native.persistent_routes.return_value = [] if state == "present" else [{}]
    getattr(
        native, "prepare_add" if state == "present" else "prepare_remove"
    ).side_effect = OSError("denied")
    code, result = run(
        {"destination": "192.0.2.73/32", "state": state, "_ansible_check_mode": check}
    )
    assert code == 1 and result["failed"] and not result["changed"]
    assert (
        "Failed to create a new route:"
        if state == "present"
        else "Failed to remove the requested route:"
    ) in result["msg"]
    native.add_route.assert_not_called()
    native.remove_route.assert_not_called()


@pytest.mark.parametrize(
    "metric", [True, 1.5, "1.0", "0x10", [], {}, 2**31, -(2**31) - 1]
)
def test_invalid_metrics_fail_even_for_existing_routes(
    run_request: Any, metric: Any
) -> None:
    run, native = run_request
    native.persistent_routes.return_value = [{}]
    code, result = run({"destination": "192.0.2.73/32", "metric": metric})
    assert code == 1 and not result["changed"] and "metric" in result["msg"]
    native.persistent_routes.assert_not_called()


@pytest.mark.parametrize("metric", [None, -5, 37, " +37 ", -(2**31), 2**31 - 1])
def test_valid_metrics_are_bound_but_not_used(run_request: Any, metric: Any) -> None:
    run, native = run_request
    assert run({"destination": "192.0.2.73/32", "metric": metric}) == (
        0,
        {"changed": True, "msg": "Route added"},
    )
    native.prepare_add.assert_called_once_with("192.0.2.73/32", "0.0.0.0")


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"destination": None},
        {"destination": "192.0.2.73/32", "state": "invalid"},
        {"destination": "192.0.2.73/32", "extra": True},
    ],
)
def test_binding_rejects_missing_required_state_and_extra_options(
    run_request: Any, arguments: dict[str, Any]
) -> None:
    run, native = run_request
    code, result = run(arguments)
    assert code == 1 and result["failed"] and not result["changed"]
    native.persistent_routes.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("suffix", ["24", "255.255.255.0", "0.0.0.255"])
def test_public_prefix_validation_keeps_check_and_actual_creation_distinct(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    suffix: str,
    check: bool,
) -> None:
    payload = load_payload("win_route", monkeypatch)
    monkeypatch.setattr(payload.route, "persistent_routes", Mock(return_value=[]))
    monkeypatch.setattr(payload.route, "_interface", Mock(return_value=11))
    command, legacy = Mock(), Mock()
    monkeypatch.setattr(payload.route, "_command", command)
    monkeypatch.setattr(payload.route, "_legacy_add", legacy)
    path = tmp_path / "request.json"
    path.write_text(
        json.dumps(
            {
                "destination": "192.0.2.193/" + suffix,
                "gateway": "192.168.0.1",
                "_ansible_check_mode": check,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["win_route.py", str(path)])
    code, result = invoke_payload(payload, capsys)
    if suffix == "24" and check:
        assert (code, result) == (0, {"changed": True, "msg": "Route added"})
    else:
        assert code == 1 and result["failed"] and not result["changed"]
        assert result["msg"].startswith("Failed to create a new route:")
    command.assert_not_called()
    legacy.assert_not_called()
