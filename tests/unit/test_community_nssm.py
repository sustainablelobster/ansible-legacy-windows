"""Exercise service lifecycle and idempotence through the public NSSM payload."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import shlex
import sys
from importlib import import_module
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


# A single process boundary is the complete external vendor API in these tests.
class Vendor:  # pylint: disable=too-few-public-methods
    """Model the external NSSM CLI independently of module configuration tables."""

    def __init__(self) -> None:
        self.exists = False
        self.state = "SERVICE_STOPPED"
        self.parameters: dict[str, list[str]] = {}
        self.calls: list[list[str]] = []
        self.failure: str | None = None

    def launch(
        self, executable: str, command: str, _parameters: dict[str, Any]
    ) -> dict[str, Any]:
        """Observe the real launch request and apply vendor-style operations.

        Test inputs use common POSIX/Windows quoting, allowing an independent
        parser without using a production quoting or argument helper.

        :param executable: Actual NSSM image requested by the payload.
        :param command: Complete CLI request.
        :returns: Vendor status and standard streams.
        :raises AssertionError: The payload requests an unknown vendor operation.
        """
        arguments = shlex.split(command)
        assert arguments.pop(0) == executable
        self.calls.append(arguments)
        operation = arguments[0]
        if self.failure == operation:
            return {"rc": 5, "stdout": "", "stderr": "independent access failure"}
        stdout = ""
        if operation == "install":
            self.exists = True
            self.parameters["Application"] = [arguments[2]]
            self.parameters["ObjectName"] = ["LocalSystem"]
        elif operation == "get":
            stdout = "\r\n".join(self.parameters.get(arguments[2], []))
        elif operation == "set":
            self.parameters[arguments[2]] = arguments[3:]
        elif operation == "reset":
            self.parameters.pop(arguments[2], None)
        elif operation == "status":
            stdout = self.state + "\r\n"
        elif operation == "start":
            self.state = "SERVICE_RUNNING"
        elif operation == "stop":
            self.state = "SERVICE_STOPPED"
        elif operation == "remove":
            assert arguments[2] == "confirm"
            self.exists = False
        else:
            raise AssertionError("Unexpected NSSM operation: " + operation)
        return {"rc": 0, "stdout": stdout, "stderr": ""}


@pytest.fixture(name="service")
def service_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[ModuleType, Vendor, Path]:
    """Load the payload with independent vendor and account/service boundaries.

    :param monkeypatch: Scoped native API and process substitutions.
    :param tmp_path: Owned application fixture directory.
    :returns: Actual payload, vendor state and existing application image.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_nssm.py", "community_nssm"
    )
    vendor = Vendor()
    monkeypatch.setattr(payload, "run_command", vendor.launch)
    monkeypatch.setattr(
        payload.services, "resolve_name", lambda name: name if vendor.exists else None
    )
    monkeypatch.setattr(payload.services, "supports_delayed_start", lambda: False)
    monkeypatch.setattr(payload.accounts, "name_to_sid", lambda _name: "S-1-5-21-1000")
    monkeypatch.setattr(payload.accounts, "sid_to_name", lambda _sid: "Operator")
    application = tmp_path / "application.exe"
    application.write_bytes(b"independent application image")
    return payload, vendor, application


def execute(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    **arguments: Any,
) -> tuple[int, dict[str, Any]]:
    """Execute the actual public JSON entry point for one service request.

    :param service: Loaded payload, independent vendor state and existing image.
    :param monkeypatch: Scoped JSON argument path substitution.
    :param capsys: Public module output capture.
    :param arguments: Public options overriding the valid minimal request.
    :returns: Process status and decoded public result.
    """
    request = {"name": "FixtureService", "application": str(service[2]), **arguments}
    argument_file = service[2].parent / "nssm-arguments.json"
    argument_file.write_text(json.dumps(request), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(service[0].__file__), str(argument_file)])
    return invoke_payload(service[0], capsys)


def test_create_repeat_and_remove(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, created = execute(service, monkeypatch, capsys, _ansible_diff=True)
    assert status == 0
    assert created["changed"] is True
    assert created["diff"]["prepared"].startswith("+[FixtureService]\n")
    assert bool(service[1].exists)
    assert service[1].parameters["Application"] == [str(service[2])]
    assert service[1].parameters["AppDirectory"] == [str(service[2].parent)]
    assert service[1].parameters["Start"] == ["SERVICE_AUTO_START"]
    assert service[1].parameters["AppRotateBytes"] == ["104858"]
    service[1].calls.clear()
    status, repeated = execute(service, monkeypatch, capsys, _ansible_diff=True)
    assert status == 0
    assert repeated == {"changed": False}
    assert all(call[0] == "get" for call in service[1].calls)
    status, removed = execute(
        service, monkeypatch, capsys, state="absent", application=None
    )
    assert status == 0
    assert removed["changed_by"] == "remove_service"
    assert not bool(service[1].exists)
    assert execute(service, monkeypatch, capsys, state="absent", application=None)[
        1
    ] == {"changed": False}


def test_new_service_check_mode_does_not_call_vendor_or_create_service(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(
        service, monkeypatch, capsys, _ansible_check_mode=True, _ansible_diff=True
    )
    assert status == 0
    assert result["changed_by"] == "install_service"
    assert service[1].exists is False
    assert service[1].calls == []


def test_real_process_decoder_accepts_nssm_bomless_utf16le_getters(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    process_helper = import_module("legacy_windows_process")

    def start(executable: str, command: str, _directory: str | None) -> Any:
        """Expose vendor bytes through the real shared decoder's process boundary.

        :param executable: NSSM image selected by the public payload.
        :param command: Complete native command line.
        :returns: Process reply containing genuine UTF-16LE byte streams.
        """
        response = service[1].launch(executable, command, {})
        return SimpleNamespace(
            returncode=response["rc"],
            communicate=lambda _stdin: (
                response["stdout"].encode("utf-16-le"),
                response["stderr"].encode("utf-16-le"),
            ),
        )

    monkeypatch.setattr(process_helper, "_start_process", start)
    monkeypatch.setattr(service[0], "run_command", process_helper.run_command)
    assert execute(service, monkeypatch, capsys, state="started")[0] == 0
    service[1].calls.clear()
    status, result = execute(service, monkeypatch, capsys, state="started")
    assert status == 0
    assert result["changed"] is False
    assert all(call[0] in ("get", "status") for call in service[1].calls)


def test_existing_check_mode_predicts_parameters_without_mutations(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    execute(service, monkeypatch, capsys)
    service[1].calls.clear()
    status, result = execute(
        service,
        monkeypatch,
        capsys,
        description="planned change",
        _ansible_check_mode=True,
    )
    assert status == 0
    assert result["changed_by"] == "Description"
    assert "Description" not in service[1].parameters
    assert all(call[0] == "get" for call in service[1].calls)


@pytest.mark.parametrize(
    "state,expected", [("started", "SERVICE_RUNNING"), ("stopped", "SERVICE_STOPPED")]
)
def test_start_stop_and_idempotence(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state: str,
    expected: str,
) -> None:
    execute(service, monkeypatch, capsys, state="present")
    service[1].state = "SERVICE_STOPPED" if state == "started" else "SERVICE_RUNNING"
    status, changed = execute(service, monkeypatch, capsys, state=state)
    assert status == 0
    assert changed["changed"] is True
    assert service[1].state == expected
    assert execute(service, monkeypatch, capsys, state=state)[1]["changed"] is False


def test_restart_stops_then_starts(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    execute(service, monkeypatch, capsys, state="started")
    service[1].calls.clear()
    status, result = execute(service, monkeypatch, capsys, state="restarted")
    assert status == 0
    assert result["changed"] is True
    actions = [call[0] for call in service[1].calls]
    assert actions.index("stop") < actions.index("start")


def test_arguments_aliases_environment_and_reset(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(
        service,
        monkeypatch,
        capsys,
        app_parameters_free_form=["arg with spaces", "plain"],
        chdir=str(service[2].parent),
        app_environment={"ZED": "last", "ALPHA": "first"},
        dependencies=["Tcpip", "EventLog"],
        app_stop_method_console=3000,
        app_stop_method_skip=2,
    )
    assert status == 0
    assert result["nssm_app_parameters"] == ["arg with spaces", "plain"]
    assert result["nssm_single_line_app_parameters"] == '"arg with spaces" plain'
    assert service[1].parameters["AppEnvironmentExtra"] == ["ALPHA=first", "ZED=last"]
    assert service[1].parameters["DependOnService"] == ["Tcpip", "EventLog"]
    assert service[1].parameters["AppStopMethodConsole"] == ["3000"]
    assert service[1].parameters["AppStopMethodSkip"] == ["2"]
    status, result = execute(
        service, monkeypatch, capsys, app_environment={}, dependencies=[]
    )
    assert status == 0
    assert result["changed"] is True
    assert "AppEnvironmentExtra" not in service[1].parameters
    assert "DependOnService" not in service[1].parameters


def test_same_service_account_does_not_reset_the_password_or_expose_it(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(
        service,
        monkeypatch,
        capsys,
        username="Operator",
        password="service-secret",
        _ansible_diff=True,
    )
    assert status == 0
    assert "service-secret" not in json.dumps(result)
    service[1].calls.clear()
    status, result = execute(
        service, monkeypatch, capsys, username="Operator", password="new-secret"
    )
    assert status == 0
    assert not result["changed"]
    assert all(call[0] == "get" for call in service[1].calls)


@pytest.mark.parametrize("operation", ["install", "get", "set", "start", "remove"])
def test_vendor_failures_preserve_actionable_diagnostics(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
) -> None:
    if operation != "install":
        execute(service, monkeypatch, capsys)
    service[1].failure = operation
    status, result = execute(
        service,
        monkeypatch,
        capsys,
        state="absent" if operation == "remove" else "started",
        description="forces update",
    )
    assert status == 1
    assert result["failed"] is True
    assert "NSSM " + operation in result["msg"]
    assert "independent access failure" in result["nssm_error_log"]


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({"application": None}, "application parameter must be defined"),
        ({"app_rotate_online": 2}, "must be 0 or 1"),
        ({"app_stop_method_skip": 0}, "between 1 and 15"),
        ({"start_mode": "delayed"}, "Delayed automatic startup is unavailable"),
        ({"username": "Operator"}, "password is required"),
    ],
)
def test_invalid_or_unavailable_requests_do_not_mutate(
    service: tuple[ModuleType, Vendor, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
    message: str,
) -> None:
    status, result = execute(service, monkeypatch, capsys, **arguments)
    assert status == 1
    assert message in result["msg"]
    assert service[1].calls == []
