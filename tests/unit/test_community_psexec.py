"""Exercise the controller PsExec module through Ansible's JSON boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

# Ansible's module runtime has no distributed typing metadata.
from ansible.module_utils import basic  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT, load_module


class SMBError(Exception):
    """Represent a failure returned by the external SMB client."""


class Client:
    """Record independently observed SMB operations and configurable replies."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.connection: dict[str, Any] = {}
        self.arguments: dict[str, Any] = {}
        self.reply: tuple[bytes | None, bytes | None, int] = (
            b"remote output\r\n",
            b"remote error\r\n",
            17,
        )
        self.fail_at: str | None = None

    def _event(self, event: str) -> None:
        self.events.append(event)
        if self.fail_at == event:
            raise SMBError("independent SMB failure")

    def connect(self, *, timeout: int) -> None:
        """Record negotiated connection setup.

        :param timeout: Requested SMB connection timeout.
        """
        self.connection["timeout"] = timeout
        self._event("connect")

    def create_service(self) -> None:
        """Record temporary service creation."""
        self._event("create")

    def run_executable(
        self, **arguments: Any
    ) -> tuple[bytes | None, bytes | None, int]:
        """Execute the supplied process request.

        :param arguments: Process options sent to the vendor client.
        :returns: Independently configured stdout, stderr and status or PID.
        """
        self.arguments = arguments
        self._event("run")
        return self.reply

    def remove_service(self) -> None:
        """Record temporary service and executable cleanup."""
        self._event("remove")

    def disconnect(self) -> None:
        """Record closing the SMB connection."""
        self._event("disconnect")


@pytest.fixture(name="remote")
def remote_fixture(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, Client]:
    """Replace only the external SMB client beneath the actual module runtime.

    :param monkeypatch: Scoped optional-library and client substitutions.
    :returns: Actual controller module and independent remote client.
    """
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/psexec.py",
        "community_psexec_under_test",
    )
    remote = Client()

    def create_client(**arguments: Any) -> Client:
        """Return the independent client with requested connection options.

        :param arguments: Controller's SMB connection request.
        :returns: Independently configured SMB client.
        """
        remote.connection.update(arguments)
        return remote

    monkeypatch.setattr(payload, "HAS_PYPSEXEC", True)
    monkeypatch.setattr(payload, "HAS_KERBEROS", True)
    monkeypatch.setattr(
        payload, "client", SimpleNamespace(Client=create_client), raising=False
    )
    priorities = {
        name + "_PRIORITY_CLASS": index
        for index, name in enumerate(
            ("ABOVE_NORMAL", "BELOW_NORMAL", "HIGH", "IDLE", "NORMAL", "REALTIME")
        )
    }
    monkeypatch.setattr(
        payload, "ProcessPriority", SimpleNamespace(**priorities), raising=False
    )
    for exception in (
        "SMBAuthenticationError",
        "SMBResponseException",
        "PDUException",
        "SCMRException",
        "SMBException",
        "PypsexecException",
    ):
        monkeypatch.setattr(payload, exception, SMBError, raising=False)
    return payload, remote


def execute(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    **arguments: Any,
) -> tuple[int, dict[str, Any]]:
    """Run actual Ansible validation and deserialize the public result.

    :param remote: Actual controller module and independent remote client.
    :param monkeypatch: Scoped argument-buffer substitution.
    :param capsys: JSON stdout and stderr capture.
    :param arguments: Public module arguments overriding a minimal valid request.
    :returns: Process status and public JSON response.
    """
    request = {"hostname": "old-host", "executable": "cmd.exe", **arguments}
    monkeypatch.setattr(
        basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": request}).encode()
    )
    monkeypatch.setattr(basic, "_ANSIBLE_PROFILE", "legacy")
    with pytest.raises(SystemExit) as exited:
        remote[0].main()
    output = capsys.readouterr()
    if remote[1].fail_at in ("remove", "disconnect"):
        assert "[WARNING]" in output.err
        assert "independent SMB failure" in output.err
    else:
        assert not output.err
    assert isinstance(exited.value.code, int)
    return exited.value.code, json.loads(output.out)


def test_synchronous_output_and_defaults(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(remote, monkeypatch, capsys)
    assert status == 0
    assert result["changed"] is True
    assert result["stdout"] == "remote output\r\n"
    assert result["stderr"] == "remote error\r\n"
    assert result["rc"] == 17
    assert remote[1].connection == {
        "server": "old-host",
        "username": None,
        "password": None,
        "port": 445,
        "encrypt": True,
        "timeout": 60,
    }
    assert remote[1].events == ["connect", "create", "run", "remove", "disconnect"]
    assert remote[1].arguments["working_dir"] == r"C:\Windows\System32"
    assert remote[1].arguments["load_profile"] is True


@pytest.mark.parametrize("asynchronous,interactive", [(True, False), (False, True)])
def test_detached_and_interactive_results(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    asynchronous: bool,
    interactive: bool,
) -> None:
    status, result = execute(
        remote, monkeypatch, capsys, asynchronous=asynchronous, interactive=interactive
    )
    assert status == 0
    assert "stdout" not in result and "stderr" not in result
    assert result["pid" if asynchronous else "rc"] == 17
    assert ("rc" not in result) if asynchronous else ("pid" not in result)


def test_process_options_and_utf8_stdin(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, _result = execute(
        remote,
        monkeypatch,
        capsys,
        encrypt=False,
        connection_timeout=9,
        port=1445,
        process_username="Operator",
        process_password="process-secret",
        integrity_level="elevated",
        process_timeout=12,
        working_directory=r"C:\Program Files\App",
        stdin="café",
        arguments='/c "echo result"',
        priority="high",
        load_profile=False,
    )
    assert status == 0
    assert remote[1].connection["encrypt"] is False
    assert remote[1].connection["port"] == 1445
    assert remote[1].connection["timeout"] == 9
    assert remote[1].arguments["stdin"] == "café".encode()
    assert remote[1].arguments["username"] == "Operator"
    assert remote[1].arguments["password"] == "process-secret"
    assert remote[1].arguments["run_elevated"] is True
    assert remote[1].arguments["run_limited"] is False
    assert remote[1].arguments["timeout_seconds"] == 12


def test_system_account_does_not_require_a_password(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, _result = execute(remote, monkeypatch, capsys, process_username="SyStEm")
    assert status == 0
    assert remote[1].arguments["use_system_account"] is True
    assert remote[1].arguments["username"] is None
    assert remote[1].arguments["password"] is None


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({"process_username": "Operator"}, "parameters are required together"),
        ({"priority": "invalid"}, "value of priority must be one of"),
        ({"unexpected": "argument"}, "Unsupported parameters"),
    ],
)
def test_invalid_requests_do_not_connect(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
    message: str,
) -> None:
    status, result = execute(remote, monkeypatch, capsys, **arguments)
    assert status == 1
    assert message in result["msg"]
    assert remote[1].events == []


def test_check_mode_skips_without_connecting(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(remote, monkeypatch, capsys, _ansible_check_mode=True)
    assert status == 0
    assert result["skipped"] is True
    assert remote[1].events == []


@pytest.mark.parametrize(
    "library,expected", [("HAS_PYPSEXEC", "pypsexec"), ("HAS_KERBEROS", "gssapi")]
)
def test_missing_optional_controller_dependency(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    library: str,
    expected: str,
) -> None:
    monkeypatch.setattr(remote[0], library, False)
    status, result = execute(remote, monkeypatch, capsys)
    assert status == 1
    assert expected in result["msg"]
    assert remote[1].events == []


def test_process_failure_still_removes_remote_service(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    remote[1].fail_at = "run"
    status, result = execute(remote, monkeypatch, capsys)
    assert status == 1
    assert "Received error when running remote process" in result["msg"]
    assert "remove" in remote[1].events


def test_partial_service_creation_failure_attempts_file_and_connection_cleanup(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    remote[1].fail_at = "create"
    status, result = execute(remote, monkeypatch, capsys)
    assert status == 1
    assert "Failed to create PAExec service" in result["msg"]
    assert remote[1].events == ["connect", "create", "remove", "disconnect"]


@pytest.mark.parametrize("operation", ["remove", "disconnect"])
def test_cleanup_failure_is_a_warning_not_a_lost_process_result(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
) -> None:
    remote[1].fail_at = operation
    status, result = execute(remote, monkeypatch, capsys)
    assert status == 0
    assert result["rc"] == 17
    assert not result.get("failed")


def test_credentials_are_censored_in_public_invocation(
    remote: tuple[ModuleType, Client],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(
        remote,
        monkeypatch,
        capsys,
        connection_username="Operator",
        connection_password="connection-secret",
        process_username="Operator",
        process_password="process-secret",
    )
    assert status == 0
    serialized = json.dumps(result)
    assert "connection-secret" not in serialized
    assert "process-secret" not in serialized
