"""Exercise complete package results and observable installer decisions."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Payload tests inspect concrete native boundary calls, not lab state.
# pylint: disable=protected-access

import hashlib
import json
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, invoke_payload, load_module, load_payload


@pytest.fixture(name="package_children")
def package_children_helper(runner: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Exercise public Package dispatch with an observable tree-wait boundary.

    :param runner: Concrete public payload and provider substitutions.
    :param monkeypatch: Scoped target helper import cache.
    :returns: Dedicated native child-wait helper with controlled root result.
    """
    helper = load_module(
        HELPER.parent / "legacy_windows_package_children.py", "children"
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_package_children", helper)
    monkeypatch.setattr(
        helper,
        "run_command",
        Mock(return_value={"changed": True, "rc": 0, "stdout": "", "stderr": ""}),
    )
    assert runner.module
    return helper


def test_wait_for_children_dispatches_only_the_changing_installer(
    runner: Any, package_children: Any, tmp_path: Path
) -> None:
    source = tmp_path / "package.msi"
    source.write_bytes(b"package")
    assert (
        runner.run({"path": str(source), "wait_for_children": True})[1]["changed"]
        is True
    )
    package_children.run_command.assert_called_once()
    runner.process.assert_not_called()


@pytest.mark.parametrize("check,installed", [(True, -1), (False, 5), (True, 5)])
def test_child_wait_preview_and_idempotence_never_create_processes(
    runner: Any, package_children: Any, tmp_path: Path, check: bool, installed: int
) -> None:
    source = tmp_path / "package.msi"
    source.write_bytes(b"package")
    runner.installer.product_state.return_value = installed
    assert runner.run(
        {"path": str(source), "wait_for_children": True, "_ansible_check_mode": check}
    ) == (0, {"changed": installed != 5, "rc": 0, "reboot_required": False})
    package_children.run_command.assert_not_called()
    runner.process.assert_not_called()


@pytest.mark.parametrize("code,reboot", [(3010, True), (0, False), (-1, False)])
def test_tree_wait_uses_root_code_for_failure_streams_and_reboot(
    runner: Any, package_children: Any, tmp_path: Path, code: int, reboot: bool
) -> None:
    source = tmp_path / "package.msi"
    source.write_bytes(b"package")
    package_children.run_command.return_value = {
        "changed": True,
        "rc": code,
        "stdout": "root output",
        "stderr": "root error",
    }
    status, result = runner.run({"path": str(source), "wait_for_children": True})
    assert result["rc"] == code and result["reboot_required"] is reboot
    assert status == int(code == -1)
    if code == -1:
        assert (
            result["stdout"] == "root output"
            and result["stderr"] == "root error"
            and result["changed"] is False
        )


@pytest.fixture(name="package_signature")
def package_signature_helper(runner: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace only signature policy while exercising the complete public payload.

    :param runner: Concrete payload runner and provider boundary.
    :param monkeypatch: Scoped target helper cache substitution.
    :returns: Actual helper with an observable policy method.
    """
    helper = load_module(
        HELPER.parent / "legacy_windows_package_signature.py", "signature"
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_package_signature", helper)
    monkeypatch.setattr(helper, "verify", Mock())
    assert runner.module
    return helper


def test_signature_failure_retains_checksum_and_does_not_launch_installer(
    runner: Any, package_signature: Any, tmp_path: Path
) -> None:
    source = tmp_path / "unsigned.msi"
    source.write_bytes(b"package")
    message = (
        f"Authenticode check failed: File '{source}': "
        "signature status is 'NotSigned', expected 'Valid'"
    )
    package_signature.verify.side_effect = ValueError(message)
    assert runner.run({"path": str(source), "verify_signature": True}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "reboot_required": False,
            "rc": 0,
            "checksum": hashlib.sha1(b"package").hexdigest().upper(),
            "msg": message,
        },
    )
    runner.process.assert_not_called()
    runner.read.assert_not_called()


@pytest.mark.parametrize("check_mode,installed", [(True, -1), (False, 5), (True, 5)])
def test_preview_and_idempotence_skip_authenticode_inspection(
    runner: Any,
    package_signature: Any,
    tmp_path: Path,
    check_mode: bool,
    installed: int,
) -> None:
    source = tmp_path / "unsigned.msi"
    source.write_bytes(b"package")
    runner.installer.product_state.return_value = installed
    assert runner.run(
        {
            "path": str(source),
            "verify_signature": True,
            "_ansible_check_mode": check_mode,
        }
    ) == (0, {"changed": installed != 5, "reboot_required": False, "rc": 0})
    package_signature.verify.assert_not_called()
    runner.process.assert_not_called()


def test_valid_signature_is_checked_before_system_acl_grant_and_installer_launch(
    runner: Any, package_signature: Any, tmp_path: Path
) -> None:
    source = tmp_path / "signed.msi"
    source.write_bytes(b"package")
    calls = Mock()
    calls.attach_mock(package_signature.verify, "verify")
    calls.attach_mock(runner.read, "read")
    calls.attach_mock(runner.process, "process")
    status, result = runner.run({"path": str(source), "verify_signature": True})
    assert status == 0 and result["changed"] is True and result["rc"] == 0
    assert [entry[0] for entry in calls.mock_calls] == ["verify", "read", "process"]


@pytest.fixture(name="package_remote")
def package_remote_helper(runner: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load only the URL helper while retaining the concrete package payload.

    :param runner: Initialized payload and adjacent target helper import path.
    :param monkeypatch: Scoped helper cache entry.
    :returns: Concrete package URL module with replaceable HTTP boundary.
    """
    assert runner.module
    helper = load_module(HELPER.parent / "legacy_windows_package_url.py", "remote")
    monkeypatch.setitem(sys.modules, "legacy_windows_package_url", helper)
    return helper


def test_url_installed_identity_does_not_fetch_or_initialize_networking(
    runner: Any,
) -> None:
    runner.installer.product_state.return_value = 5
    assert runner.run(
        {"path": "http://fixture/missing.msi", "product_id": "Product"}
    ) == (0, {"changed": False, "reboot_required": False, "rc": 0})
    runner.installer.product_code.assert_not_called()
    runner.process.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_url_without_identity_downloads_even_for_installed_product_and_removes_temp(
    runner: Any, package_remote: Any, monkeypatch: pytest.MonkeyPatch, check_mode: bool
) -> None:
    paths = []

    def _acquire(
        _url: str, _options: dict[str, Any], result: dict[str, Any], root: str
    ) -> str:
        path = Path(root) / "downloaded.msi"
        path.write_bytes(b"package")
        paths.append(path)
        result.update(msg="OK", status_code=200, elapsed=0.5)
        return str(path)

    monkeypatch.setattr(package_remote, "acquire", _acquire)
    runner.installer.product_state.return_value = 5
    assert runner.run(
        {"path": "http://fixture/installer.msi", "_ansible_check_mode": check_mode}
    ) == (
        0,
        {
            "changed": False,
            "reboot_required": False,
            "rc": 0,
            "msg": "OK",
            "status_code": 200,
            "elapsed": 0.5,
        },
    )
    assert len(paths) == 1 and not paths[0].parent.exists()
    runner.installer.product_code.assert_called_once_with(str(paths[0]))
    runner.process.assert_not_called()


def test_url_download_failure_has_exact_unhandled_boundary_and_owned_temp_cleanup(
    runner: Any, package_remote: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = []

    def _acquire(
        _url: str, _options: dict[str, Any], _result: dict[str, Any], root: str
    ) -> str:
        paths.append(Path(root))
        raise package_remote.PackageDownloadError("wire failure")

    monkeypatch.setattr(package_remote, "acquire", _acquire)
    assert runner.run({"path": "http://fixture/package.msi"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: wire failure",
        },
    )
    assert len(paths) == 1 and not paths[0].exists()
    runner.process.assert_not_called()


@pytest.fixture(name="runner")
def package_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Supply an observable installed-product provider and child process.

    :param monkeypatch: Scoped import and native substitutions.
    :param capsys: Capture of the payload's public JSON result.
    :returns: Payload runner and boundary recorders.
    """
    module = load_payload("win_package", monkeypatch)
    installer = SimpleNamespace(
        package_type=Mock(return_value="msi"),
        product_code=Mock(return_value="Product"),
        product_state=Mock(return_value=-1),
        patches=Mock(return_value=[]),
        patch_state=Mock(return_value=1),
        summary_property=Mock(
            side_effect=lambda _path, field: (
                "Product" if field == 7 else "{224C316C-5894-4771-BABF-21A3AC1F75FF}"
            )
        ),
    )
    monkeypatch.setattr(
        module.package, "WindowsInstaller", lambda: nullcontext(installer)
    )
    process = Mock(return_value={"changed": True, "rc": 0, "stdout": "", "stderr": ""})
    monkeypatch.setattr(module.package.processes, "run_command", process)
    read = Mock()
    monkeypatch.setattr(module.package, "_system_read", read)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(module, "read_arguments", lambda *_args: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(
        run=_run, module=module, installer=installer, process=process, read=read
    )


@pytest.mark.parametrize(
    "parameters,message",
    [
        ({}, "state is present but all of the following are missing: path"),
        (
            {"state": "absent"},
            "state is absent but any of the following are missing: path, product_id",
        ),
        (
            {"path": "package.msi", "creates_version": "1"},
            "missing parameter(s) required by 'creates_version': creates_path",
        ),
    ],
)
def test_required_inputs_fail_before_native_provider_initialization(
    runner: Any, parameters: dict[str, Any], message: str
) -> None:
    assert runner.run(parameters) == (
        1,
        {"changed": False, "failed": True, "msg": message},
    )
    runner.installer.product_state.assert_not_called()
    runner.process.assert_not_called()


def test_preview_reads_msi_identity_ignoring_supplied_id_without_checksum_or_acl_write(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "renamed.exe"
    source.write_bytes(b"package")
    assert runner.run(
        {
            "path": str(source),
            "product_id": "Ignored",
            "_ansible_check_mode": True,
            "checksum": "bad",
            "verify_signature": True,
        }
    ) == (0, {"changed": True, "reboot_required": False, "rc": 0})
    runner.installer.product_code.assert_called_once_with(str(source))
    runner.installer.product_state.assert_called_once_with("Product")
    runner.process.assert_not_called()
    runner.read.assert_not_called()


def test_idempotence_has_no_failed_or_checksum_fields_and_executes_nothing(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    runner.installer.product_state.return_value = 5
    assert runner.run({"path": str(source)}) == (
        0,
        {"changed": False, "reboot_required": False, "rc": 0},
    )
    runner.process.assert_not_called()
    runner.read.assert_not_called()


def test_install_returns_uppercase_digest_failed_false_and_native_command(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    assert runner.run(
        {
            "path": str(source),
            "log_path": str(tmp_path / "installer.log"),
            "arguments": 'INSTALLDIR="owned application"',
        }
    ) == (
        0,
        {
            "changed": True,
            "reboot_required": False,
            "rc": 0,
            "failed": False,
            "checksum": "582681C2EAE02B3F3D399C0C26D321560F6C567A",
        },
    )
    command = runner.process.call_args.args[1]
    assert "/i " in command and "/L*V " in command and "/qn /norestart" in command
    assert command.endswith(' INSTALLDIR="owned application"')
    assert runner.process.call_args.args[2]["output_encoding_override"] == "unicode"
    runner.read.assert_called_once_with(str(source))


def test_msi_list_property_quotes_only_the_value_in_actual_installer_command(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    destination = str(tmp_path / "owned application")
    status, result = runner.run(
        {"path": str(source), "arguments": ["INSTALLDIR=" + destination, "FLAG=1"]}
    )
    assert status == 0 and result["changed"] is True
    assert runner.process.call_args.args[1].endswith(
        ' INSTALLDIR="' + destination + '" FLAG=1'
    )


def test_registry_list_property_preserves_generic_whole_argument_quoting(
    runner: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "installer.exe"
    source.write_bytes(b"package")
    monkeypatch.setattr(runner.module.package, "_registry_location", lambda _id: None)
    status, result = runner.run(
        {"path": str(source), "provider": "registry", "arguments": ["PROPERTY=a b"]}
    )
    assert status == 0 and result["changed"] is True
    assert runner.process.call_args.args[1].endswith(' "PROPERTY=a b"')


def test_msi_embedded_quotes_and_raw_strings_keep_existing_command_syntax(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    arguments = 'PROPERTY="a b"'
    status, _result = runner.run({"path": str(source), "arguments": arguments})
    assert status == 0 and runner.process.call_args.args[1].endswith(" " + arguments)
    element = 'PROPERTY=a "b"'
    status, _result = runner.run({"path": str(source), "arguments": [element]})
    assert status == 0
    assert runner.process.call_args.args[1].endswith(
        " " + runner.module.package.quote_argument(element)
    )


@pytest.mark.parametrize(
    "provider,state,algorithm",
    [
        ("MSI", "PRESENT", "SHA256"),
        ("MsI", "PrEsEnT", "ShA256"),
        ("auto", "present", "sha256"),
    ],
)
def test_case_insensitive_choices_reach_actual_msi_dispatch(
    runner: Any, tmp_path: Path, provider: str, state: str, algorithm: str
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    code, result = runner.run(
        {
            "path": str(source),
            "provider": provider,
            "state": state,
            "checksum_algorithm": algorithm,
        }
    )
    assert code == 0 and result["changed"] is True
    assert len(result["checksum"]) == 64
    runner.installer.product_code.assert_called_once_with(str(source))
    assert "/i " in runner.process.call_args.args[1]


def test_case_insensitive_state_preserves_required_source_validation(
    runner: Any,
) -> None:
    assert runner.run({"state": "PRESENT"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "state is present but all of the following are missing: path",
        },
    )
    runner.installer.product_state.assert_not_called()


@pytest.mark.parametrize("name", ["maximum_redirection", "url_timeout"])
@pytest.mark.parametrize(
    "value,kind,detail",
    [
        (True, "System.Boolean", "Input string was not in a correct format."),
        (2.5, "System.Decimal", "Input string was not in a correct format."),
        (
            2147483648,
            "System.Int64",
            "Value was either too large or too small for an Int32.",
        ),
    ],
)
def test_int32_binding_failure_never_initializes_or_executes_installer(
    runner: Any, name: str, value: object, kind: str, detail: str
) -> None:
    assert runner.run({"path": "package.msi", name: value}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": f"argument for {name} is of type {kind} and we were "
            f"unable to convert to int: {detail}",
        },
    )
    runner.installer.product_state.assert_not_called()
    runner.process.assert_not_called()


@pytest.mark.parametrize("name", ["maximum_redirection", "url_timeout"])
@pytest.mark.parametrize(
    "value,kind",
    [
        (-(2**63), "System.Int64"),
        (2**63 - 1, "System.Int64"),
        (-(2**63) - 1, "System.Decimal"),
        (2**63, "System.Decimal"),
        (10**28, "System.Decimal"),
        (-(10**28), "System.Decimal"),
        (79228162514264337593543950335, "System.Decimal"),
        (-79228162514264337593543950335, "System.Decimal"),
        (79228162514264337593543950336, "System.Double"),
        (-79228162514264337593543950336, "System.Double"),
        ("79228162514264337593543950336", "System.String"),
        ("-79228162514264337593543950336", "System.String"),
    ],
)
def test_json_integer_boundaries_preserve_exact_public_binding_failures(
    runner: Any, name: str, value: object, kind: str
) -> None:
    detail = (
        "Input string was not in a correct format."
        if kind == "System.Double"
        else "Value was either too large or too small for an Int32."
    )
    assert runner.run({"path": "package.msi", name: value}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": f"argument for {name} is of type {kind} and we were "
            f"unable to convert to int: {detail}",
        },
    )
    runner.installer.product_state.assert_not_called()
    runner.process.assert_not_called()


@pytest.mark.parametrize(
    "argument",
    [("timeout", True), ("timeout", 2.5), ("timeout", 2147483648), ("method", "GET")],
)
def test_unreleased_alias_is_rejected_by_real_public_argument_file(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argument: tuple[str, object],
) -> None:
    name, value = argument
    argument_file = tmp_path / "arguments.json"
    argument_file.write_text(
        json.dumps({"path": "local.msi", name: value}), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["win_package.py", str(argument_file)])
    status, result = invoke_payload(runner.module, capsys)
    assert status == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "Unsupported parameters for "
        "(sustainablelobster.legacy_windows.win_package) module: "
        + name
        + ". Supported parameters include: "
        + ", ".join(sorted(runner.module._PARAMETERS)),
    }
    runner.installer.product_state.assert_not_called()
    runner.process.assert_not_called()


def test_checksum_failure_keeps_rc_zero_and_does_not_execute_or_change_permissions(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    code, result = runner.run({"path": str(source), "checksum": "wrong"})
    assert code == 1 and result["changed"] is False and result["rc"] == 0
    assert result["checksum"] == "582681C2EAE02B3F3D399C0C26D321560F6C567A"
    assert result["msg"] == (
        f"The checksum for {source} did not match 'wrong', it was '{result['checksum']}'"
    )
    runner.process.assert_not_called()
    runner.read.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_absent_unknown_product_uses_no_file_or_installer(
    runner: Any, check: bool
) -> None:
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        runner.module.package, "_registry_location", lambda _identifier: None
    )
    try:
        assert runner.run(
            {"state": "absent", "product_id": "Missing", "_ansible_check_mode": check}
        ) == (0, {"changed": False, "reboot_required": False, "rc": 0})
    finally:
        monkeypatch.undo()
    runner.process.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_msi_removal_uses_product_id_and_no_installation_digest_or_read_ace(
    runner: Any, check: bool
) -> None:
    runner.installer.product_state.return_value = 5
    assert runner.run(
        {"state": "absent", "product_id": "Product", "_ansible_check_mode": check}
    ) == (
        0,
        {
            "changed": True,
            "reboot_required": False,
            "rc": 0,
            **({} if check else {"failed": False}),
        },
    )
    assert runner.process.call_count == int(not check)
    if not check:
        assert "/x Product /L*V " in runner.process.call_args.args[1]
    runner.read.assert_not_called()


def test_later_creates_service_check_replaces_absent_path_status(
    runner: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    monkeypatch.setattr(runner.module.package, "_service_exists", lambda _name: True)
    assert runner.run(
        {
            "path": str(source),
            "creates_path": str(tmp_path / "missing"),
            "creates_service": "PresentService",
        }
    ) == (0, {"changed": False, "reboot_required": False, "rc": 0})
    runner.process.assert_not_called()


def test_registry_install_quotes_executable_but_preserves_raw_arguments(
    runner: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "installer file.exe"
    source.write_bytes(b"package")
    monkeypatch.setattr(runner.module.package, "_registry_location", lambda _id: None)
    code, result = runner.run(
        {"path": str(source), "provider": "registry", "arguments": "/quiet"}
    )
    assert code == 0 and result["changed"] is True
    assert runner.process.call_args.args[1] == f'"{source}" /quiet'
    assert runner.process.call_args.args[2]["output_encoding_override"] == "utf-8"
    runner.read.assert_not_called()


def test_registry_removal_prefers_existing_quiet_string_and_expands_prefix(
    runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    location = {
        "path": r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Owned",
        "values": {
            "QuietUninstallString": '"%SystemRoot%\\owned.exe" /quiet',
            "UninstallString": "must-not-run",
        },
    }
    monkeypatch.setattr(
        runner.module.package, "_registry_location", lambda _id: location
    )
    code, result = runner.run(
        {"provider": "registry", "state": "absent", "product_id": "Owned"}
    )
    assert code == 0 and result["changed"] is True
    assert runner.process.call_args.args[1] == '"C:\\Windows\\owned.exe" /quiet'
    runner.read.assert_not_called()


def test_registry_key_without_uninstall_string_fails_without_process(
    runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    location = {"path": r"HKCU:\SOFTWARE\Uninstall\Owned", "values": {}}
    monkeypatch.setattr(
        runner.module.package, "_registry_location", lambda _id: location
    )
    code, result = runner.run(
        {"provider": "registry", "state": "absent", "product_id": "Owned"}
    )
    assert code == 1 and result["changed"] is False and result["rc"] == 0
    assert result["msg"] == (
        "Failed to find registry uninstall string at registry path "
        "'HKCU:\\SOFTWARE\\Uninstall\\Owned'"
    )
    runner.process.assert_not_called()


def test_unexpected_return_code_retains_streams_and_unchanged_false(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    runner.process.return_value.update(rc=1603, stdout="output", stderr="error")
    code, result = runner.run({"path": str(source)})
    assert code == 1 and result["changed"] is False and result["rc"] == 1603
    assert (
        result["failed"] is True
        and result["stdout"] == "output"
        and result["stderr"] == "error"
    )
    assert result["msg"].startswith("unexpected rc from '")


def test_allowed_3010_reports_reboot_without_restarting_host(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    runner.process.return_value["rc"] = 3010
    assert runner.run({"path": str(source)})[1]["reboot_required"] is True


def test_return_code_is_compared_as_signed_32_bit_value(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "local.msi"
    source.write_bytes(b"package")
    runner.process.return_value["rc"] = 4294967295
    result = runner.run({"path": str(source), "expected_return_code": [-1]})
    assert result[0] == 0 and result[1]["rc"] == -1 and result[1]["failed"] is False


def test_msp_without_applicable_installed_product_fails_before_changes(
    runner: Any, tmp_path: Path
) -> None:
    source = tmp_path / "patch.msp"
    source.write_bytes(b"patch")
    assert runner.run({"path": str(source), "provider": "msp"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": (
                "Unhandled exception while executing module: "
                "The specified patch does not apply to any installed MSI packages."
            ),
        },
    )
    runner.process.assert_not_called()
    runner.read.assert_not_called()


@pytest.mark.parametrize("preview", [False, True])
def test_msp_not_applied_to_existing_product_installs_or_previews(
    runner: Any, tmp_path: Path, preview: bool
) -> None:
    source = tmp_path / "renamed.exe"
    source.write_bytes(b"patch")
    runner.installer.package_type.return_value = "msp"
    runner.installer.product_state.return_value = 5
    runner.installer.patch_state.side_effect = OSError(1647, "Unknown patch")
    code, result = runner.run({"path": str(source), "_ansible_check_mode": preview})
    assert code == 0 and result["changed"] is True
    assert result["rc"] == 0 and result["reboot_required"] is False
    assert runner.process.call_count == int(not preview)
    if not preview:
        assert "/update " in runner.process.call_args.args[1]
        runner.read.assert_called_once_with(str(source))


@pytest.fixture(name="semicolon_patch")
def semicolon_patch_source(
    runner: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Any:
    """Use an owned source and a real local link at the native process boundary.

    :param runner: Public Package payload and observable installer.
    :param tmp_path: Owned sources and temporary-link location.
    :param monkeypatch: Scoped target temporary directory and random name.
    :returns: Original source and the unique expected temporary link.
    """
    source = tmp_path / "semi;colon patch.msp"
    source.write_bytes(b"patch")
    runner.installer.package_type.return_value = "msp"
    runner.installer.product_state.return_value = 5
    runner.installer.patch_state.side_effect = OSError(1647, "Unknown patch")
    monkeypatch.setattr(
        runner.module.package.tempfile, "gettempdir", lambda: str(tmp_path)
    )
    monkeypatch.setattr(
        runner.module.package.uuid, "uuid4", lambda: SimpleNamespace(hex="owned")
    )
    return SimpleNamespace(source=source, link=tmp_path / "win_package-owned.msp")


@pytest.mark.parametrize("installer_result", [0, 1603, OSError("installer failed")])
def test_semicolon_link_lives_through_installer_and_is_removed_on_all_exits(
    runner: Any, semicolon_patch: Any, installer_result: int | OSError
) -> None:
    def _process(_executable: Any, command: str, parameters: Any) -> Any:
        assert runner.read.call_args.args == (str(semicolon_patch.source),)
        if " /c mklink " in command:
            assert str(semicolon_patch.source) in command
            assert parameters == {
                "chdir": None,
                "stdin": None,
                "output_encoding_override": "utf-8",
            }
            semicolon_patch.link.symlink_to(semicolon_patch.source)
            return {"changed": True, "rc": 0, "stdout": "", "stderr": ""}
        assert " /update " in command and ";" not in command
        assert semicolon_patch.link.read_bytes() == b"patch"
        if isinstance(installer_result, OSError):
            raise installer_result
        return {
            "changed": True,
            "rc": installer_result,
            "stdout": "out",
            "stderr": "err",
        }

    runner.process.side_effect = _process
    code, result = runner.run({"path": str(semicolon_patch.source)})
    assert code == int(installer_result != 0) and result["changed"] is (
        installer_result == 0
    )
    assert runner.process.call_count == 2
    assert not semicolon_patch.link.is_symlink()
    assert semicolon_patch.source.read_bytes() == b"patch"


@pytest.mark.parametrize("partial_link", [False, True])
def test_semicolon_link_failure_retains_streams_and_never_starts_installer(
    runner: Any, semicolon_patch: Any, partial_link: bool
) -> None:
    def _mklink(*_args: Any) -> Any:
        if partial_link:
            semicolon_patch.link.symlink_to(semicolon_patch.source)
        return {
            "changed": True,
            "rc": 1,
            "stdout": "out",
            "stderr": "permission denied",
        }

    runner.process.side_effect = _mklink
    code, result = runner.run({"path": str(semicolon_patch.source)})
    assert code == 1 and not result["changed"]
    assert result["rc"] == 1 and result["stdout"] == "out"
    assert result["stderr"] == "permission denied"
    assert result["msg"] == (
        f"Failed to create temporary symlink '{semicolon_patch.link}' -> "
        f"'{semicolon_patch.source}' for msiexec patch install as path contains semicolon"
    )
    runner.process.assert_called_once()
    assert not semicolon_patch.link.is_symlink()


@pytest.mark.parametrize("check,applied", [(True, False), (False, True), (True, True)])
def test_semicolon_preview_and_idempotence_do_not_create_links(
    runner: Any, semicolon_patch: Any, check: bool, applied: bool
) -> None:
    if applied:
        runner.installer.patch_state.side_effect = None
        runner.installer.patch_state.return_value = 1
    code, result = runner.run(
        {"path": str(semicolon_patch.source), "_ansible_check_mode": check}
    )
    assert code == 0 and result["changed"] is (not applied)
    runner.read.assert_not_called()
    runner.process.assert_not_called()
    assert not semicolon_patch.link.is_symlink()


def test_semicolon_link_collision_is_not_deleted_or_adopted(
    runner: Any, semicolon_patch: Any
) -> None:
    semicolon_patch.link.write_bytes(b"foreign")
    code, result = runner.run({"path": str(semicolon_patch.source)})
    assert code == 1 and "Temporary patch link already exists" in result["msg"]
    runner.process.assert_not_called()
    assert semicolon_patch.link.read_bytes() == b"foreign"


def test_semicolon_mklink_does_not_use_the_installer_child_wait_policy(
    runner: Any, semicolon_patch: Any, package_children: Any
) -> None:
    def _mklink(*_args: Any) -> Any:
        semicolon_patch.link.symlink_to(semicolon_patch.source)
        return {"changed": True, "rc": 0, "stdout": "", "stderr": ""}

    runner.process.side_effect = _mklink
    code, result = runner.run(
        {"path": str(semicolon_patch.source), "wait_for_children": True}
    )
    assert code == 0 and result["changed"]
    runner.process.assert_called_once()
    assert " /c mklink " in runner.process.call_args.args[1]
    package_children.run_command.assert_called_once()
    assert " /update " in package_children.run_command.call_args.args[1]
    assert not semicolon_patch.link.is_symlink()


@pytest.mark.parametrize("context", [1, 2, 4])
def test_msp_applied_context_removal_without_path_uses_patch_and_product(
    runner: Any, context: int
) -> None:
    patch = "{224C316C-5894-4771-BABF-21A3AC1F75FF}"
    runner.installer.patches.return_value = [
        {"patch": patch.lower(), "product": "Product", "context": context}
    ]
    code, result = runner.run({"product_id": patch, "state": "absent"})
    assert code == 0 and result["changed"] is True
    assert (
        "/uninstall " + patch + " /package Product" in runner.process.call_args.args[1]
    )
    runner.installer.patch_state.assert_called_with(patch, "Product", context)
    runner.read.assert_not_called()


def test_msp_multi_product_removal_retains_encounter_order_and_stops_on_failure(
    runner: Any,
) -> None:
    patch = "{224C316C-5894-4771-BABF-21A3AC1F75FF}"
    runner.installer.patches.return_value = [
        {"patch": patch, "product": product, "context": 4}
        for product in ("First", "First", "Second", "NeverRun")
    ]
    runner.process.side_effect = [
        {"changed": True, "rc": 0, "stdout": "", "stderr": ""},
        {"changed": True, "rc": 1603, "stdout": "out", "stderr": "err"},
    ]
    code, result = runner.run(
        {"provider": "msp", "product_id": patch, "state": "absent"}
    )
    assert code == 1 and result["changed"] is False
    assert result["rc"] == 1603 and result["stdout"] == "out"
    commands = [call.args[1] for call in runner.process.call_args_list]
    assert len(commands) == 2
    assert "/package First " in commands[0] and "/package Second " in commands[1]


def test_msp_skip_preserves_measured_string_length_not_list_count(runner: Any) -> None:
    patch = "Patch"
    products = ["{" + str(index).zfill(36) + "}" for index in range(38)]
    runner.installer.patches.return_value = [
        {"patch": patch, "product": product, "context": 4} for product in products
    ] + [{"patch": patch, "product": "{" + "x" * 36 + "}", "context": 4}]
    runner.installer.patch_state.side_effect = [1] * 38 + [2]
    code, result = runner.run(
        {"provider": "msp", "product_id": patch, "state": "absent"}
    )
    assert code == 0 and result["changed"] is False
    runner.process.assert_not_called()


def test_msp_registered_patch_is_not_treated_as_applied(runner: Any) -> None:
    runner.installer.patches.return_value = [
        {"patch": "Patch", "product": "Product", "context": 4}
    ]
    runner.installer.patch_state.return_value = 8
    code, result = runner.run(
        {"provider": "msp", "product_id": "Patch", "state": "absent"}
    )
    assert code == 0 and result["changed"] is False
    runner.process.assert_not_called()


def test_msp_multi_product_removal_retains_earlier_reboot_request(runner: Any) -> None:
    runner.installer.patches.return_value = [
        {"patch": "Patch", "product": product, "context": 4}
        for product in ("First", "Second")
    ]
    runner.process.side_effect = [
        {"changed": True, "rc": 3010, "stdout": "", "stderr": ""},
        {"changed": True, "rc": 0, "stdout": "", "stderr": ""},
    ]
    code, result = runner.run(
        {"provider": "msp", "product_id": "Patch", "state": "absent"}
    )
    assert code == 0 and result["rc"] == 0 and result["reboot_required"] is True


@pytest.mark.parametrize(
    "kind,expected", [("msi", "msi"), ("msp", "msix"), (None, "msix")]
)
def test_automatic_file_selection_preserves_source_msi_msix_msp_order(
    runner: Any, kind: str | None, expected: str
) -> None:
    runner.installer.package_type.return_value = kind
    assert (
        runner.module.package._select_provider(
            runner.installer, "renamed.msix", None, "auto"
        )
        == expected
    )
