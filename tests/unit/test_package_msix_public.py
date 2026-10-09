"""Exercise the real Package public binding and dedicated MSIX dispatch path."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Exercise the real binding function instead of duplicating parameter conversion.
# pylint: disable=protected-access

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="public")
def public_payload(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Bind the real private payload to observable package-provider boundaries.

    :param monkeypatch: Scoped adjacent imports and native provider substitutes.
    :returns: Payload, decision helper and observed native MSIX manager.
    """
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(root / "plugins/module_utils"))
    decision = load_module(
        root / "plugins/module_utils/legacy_windows_package.py", "msix_decision"
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_package", decision)
    payload = load_module(root / "plugins/modules/win_package.py", "msix_public")
    installer = MagicMock()
    installer.__enter__.return_value = installer
    installer.product_state.return_value = -1
    installer.patches.return_value = []
    monkeypatch.setattr(decision, "WindowsInstaller", lambda: installer)
    manager = MagicMock()
    manager.__enter__.return_value = manager
    provider = SimpleNamespace(
        available=lambda: True,
        installed_status=Mock(return_value={"id": "Owned_Full", "installed": False}),
        PackageManager=Mock(return_value=manager),
        PackageApiError=load_module(
            root / "plugins/module_utils/legacy_windows_package_msix.py",
            "msix_api_error",
        ).PackageApiError,
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_package_msix", provider)
    runner = Mock(
        side_effect=AssertionError("MSIX must not launch an installer process")
    )
    monkeypatch.setattr(decision.processes, "run_command", runner)
    return SimpleNamespace(
        payload=payload,
        decision=decision,
        provider=provider,
        manager=manager,
        runner=runner,
        installer=installer,
    )


def test_msix_install_ignores_executable_options_and_returns_normal_package_digest(
    public: Any, tmp_path: Path
) -> None:
    source = tmp_path / "owned.appx"
    source.write_bytes(b"owned signed package")
    options = public.payload._parameters(
        {
            "path": str(source),
            "provider": "MSIX",
            "arguments": "ignored",
            "expected_return_code": [99],
            "chdir": str(tmp_path / "missing"),
            "log_path": str(tmp_path / "ignored.log"),
            "wait_for_children": True,
        }
    )
    assert public.decision.manage(options) == {
        "changed": True,
        "reboot_required": False,
        "rc": 0,
        "checksum": hashlib.sha1(source.read_bytes()).hexdigest().upper(),
    }
    public.manager.install.assert_called_once_with(str(source))
    public.manager.remove.assert_not_called()
    public.runner.assert_not_called()


@pytest.mark.parametrize(
    "check,installed", [(True, False), (False, True), (True, True)]
)
def test_msix_preview_and_idempotence_do_not_create_a_deployment_operation(
    public: Any, tmp_path: Path, check: bool, installed: bool
) -> None:
    source = tmp_path / "owned.msix"
    source.write_bytes(b"package")
    public.provider.installed_status.return_value["installed"] = installed
    options = public.payload._parameters({"path": str(source), "provider": "msix"})
    assert public.decision.manage(options, check) == {
        "changed": not installed,
        "reboot_required": False,
        "rc": 0,
    }
    public.provider.PackageManager.assert_not_called()
    public.runner.assert_not_called()


def test_auto_removal_resolves_name_before_msp_and_passes_only_the_full_name(
    public: Any,
) -> None:
    public.provider.installed_status.return_value["installed"] = True
    options = public.payload._parameters({"product_id": "Owned*", "state": "absent"})
    assert public.decision.manage(options) == {
        "changed": True,
        "reboot_required": False,
        "rc": 0,
    }
    public.provider.installed_status.assert_called_with(None, "Owned*")
    public.manager.remove.assert_called_once_with("Owned_Full")
    public.installer.patches.assert_not_called()
    public.runner.assert_not_called()


@pytest.mark.parametrize("extension", ["appx", "appxbundle", "msix", "msixbundle"])
def test_auto_archive_selection_previews_msix_without_an_installer_process(
    public: Any, tmp_path: Path, extension: str
) -> None:
    source = tmp_path / ("owned." + extension)
    source.write_bytes(b"package")
    public.installer.package_type.return_value = None
    options = public.payload._parameters({"path": str(source)})
    assert public.decision.manage(options, True) == {
        "changed": True,
        "reboot_required": False,
        "rc": 0,
    }
    public.provider.installed_status.assert_called_once_with(str(source), None)
    public.installer.product_code.assert_not_called()
    public.runner.assert_not_called()


def test_native_msi_metadata_takes_priority_over_an_msix_archive_extension(
    public: Any, tmp_path: Path
) -> None:
    source = tmp_path / "owned.appx"
    source.write_bytes(b"MSI database")
    public.installer.package_type.return_value = "msi"
    options = public.payload._parameters({"path": str(source)})
    assert public.decision.manage(options, True) == {
        "changed": True,
        "reboot_required": False,
        "rc": 0,
    }
    public.installer.product_code.assert_called_once_with(str(source))
    public.provider.installed_status.assert_not_called()
    public.runner.assert_not_called()


def test_bad_checksum_fails_before_any_native_msix_deployment(
    public: Any, tmp_path: Path
) -> None:
    source = tmp_path / "owned.appx"
    source.write_bytes(b"package")
    options = public.payload._parameters(
        {"path": str(source), "provider": "msix", "checksum": "wrong"}
    )
    result = public.decision.manage(options)
    assert result["failed"] is True and result["changed"] is False and result["rc"] == 0
    assert result["checksum"] == hashlib.sha1(source.read_bytes()).hexdigest().upper()
    public.provider.PackageManager.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("hresult", [-2147009255, -2147024891])
def test_msix_deployment_failures_retain_hresult_and_complete_provider_output(
    public: Any, tmp_path: Path, state: str, hresult: int
) -> None:
    # The access-denied fallback is a controller contract case, not Windows proof.
    source = tmp_path / "owned.appx"
    source.write_bytes(b"package")
    request = {"provider": "msix", "state": state}
    if state == "present":
        request["path"] = str(source)
        operation = public.manager.install
        command = "Add-AppxPackage"
    else:
        request["product_id"] = "Owned_Full"
        public.provider.installed_status.return_value["installed"] = True
        operation = public.manager.remove
        command = "Remove-AppxPackage"
    operation.side_effect = public.provider.PackageApiError(
        hresult, "deployment", "complete native deployment diagnostic\r\n"
    )
    result = public.decision.manage(public.payload._parameters(request))
    expected = {
        "changed": False,
        "failed": True,
        "reboot_required": False,
        "rc": hresult,
        "stdout": "",
        "stderr": "complete native deployment diagnostic\r\n",
        "msg": f"unexpected status from {command}: see rc and stderr for more details",
    }
    if state == "present":
        expected["checksum"] = hashlib.sha1(source.read_bytes()).hexdigest().upper()
    assert result == expected
    public.manager.__exit__.assert_called_once()


def test_failed_cleanup_is_saved_before_recovery_blocks_workspace_removal(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    fixture = yaml.safe_load(
        (root / "tests/integration/win_package_msix.yml").read_text()
    )
    cleanup, preserve, gate = next(
        task["always"][:3] for task in fixture[0]["tasks"] if "always" in task
    )
    # Run the maintained preservation/gate through real controller Ansible.
    # Only the Windows cleanup operation is replaced with a failing local child.
    del cleanup["sustainablelobster.legacy_windows.win_command"]
    cleanup["ansible.builtin.command"] = {
        "argv": [sys.executable, "-c", "print('owned cleanup failed'); exit(7)"]
    }
    workspace = tmp_path / "owned-workspace"
    workspace.mkdir()
    play = {
        "name": "Verify failed MSIX cleanup capture without Windows access",
        "hosts": "localhost",
        "connection": "local",
        "gather_facts": False,
        "vars": {
            "ansible_python_interpreter": sys.executable,
            "package_msix_workspace": {"path": str(workspace)},
            "package_msix_results": [{"partial": "retained"}],
            "package_msix_capture_prefix": str(tmp_path / "capture"),
        },
        "tasks": [
            cleanup,
            preserve,
            gate,
            {
                "name": "Remove only a successfully recovered workspace",
                "ansible.builtin.file": {"path": str(workspace), "state": "absent"},
            },
        ],
    }
    playbook = tmp_path / "failed-cleanup.yml"
    playbook.write_text(yaml.safe_dump([play]))
    environment = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-tmp"))
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.playbook",
            "-i",
            "localhost,",
            str(playbook),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    # pylint: enable=duplicate-code
    assert completed.returncode == 2, completed.stdout + completed.stderr
    capture = json.loads((tmp_path / "capture-localhost.json").read_text())
    assert capture["cleanup"]["rc"] == 7
    assert capture["cleanup"]["stdout"] == "owned cleanup failed"
    assert capture["results"] == [{"partial": "retained"}]
    assert workspace.is_dir()
