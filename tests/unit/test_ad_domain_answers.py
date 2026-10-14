"""Check native answer-file confidentiality, Unicode encoding and cleanup."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# These tests replace the Windows security API at its native boundary.
# pylint: disable=protected-access

import importlib
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize(
    "password", ["FixtureSafeModeSecret2!", "FixtureSafeModeSecret2!é中"]
)
def test_private_answer_restricts_directory_before_writing_and_cleans_up_on_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: bool, password: str
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    native = importlib.import_module("legacy_ad_domain_native")
    security, kernel = Mock(), Mock()
    events: list[str] = []

    def _descriptor(sddl: str, version: int, output: Any, _length: Any) -> bool:
        assert sddl == "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" and version == 1
        output._obj.value = 77
        events.append("restrict")
        return True

    def _directory(path: str, attributes: Any) -> bool:
        assert attributes._obj.descriptor == 77
        assert events == ["restrict"]
        assert not Path(path).exists()
        os.mkdir(path)
        events.append("directory")
        return True

    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect = (
        _descriptor
    )
    kernel.CreateDirectoryW.side_effect = _directory
    monkeypatch.setattr(
        native.ctypes,
        "WinDLL",
        lambda name, **_kwargs: security if name == "advapi32" else kernel,
        raising=False,
    )
    monkeypatch.setattr(native.tempfile, "gettempdir", lambda: str(tmp_path))

    def _run() -> None:
        with native._private_answer({"SafeModeAdminPassword": password}) as answer:
            assert events == ["restrict", "directory"]
            contents = '[DCINSTALL]\r\nSafeModeAdminPassword="' + password + '"\r\n'
            expected = (
                (b"\xff\xfe" + contents.encode("utf-16-le"))
                if "é" in password
                else contents.encode("ascii")
            )
            assert Path(answer).read_bytes() == expected
            if failure:
                raise ValueError("native consumer failed")

    if failure:
        with pytest.raises(ValueError, match="consumer"):
            _run()
    else:
        _run()
    assert not list(tmp_path.iterdir())
    kernel.LocalFree.assert_called_once()
    assert kernel.LocalFree.call_args[0][0].value == 77


@pytest.mark.parametrize("failure", ["start", "communicate"])
def test_native_runner_failure_cleans_its_answer_without_claiming_success(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    native = importlib.import_module("legacy_ad_domain_native")
    engine = native.PromotionEngine.__new__(native.PromotionEngine)
    engine.path, engine.help = "native-dcpromo.exe", "SafeModeAdminPassword"
    engine.legacy_answer_format = False
    process = MagicMock()
    process.__enter__.return_value = process
    process.returncode = None
    process.communicate.side_effect = OSError("Native communication failed")
    start = Mock(return_value=process)
    if failure == "start":
        start.side_effect = OSError("Native process start failed")
    monkeypatch.setattr(native.subprocess, "Popen", start)
    events: list[str] = []

    @contextmanager
    def _answer(settings: dict[str, str]) -> Any:
        assert settings == {"SafeModeAdminPassword": "FixtureSafeModeSecret2!"}
        events.append("create")
        try:
            yield "restricted-answer.ini"
        finally:
            events.append("cleanup")

    monkeypatch.setattr(native, "_private_answer", _answer)
    with pytest.raises(OSError, match="Native") as caught:
        engine.run({"SafeModeAdminPassword": "FixtureSafeModeSecret2!"})
    assert not getattr(caught.value, "promotion_completed", False)
    assert events == ["create", "cleanup"]
    assert process.communicate.call_count == int(failure == "communicate")
    assert process.__exit__.call_count == int(failure == "communicate")


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_native_observer_cleans_its_script_and_preserves_existing_answer_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    directory: bool,
    failure: bool,
) -> None:
    observer = load_module(
        ROOT / "tests/integration/fixtures/legacy_ad_domain_observer.py",
        "tested_domain_observer",
    )
    existing = tmp_path / "legacy-ad-promotion-unrelated"
    existing.mkdir()
    monkeypatch.setattr(observer.tempfile, "tempdir", str(tmp_path))
    monkeypatch.setenv("SystemRoot", r"C:\Windows")

    def _read(command: list[str], **kwargs: Any) -> bytes:
        assert command[:3] == [
            os.path.join(r"C:\Windows", "System32", "cscript.exe"),
            "//Nologo",
            "//U",
        ]
        assert command[4:] == (["directory"] if directory else [])
        assert kwargs == {"stderr": subprocess.STDOUT}
        assert 'GetObject("LDAP://RootDSE")' in Path(command[3]).read_text(
            encoding="ascii"
        )
        if failure:
            raise subprocess.CalledProcessError(1, command, b"native provider failed")
        values = [
            "20261014090000.000000+000",
            "OwnedDC",
            "example.test",
            "5",
            "Running" if directory else "absent",
        ]
        if directory:
            values.extend(["2", "2", "2"])
        return ("\ufeff" + "\r\n".join(values) + "\r\n").encode("utf-16-le")

    monkeypatch.setattr(observer.subprocess, "check_output", _read)
    if failure:
        with pytest.raises(subprocess.CalledProcessError):
            observer.observe(directory=directory)
    else:
        result = observer.observe(directory=directory)
        assert result["boot_id"] == "20261014090000.000000+000"
        assert result["hostname"] == "OwnedDC" and result["domain"] == "example.test"
        assert result["role"] == 5
        assert result["dns_service_state"] == ("Running" if directory else "absent")
        assert result["answer_directories"] == [str(existing)]
        for name in ("controller_level", "domain_level", "forest_level"):
            assert result.get(name) == (2 if directory else None)
    assert list(tmp_path.iterdir()) == [existing]
