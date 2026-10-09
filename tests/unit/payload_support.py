"""Load and run target payloads with the developer interpreter for unit tests."""

# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "plugins" / "module_utils" / "legacy_windows_module.py"


def load_module(source: Path, name: str) -> ModuleType:
    """Import a target source file without running its script entry point.

    :param source: Python source file to import.
    :param name: Isolated module name for the imported source.
    :returns: A fresh module object without adding it to the import cache.
    """
    spec = importlib.util.spec_from_file_location(name, source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_error(code: int) -> OSError:
    """Build the portable native-error substitute used by boundary tests.

    :param code: Windows error code exposed as the exception's errno.
    :returns: The error without consulting host-specific Windows facilities.
    """
    return OSError(code, "native failure")


def load_payload(name: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import a payload with adjacent helpers and deterministic number symbols.

    :param name: Payload basename without the Python suffix.
    :param monkeypatch: Scoped import-path and locale substitutes.
    :returns: The payload without executing its JSON entry point.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    source = ROOT / "plugins" / "modules" / (name + ".py")
    module = load_module(source, "tested_" + name)
    helper = sys.modules["legacy_windows_module"]
    monkeypatch.setattr(helper, "_number_symbols", lambda: (".", "+", "-"))
    return module


def invoke_payload(
    payload: ModuleType, capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, Any]]:
    """Call a loaded payload's entry point and validate its JSON output.

    The caller supplies the argument file through ``sys.argv`` and replaces
    any native boundaries before calling this function.

    :param payload: Loaded module exposing its ``main`` entry point.
    :param capsys: Scoped stdout and stderr capture.
    :returns: Integer exit status and decoded JSON result.
    """
    with pytest.raises(SystemExit) as exited:
        payload.main()
    assert isinstance(exited.value.code, int)
    captured = capsys.readouterr()
    assert captured.err == ""
    return exited.value.code, json.loads(captured.out)


def run_payload(
    name: str,
    tmp_path: Path,
    arguments: object,
    *,
    entrypoint_code: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    """Stage a native payload's helpers and exercise its JSON process contract.

    :param name: Payload basename without the Python suffix.
    :param tmp_path: Isolated test directory for staged files and arguments.
    :param arguments: JSON-serializable module arguments.
    :param entrypoint_code: Optional Python code to replace a native boundary
        before calling the payload entry point; the argument path remains argv[1].
    :returns: The completed process and its decoded JSON response.
    """
    payload_directory = tmp_path / "payload"
    payload_directory.mkdir(exist_ok=True)
    source = ROOT / "plugins" / "modules" / (name + ".py")
    module_path = payload_directory / source.name
    shutil.copyfile(source, module_path)
    shutil.copyfile(HELPER, payload_directory / HELPER.name)
    if name in ("win_command", "win_shell"):
        for filename in ("legacy_windows_process.py", "legacy_windows_text.py"):
            shutil.copyfile(HELPER.parent / filename, payload_directory / filename)
    argument_file = tmp_path / "arguments.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    command = (
        [sys.executable, str(module_path), str(argument_file)]
        if entrypoint_code is None
        else [sys.executable, "-c", entrypoint_code, str(argument_file)]
    )
    process = subprocess.run(
        command,
        cwd=payload_directory,
        capture_output=True,
        text=True,
        check=False,
    )
    assert not process.stderr
    return process, json.loads(process.stdout)
