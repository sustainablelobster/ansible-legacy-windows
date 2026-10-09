"""Check the JSON contract and native reader ownership without a Windows target."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundaries are replaced explicitly; these are not Windows sharing tests.
# pylint: disable=protected-access

import base64
import ctypes
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import load_payload, run_payload


@pytest.fixture(name="payload")
def slurp_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the target module with its adjacent helper available.

    :param monkeypatch: Scoped import-path changes.
    :returns: The loaded payload without executing its entry point.
    """
    return load_payload("slurp", monkeypatch)


def _run(
    tmp_path: Path, arguments: object, *, emulate_reader: bool = False
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    entrypoint_code = None
    if emulate_reader:
        # Exercise the real standalone JSON lifecycle, replacing only the
        # Windows handle opener with a developer-side binary file reader.
        entrypoint_code = (
            "import sys; from pathlib import Path; import slurp; "
            "slurp._read_bytes = lambda path: Path(path).read_bytes(); "
            "slurp.main()"
        )
    return run_payload("slurp", tmp_path, arguments, entrypoint_code=entrypoint_code)


@pytest.mark.parametrize(
    "contents", [b"", bytes(range(256)), b"first\r\n\x00\xfflast\n"]
)
@pytest.mark.parametrize("check_mode", [False, True])
def test_exact_binary_contents_are_unchanged_and_repeatable(
    tmp_path: Path, contents: bytes, check_mode: bool
) -> None:
    source = tmp_path / "data [literal] \u96ea.bin"
    source.write_bytes(contents)
    arguments = {"src": str(source), "_ansible_check_mode": check_mode}

    first_process, first = _run(tmp_path, arguments, emulate_reader=True)
    second_process, second = _run(tmp_path, arguments, emulate_reader=True)

    assert first_process.returncode == second_process.returncode == 0
    assert first == second
    assert first == {
        "changed": False,
        "content": base64.b64encode(contents).decode("ascii"),
        "encoding": "base64",
    }
    assert source.read_bytes() == contents
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("name", ["src", "path", "SrC", "PATH"])
def test_source_alias_and_parameter_casing(tmp_path: Path, name: str) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"alias")

    process, result = _run(tmp_path, {name: str(source)}, emulate_reader=True)

    assert process.returncode == 0
    assert result["content"] == "YWxpYXM="


def test_primary_source_wins_alias_and_unknown_options_are_ignored(
    tmp_path: Path,
) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"primary")

    process, result = _run(
        tmp_path,
        {
            "src": str(source),
            "path": str(tmp_path / "missing"),
            "armor": False,
            "unexpected": "private value",
        },
        emulate_reader=True,
    )

    assert process.returncode == 0
    assert result == {"changed": False, "content": "cHJpbWFyeQ==", "encoding": "base64"}
    assert "private value" not in process.stdout


@pytest.mark.parametrize("source", [None, ""])
def test_invalid_primary_source_does_not_fall_back_to_valid_alias(
    tmp_path: Path, source: object
) -> None:
    alias = tmp_path / "data.bin"
    alias.write_bytes(b"do not read")

    process, result = _run(tmp_path, {"src": source, "path": str(alias)})

    assert process.returncode == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "Specify a nonempty file path for src.",
    }


@pytest.mark.parametrize("arguments", [{}, {"unknown": "ignored"}])
def test_missing_source_is_an_actionable_failure(
    tmp_path: Path, arguments: object
) -> None:
    process, result = _run(tmp_path, arguments)

    assert process.returncode == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "Missing required argument: src.",
    }


@pytest.mark.parametrize("source", [None, "", "wild*card", "wild?card", "null\x00byte"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_invalid_paths_fail_before_opening(
    tmp_path: Path, source: object, check_mode: bool
) -> None:
    process, result = _run(
        tmp_path, {"path": source, "_ansible_check_mode": check_mode}
    )

    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert "path" in str(result["msg"])
    assert "exception" not in result


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_missing_file_and_directory_are_unchanged_failures(
    tmp_path: Path, directory: bool, check_mode: bool
) -> None:
    source = tmp_path if directory else tmp_path / "missing.bin"

    process, result = _run(
        tmp_path, {"src": str(source), "_ansible_check_mode": check_mode}
    )

    assert process.returncode == 1
    reason = "is a directory" if directory else "is not found"
    assert result == {
        "changed": False,
        "failed": True,
        "msg": f"Path {source} {reason}",
    }


def test_environment_expansion_is_case_insensitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"environment")
    monkeypatch.setenv("SLURP_TEST_SOURCE", str(source))

    process, result = _run(
        tmp_path, {"src": "%slurp_test_source%"}, emulate_reader=True
    )

    assert process.returncode == 0
    assert result["content"] == "ZW52aXJvbm1lbnQ="


@pytest.mark.parametrize("source", [" ", "   "])
@pytest.mark.parametrize("check_mode", [False, True])
def test_ascii_space_only_source_matches_provider_directory_failure(
    tmp_path: Path, source: str, check_mode: bool
) -> None:
    process, result = _run(tmp_path, {"src": source, "_ansible_check_mode": check_mode})
    assert process.returncode == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": f"Path {source} is a directory",
    }


@pytest.mark.parametrize("source", ["\u00a0", "\u3000", " \u00a0 "])
@pytest.mark.parametrize("check_mode", [False, True])
def test_unicode_whitespace_is_not_trimmed_into_a_directory(
    tmp_path: Path, source: str, check_mode: bool
) -> None:
    process, result = _run(tmp_path, {"src": source, "_ansible_check_mode": check_mode})
    assert process.returncode == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": f"Path {source} is not found",
    }


def _native_reader(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> tuple[SimpleNamespace, Mock, SimpleNamespace]:
    kernel = SimpleNamespace(
        CreateFileW=Mock(return_value=41), CloseHandle=Mock(return_value=1)
    )
    adopt_handle = Mock()
    monkeypatch.setitem(
        sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=adopt_handle)
    )
    # Replace the payload's reference, not global os.name used by pytest/pathlib.
    target_os = SimpleNamespace(
        name="nt",
        O_RDONLY=os.O_RDONLY,
        O_BINARY=0x8000,
        fdopen=os.fdopen,
        close=os.close,
    )
    monkeypatch.setattr(payload, "os", target_os)
    monkeypatch.setattr(
        payload.ctypes, "WinDLL", Mock(return_value=kernel), raising=False
    )
    return kernel, adopt_handle, target_os


def test_native_reader_uses_read_only_sharing_and_closes_adopted_descriptor(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(bytes(range(256)))
    kernel, adopt_handle, _ = _native_reader(payload, monkeypatch)
    descriptor = os.open(source, os.O_RDONLY)
    adopt_handle.return_value = descriptor

    assert payload._read_bytes(str(source)) == bytes(range(256))

    kernel.CreateFileW.assert_called_once_with(
        str(source), 0x80000000, 1, None, 3, 0x80, None
    )
    adopt_handle.assert_called_once_with(41, os.O_RDONLY | 0x8000)
    kernel.CloseHandle.assert_not_called()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_native_open_failure_does_not_adopt_or_close_an_invalid_handle(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel, adopt_handle, _ = _native_reader(payload, monkeypatch)
    kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
    monkeypatch.setattr(payload.ctypes, "get_last_error", lambda: 32, raising=False)
    make_error = Mock(return_value=OSError("sharing violation"))
    monkeypatch.setattr(payload.ctypes, "WinError", make_error, raising=False)

    with pytest.raises(OSError, match="sharing violation"):
        payload._read_bytes("locked.bin")

    make_error.assert_called_once_with(32)
    adopt_handle.assert_not_called()
    kernel.CloseHandle.assert_not_called()


def test_failed_descriptor_adoption_closes_native_handle(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel, adopt_handle, _ = _native_reader(payload, monkeypatch)
    adopt_handle.side_effect = OSError("cannot adopt handle")

    with pytest.raises(OSError, match="cannot adopt handle"):
        payload._read_bytes("data.bin")

    kernel.CloseHandle.assert_called_once_with(41)


def test_failed_file_wrapper_closes_adopted_descriptor(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"data")
    kernel, adopt_handle, target_os = _native_reader(payload, monkeypatch)
    descriptor = os.open(source, os.O_RDONLY)
    adopt_handle.return_value = descriptor
    target_os.fdopen = Mock(side_effect=ValueError("cannot wrap descriptor"))

    with pytest.raises(ValueError, match="cannot wrap descriptor"):
        payload._read_bytes(str(source))

    kernel.CloseHandle.assert_not_called()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_failed_read_closes_file_and_next_read_recovers(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"recovery")
    kernel, adopt_handle, target_os = _native_reader(payload, monkeypatch)
    streams = []

    def _open_file(descriptor: int, mode: str) -> object:
        stream = os.fdopen(descriptor, mode)
        streams.append(stream)
        if len(streams) == 1:
            monkeypatch.setattr(stream, "read", Mock(side_effect=OSError("read error")))
        return stream

    adopt_handle.side_effect = lambda _handle, _flags: os.open(source, os.O_RDONLY)
    target_os.fdopen = _open_file

    with pytest.raises(OSError, match="read error"):
        payload._read_bytes(str(source))
    assert streams[0].closed
    assert payload._read_bytes(str(source)) == b"recovery"
    assert streams[1].closed
    kernel.CloseHandle.assert_not_called()


def test_native_reader_rejects_non_windows_without_opening(payload: ModuleType) -> None:
    if os.name == "nt":
        pytest.skip("The developer platform is Windows")
    with pytest.raises(ValueError, match="requires a Windows target"):
        payload._read_bytes("data.bin")
