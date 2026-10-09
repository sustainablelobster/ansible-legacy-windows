"""Check native signature policy results and resource ownership boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native structures are inspected to validate ABI arguments and owned cleanup.
# pylint: disable=protected-access

import ctypes
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="signature")
def signature_helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the actual Python3.4 signature helper without native DLL initialization.

    :param monkeypatch: Scoped sibling-helper import path.
    :returns: Concrete native signature module.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        HELPER.parent / "legacy_windows_package_signature.py", "signature"
    )


def native_file_policy(
    signature: Any, monkeypatch: pytest.MonkeyPatch, code: int
) -> Any:
    """Replace the DLL call while retaining concrete native request structures.

    :param signature: Actual signature helper.
    :param monkeypatch: Scoped native library substitution.
    :param code: Observable verification return code.
    :returns: Native-call recorder.
    """

    def _verify(_window: Any, _guid: Any, reference: Any) -> int:
        data = reference._obj
        assert data.ui == 2 and data.revocation == 0 and data.flags == 0
        if data.action == 1:
            assert data.choice == 1
            information = ctypes.cast(
                data.information, ctypes.POINTER(signature._FileInfo)
            ).contents
            assert information.size == ctypes.sizeof(signature._FileInfo)
            assert information.path == "owned package.msi"
            data.state = 123
            return code
        assert data.action == 2 and data.state == 123
        return 0

    library = SimpleNamespace(WinVerifyTrust=Mock(side_effect=_verify))
    monkeypatch.setattr(
        signature.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    return library


@pytest.mark.parametrize(
    "code,expected",
    [
        (0, "Valid"),
        (0x80090008, "Incompatible"),
        (0x800B0100, "NotSigned"),
        (0x80096010, "HashMismatch"),
        (0x8009200D, "HashMismatch"),
        (0x800B0001, "NotSupportedFileFormat"),
        (0x800B0111, "NotTrusted"),
        (0x800B0109, "UnknownError"),
    ],
)
def test_file_verification_maps_released_status_and_always_closes_state(
    signature: Any, monkeypatch: pytest.MonkeyPatch, code: int, expected: str
) -> None:
    library = native_file_policy(signature, monkeypatch, ctypes.c_int32(code).value)
    assert signature.status("owned package.msi") == expected
    assert library.WinVerifyTrust.call_count == 2


@pytest.mark.parametrize("state,valid", [(5, True), (6, True), (7, False), (3, False)])
def test_catalog_verification_keeps_file_open_through_state_and_certificate_cleanup(
    signature: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: int,
    valid: bool,
) -> None:
    path = tmp_path / "owned catalog file.exe"
    path.write_bytes(b"protected input")
    descriptor: list[int] = []

    def _descriptor(value: int) -> int:
        descriptor.append(value)
        return 777

    monkeypatch.setitem(
        sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=_descriptor)
    )

    # These six arguments are the real native API boundary, not a test helper API.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _catalog(
        actual: str,
        handle: int,
        flags: int,
        information: Any,
        certificate: Any,
        trust: Any,
    ) -> int:
        assert actual == str(path) and handle == 777 and flags == 0x3803
        information._obj.state = state
        certificate._obj.value, trust._obj.value = 123, 456
        return 0

    def _close(_window: Any, _guid: Any, reference: Any) -> int:
        assert os.fstat(descriptor[0]).st_size == 15
        assert reference._obj.action == 2 and reference._obj.state == 456
        assert reference._obj.choice == 3
        return 0

    library = SimpleNamespace(
        WTGetSignatureInfo=Mock(side_effect=_catalog),
        WinVerifyTrust=Mock(side_effect=_close),
    )
    crypt = SimpleNamespace(CertFreeCertificateContext=Mock(return_value=1))
    monkeypatch.setattr(
        signature.ctypes, "WinDLL", Mock(return_value=crypt), raising=False
    )
    assert signature._catalog_valid(library, str(path)) is valid
    library.WinVerifyTrust.assert_called_once()
    crypt.CertFreeCertificateContext.assert_called_once()
    assert path.read_bytes() == b"protected input"


def test_valid_catalog_does_not_run_the_embedded_signature_fallback(
    signature: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = SimpleNamespace(WinVerifyTrust=Mock())
    monkeypatch.setattr(
        signature.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    monkeypatch.setattr(signature, "_catalog_valid", Mock(return_value=True))
    assert signature.status("owned catalog file.exe") == "Valid"
    library.WinVerifyTrust.assert_not_called()


@pytest.mark.parametrize("state", ["NotSigned", "HashMismatch", "UnknownError"])
def test_invalid_signature_has_the_complete_released_package_message(
    signature: Any, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    monkeypatch.setattr(signature, "status", Mock(return_value=state))
    with pytest.raises(ValueError) as error:
        signature.verify("owned package.msi")
    assert str(error.value) == (
        "Authenticode check failed: File 'owned package.msi': "
        f"signature status is '{state}', expected 'Valid'"
    )


def test_signature_input_error_is_reported_without_accepting_the_file(
    signature: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        signature, "status", Mock(side_effect=OSError("cannot read owned input"))
    )
    with pytest.raises(
        ValueError, match="Authenticode check failed: cannot read owned input"
    ):
        signature.verify("owned package.msi")


@pytest.mark.parametrize(
    "path,selected",
    [
        (r"C:\owned\plain.exe", [r"C:\owned\plain.exe"]),
        (r"C:\owned\unmatched[7].exe", []),
        (r"C:\owned\matched[1].exe", [r"C:\owned\matched1.exe"]),
        (
            r"C:\owned\multiple[12].exe",
            [r"C:\owned\multiple1.exe", r"C:\owned\multiple2.exe"],
        ),
        (r"C:\owned\tick`x.exe", [r"C:\owned\tick`x.exe"]),
        (r"C:\owned\escaped`[1`].exe", [r"C:\owned\escaped[1].exe"]),
        (r"C:\owned\double``.exe", [r"C:\owned\double`.exe"]),
        (r"C:\owned\folder[3]\command.exe", [r"C:\owned\folder3\command.exe"]),
        (r"C:\owned\missing[4]\command.exe", []),
    ],
)
def test_signature_resolves_measured_provider_paths_before_verification(
    signature: Any,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    selected: list[str],
) -> None:
    entries = {
        "C:\\owned": [
            "plain.exe",
            "unmatched[7].exe",
            "matched[1].exe",
            "matched1.exe",
            "multiple[12].exe",
            "multiple2.exe",
            "multiple1.exe",
            "tick`x.exe",
            "tickx.exe",
            "escaped`[1`].exe",
            "escaped[1].exe",
            "double``.exe",
            "double`.exe",
            "folder[3]",
            "folder3",
            "missing[4]",
        ],
        "C:\\owned\\folder3": ["command.exe"],
    }
    monkeypatch.setattr(signature.os.path, "isdir", lambda value: value in entries)
    monkeypatch.setattr(signature.os, "listdir", lambda value: entries[value])
    monkeypatch.setattr(signature.os.path, "isfile", lambda value: value not in entries)
    monkeypatch.setattr(signature, "_visible", lambda _value: True)
    monkeypatch.setattr(signature.filenames, "_current_lower", lambda: str.lower)
    monkeypatch.setattr(
        signature.filenames,
        "compare_paths",
        lambda left, right: (left.lower() > right.lower())
        - (left.lower() < right.lower()),
    )
    assert signature._signature_paths(path) == selected


@pytest.mark.parametrize(
    "states,expected",
    [
        ([], "You cannot call a method on a null-valued expression."),
        (["Valid", "UnknownError"], "signature status is 'Valid UnknownError'"),
        (["Valid", "Valid"], "signature status is 'Valid Valid'"),
    ],
)
def test_zero_or_multiple_provider_results_preserve_released_failure(
    signature: Any,
    monkeypatch: pytest.MonkeyPatch,
    states: list[str],
    expected: str,
) -> None:
    selected = [f"selected{index}.exe" for index in range(len(states))]
    monkeypatch.setattr(signature, "_signature_paths", Mock(return_value=selected))
    observed = Mock(side_effect=states)
    monkeypatch.setattr(signature, "status", observed)
    with pytest.raises(ValueError) as error:
        signature.verify("owned[12].exe")
    assert str(error.value).startswith("Authenticode check failed: ")
    assert expected in str(error.value)
    assert [call.args[0] for call in observed.call_args_list] == selected


def test_single_selected_valid_file_accepts_original_installer_path(
    signature: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        signature, "_signature_paths", Mock(return_value=["different1.exe"])
    )
    observed = Mock(return_value="Valid")
    monkeypatch.setattr(signature, "status", observed)
    assert signature.verify("different[1].exe") is None
    observed.assert_called_once_with("different1.exe")
