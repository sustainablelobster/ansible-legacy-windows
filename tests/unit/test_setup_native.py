"""Fault-test subset isolation, native projections, and owned collector cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Fault tests deliberately exercise the concrete private native call boundaries.
# pylint: disable=protected-access

import contextlib
import ctypes
import datetime
import importlib
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest


@pytest.fixture(name="helper")
def setup_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load dedicated helpers and unchanged dependencies from the source tree.

    :param monkeypatch: Scoped module-search path and import isolation.
    :returns: Imported setup helper.
    """
    monkeypatch.syspath_prepend(
        str(Path(__file__).resolve().parents[2] / "legacy_windows/plugins/module_utils")
    )
    for name in (
        "legacy_windows_setup",
        "legacy_windows_setup_native",
        "legacy_windows_setup_network",
        "legacy_windows_setup_winrm",
    ):
        monkeypatch.delitem(sys.modules, name, raising=False)
    return importlib.import_module("legacy_windows_setup")


@pytest.mark.parametrize(
    "requested, expected",
    [
        (["!all", "!min"], set()),
        (["!all", "!min", "dns"], {"dns"}),
        (["!all", "!min", "interfaces"], {"interfaces"}),
        (
            ["!all", "!min", "hardware", "!hardware"],
            {"bios", "memory", "processor", "uptime", "virtual"},
        ),
        (["!all", "!min", "INVALID"], set()),
    ],
)
def test_subset_selection(
    helper: ModuleType, requested: list[str], expected: set[str]
) -> None:
    warnings: list[str] = []
    assert helper.selected_subsets(requested, warnings) == expected
    assert warnings == (
        ["invalid value INVALID specified in gather_subset"]
        if "INVALID" in requested
        else []
    )


def test_minimum_and_ignored_unknown_exclusion(helper: ModuleType) -> None:
    warnings: list[str] = []
    minimum = {
        "date_time",
        "distribution",
        "dns",
        "env",
        "local",
        "platform",
        "powershell_version",
        "user",
    }
    assert helper.selected_subsets(["!all", "!unknown"], warnings) == minimum
    assert not warnings


def _parameters(subsets: list[str]) -> dict[str, object]:
    return {
        "gather_subset": subsets,
        "gather_timeout": 10,
        "fact_path": None,
        "_measure_subset": False,
    }


@pytest.mark.parametrize("subsets", [["!all", "!min"], ["!all", "!min", "dns"]])
@pytest.mark.parametrize("timeout", [10, -1])
def test_empty_collector_selection_does_not_start_native_child(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    subsets: list[str],
    timeout: int,
) -> None:
    monkeypatch.setattr(helper.os, "name", "nt")
    monkeypatch.setattr(
        helper.native,
        "windows_version",
        lambda: SimpleNamespace(major=10, minor=0),
        raising=False,
    )
    run = Mock()
    monkeypatch.setattr(helper, "_collect_process", run)
    assert helper.read_facts(
        dict(_parameters(subsets), gather_timeout=timeout), []
    ) == {
        "gather_subset": subsets,
        "module_setup": True,
    }
    run.assert_not_called()


def test_negative_collector_timeout_fails_before_starting_child(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.os, "name", "nt")
    monkeypatch.setattr(
        helper.native, "windows_version", lambda: SimpleNamespace(major=10, minor=0)
    )
    run = Mock()
    monkeypatch.setattr(helper, "_collect_process", run)
    with pytest.raises(ValueError, match="when collecting facts"):
        helper.read_facts(
            dict(_parameters(["!all", "!min", "bios"]), gather_timeout=-1), []
        )
    run.assert_not_called()


def test_failed_collector_does_not_discard_previous_or_later_facts(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.os, "name", "nt")
    monkeypatch.setattr(
        helper.native,
        "windows_version",
        lambda: SimpleNamespace(major=10, minor=0),
        raising=False,
    )
    run = Mock(
        side_effect=[
            {"facts": {"bios": "retained"}, "warnings": [], "elapsed": 0.1},
            OSError("denied"),
            {"facts": {"user": "available"}, "warnings": [], "elapsed": 0.2},
        ]
    )
    monkeypatch.setattr(helper, "_collect_process", run)
    parameters = dict(
        _parameters(["!all", "!min", "bios", "distribution", "user"]),
        _measure_subset=True,
    )
    warnings: list[str] = []
    result = helper.read_facts(parameters, warnings)
    assert result["bios"] == "retained" and result["user"] == "available"
    assert result["measure_info"] == {"bios": 0.1, "user": 0.2}
    assert warnings == ["Error when collecting distribution facts: denied"]


def test_timeout_kills_and_reaps_only_owned_child(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.native, "collector_needs_detached", lambda: False)
    child = Mock()
    child.__enter__ = Mock(return_value=child)
    child.__exit__ = Mock(return_value=False)
    child.communicate.side_effect = [subprocess.TimeoutExpired("owned", 0), (b"", b"")]
    start = Mock(return_value=child)
    monkeypatch.setattr(helper.subprocess, "Popen", start)
    monkeypatch.setattr(
        helper.native,
        "windows_version",
        lambda: SimpleNamespace(major=6, minor=1),
        raising=False,
    )
    monkeypatch.setattr(
        helper.native, "owned_job", lambda _handle: contextlib.nullcontext()
    )
    result = helper._collect_process(
        "bios", dict(_parameters(["bios"]), gather_timeout=0)
    )
    assert result == {
        "facts": {},
        "warnings": ["Failed to collect bios due to timeout"],
    }
    child.kill.assert_called_once_with()
    assert child.communicate.call_count == 2
    assert start.call_args.args[0][0] == sys.executable
    assert child.communicate.call_args_list[0].kwargs == {"timeout": 0}
    assert start.call_args.kwargs["creationflags"] == 0x01000000


def test_timeout_closes_descendant_job_before_reaping_inherited_pipes(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []

    @contextlib.contextmanager
    def _job(_handle: object) -> Any:
        events.append("assigned")
        try:
            yield
        finally:
            events.append("descendants terminated")

    def _communicate(request: object = None, **_kwargs: object) -> tuple[bytes, bytes]:
        if request is not None:
            events.append("timeout")
            raise subprocess.TimeoutExpired("owned", 2)
        assert events[-1] == "descendants terminated"
        events.append("reaped")
        return b"", b""

    child = Mock()
    child.__enter__ = Mock(return_value=child)
    child.__exit__ = Mock(return_value=False)
    child.communicate.side_effect = _communicate
    child.kill.side_effect = lambda: events.append("worker killed")
    monkeypatch.setattr(helper.subprocess, "Popen", Mock(return_value=child))
    monkeypatch.setattr(
        helper.native, "windows_version", lambda: SimpleNamespace(major=10, minor=0)
    )
    monkeypatch.setattr(helper.native, "owned_job", _job)
    assert helper._collect_process("local", _parameters(["local"])) == {
        "facts": {},
        "warnings": ["Failed to collect local due to timeout"],
    }
    assert events == [
        "assigned",
        "timeout",
        "worker killed",
        "descendants terminated",
        "reaped",
    ]


@pytest.mark.parametrize(
    "version, flags",
    [
        ((5, 1), 0x01000000),
        ((6, 0), 0x01000000),
        ((6, 1), 0x01000000),
        ((6, 2), 0),
        ((10, 0), 0),
    ],
)
def test_worker_job_creation_follows_native_nesting_boundary(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    version: tuple[int, int],
    flags: int,
) -> None:
    monkeypatch.setattr(helper.native, "collector_needs_detached", lambda: False)
    child = Mock(returncode=0)
    child.__enter__ = Mock(return_value=child)
    child.__exit__ = Mock(return_value=False)
    child.communicate.return_value = (b'{"facts":{},"warnings":[]}', b"")
    start = Mock(return_value=child)
    monkeypatch.setattr(helper.subprocess, "Popen", start)
    monkeypatch.setattr(
        helper.native,
        "windows_version",
        lambda: SimpleNamespace(major=version[0], minor=version[1]),
        raising=False,
    )
    monkeypatch.setattr(
        helper.native, "owned_job", lambda _handle: contextlib.nullcontext()
    )
    assert helper._collect_process("bios", _parameters(["bios"])) == {
        "facts": {},
        "warnings": [],
    }
    assert start.call_args.kwargs["creationflags"] == flags


def test_job_assignment_failure_kills_waiting_owned_child_before_input(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.native, "collector_needs_detached", lambda: False)
    child = Mock()
    child.__enter__ = Mock(return_value=child)
    child.__exit__ = Mock(return_value=False)
    child.poll.return_value = None
    start = Mock(return_value=child)
    monkeypatch.setattr(helper.subprocess, "Popen", start)
    monkeypatch.setattr(
        helper.native,
        "windows_version",
        lambda: SimpleNamespace(major=6, minor=1),
        raising=False,
    )
    monkeypatch.setattr(
        helper.native, "owned_job", Mock(side_effect=OSError("assignment denied"))
    )
    with pytest.raises(OSError, match="assignment denied"):
        helper._collect_process("bios", _parameters(["bios"]))
    child.kill.assert_called_once_with()
    child.communicate.assert_called_once_with()


def test_network_scalar_array_and_null_projection(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    network = helper.native.network
    adapter = {
        "kind": 6,
        "modern": True,
        "interface_index": 7,
        "addresses": [(2, "192.0.2.1", "24"), (23, "fe80::1%7", "64")],
        "connection_name": "Unicode 雪",
        "speed": 1000.0,
    }
    monkeypatch.setattr(network, "_adapters", lambda: [adapter])
    assert network.read_interfaces() == [
        {
            "interface_index": 7,
            "connection_name": "Unicode 雪",
            "speed": 1000.0,
            "ipv4": {"address": "192.0.2.1", "prefix": "24"},
            "ipv6": {"address": "fe80::1%7", "prefix": "64"},
        }
    ]
    adapter["addresses"] = [(2, "192.0.2.1", "24"), (2, "192.0.2.2", "24")]
    row = network.read_interfaces()[0]
    assert row["ipv6"] is None and isinstance(row["ipv4"], list)


def test_local_json_preserves_false_zero_array_and_unicode(
    helper: ModuleType, tmp_path: Path
) -> None:
    for name, text in {
        "false": "false",
        "zero": "0",
        "empty": "[]",
        "single": '[{"value":"one"}]',
        "array": '[1,"two",false,null]',
        "nested": '{"雪":"Unicode","array":[1]}',
        "null": "null",
    }.items():
        (tmp_path / (name + ".json")).write_text(text, encoding="utf-8")
    (tmp_path / "ignored.JSON").write_text("true", encoding="utf-8")
    facts: dict[str, object] = {}
    helper.native.collect("local", {"fact_path": str(tmp_path)}, facts, [])
    assert facts == {
        "ansible_false": False,
        "ansible_zero": 0,
        "ansible_empty": {"Count": 0, "value": []},
        "ansible_single": {"Count": 1, "value": [{"value": "one"}]},
        "ansible_array": {"Count": 4, "value": [1, "two", False, None]},
        "ansible_nested": {"雪": "Unicode", "array": [1]},
    }


@pytest.mark.parametrize("raw", [b"", b"\0" * 8, b"\0\2\7\0\x04\0\0\0\x01\x03\0\0"])
def test_malformed_smbios_does_not_return_invented_fields(
    helper: ModuleType, raw: bytes
) -> None:
    if len(raw) == 8:
        assert helper.native.parse_smbios(raw) == {
            "processors": [],
            "counts_found": False,
        }
    else:
        with pytest.raises(ValueError):
            helper.native.parse_smbios(raw)


@pytest.mark.parametrize(
    "kind, value, expected",
    [
        (11, b"\x01\0\0\0\0\0\0\0", 1),
        (3, b"\x01\0\0\0\0\0\0\0", b"\x01\0\0\0\0\0\0\0"),
        (11, 123, 123),
    ],
)
def test_python34_registry_qword_conversion_is_type_specific(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    kind: int,
    value: object,
    expected: object,
) -> None:
    key = Mock()
    key.__enter__ = Mock(return_value=key)
    key.__exit__ = Mock(return_value=False)
    registry = SimpleNamespace(
        OpenKey=Mock(return_value=key),
        QueryValueEx=Mock(return_value=(value, kind)),
        HKEY_LOCAL_MACHINE=1,
        KEY_READ=2,
        KEY_WOW64_64KEY=4,
    )
    monkeypatch.setattr(helper.native, "winreg", registry)
    assert helper.native._registry("synthetic", "InstallTime") == expected


@pytest.mark.parametrize(
    "fields, expected",
    [
        ((10, 0, 26200, 0, 0), "10.0.26200.0"),
        ((6, 1, 7601, 1, 0), "6.1.7601.65536"),
        ((5, 1, 2600, 3, 0), "5.1.2600.196608"),
    ],
)
def test_framework_os_version_includes_service_pack_revision(
    helper: ModuleType,
    fields: tuple[int, int, int, int, int],
    expected: str,
) -> None:
    major, minor, build, sp_major, sp_minor = fields
    version = SimpleNamespace(
        major=major,
        minor=minor,
        build=build,
        service_pack_major=sp_major,
        service_pack_minor=sp_minor,
    )
    assert helper.native._version_string(version) == expected


@pytest.mark.parametrize("value, expected", [(1.0, 1), (2.5, 2.5), (0.0, 0)])
def test_integral_cpu_ratios_preserve_measured_json_number_type(
    helper: ModuleType, value: float, expected: object
) -> None:
    actual = helper.native._json_number(value)
    assert actual == expected and type(actual) is type(expected)


def test_rtl_version_avoids_the_measured_python34_manifest_version(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _read(pointer: Any) -> int:
        version = ctypes.cast(
            pointer, ctypes.POINTER(helper.native._OsVersion)
        ).contents
        assert version.size == 284
        version.major, version.minor, version.build = 10, 0, 26200
        version.product_type = 1
        return 0

    library = SimpleNamespace(RtlGetVersion=Mock(side_effect=_read))
    monkeypatch.setattr(
        helper.native.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    version = helper.native.windows_version()
    assert helper.native._version_string(version) == "10.0.26200.0"
    assert version.product_type == 1


@pytest.mark.parametrize("status", [-1073741819, -1073741823])
def test_rtl_failure_reports_the_actual_distinct_ntstatus(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    library = SimpleNamespace(RtlGetVersion=Mock(return_value=status))
    monkeypatch.setattr(
        helper.native.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    with pytest.raises(OSError, match=f"0x{status & 0xFFFFFFFF:08X}"):
        helper.native.windows_version()


@pytest.mark.parametrize(
    "step, code",
    [
        ("CreateJobObjectW", 8),
        ("SetInformationJobObject", 87),
        ("AssignProcessToJobObject", 5),
    ],
)
def test_job_errors_preserve_actual_native_codes_and_close_owned_handle(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, step: str, code: int
) -> None:
    library = SimpleNamespace(
        CreateJobObjectW=Mock(return_value=77),
        SetInformationJobObject=Mock(return_value=1),
        AssignProcessToJobObject=Mock(return_value=1),
        CloseHandle=Mock(return_value=1),
    )
    getattr(library, step).return_value = 0
    monkeypatch.setattr(
        helper.native.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    monkeypatch.setattr(
        helper.native.ctypes, "get_last_error", lambda: code, raising=False
    )

    def _error(value: int) -> OSError:
        error = OSError("native code " + str(value))
        error.winerror = value  # type: ignore[attr-defined]
        return error

    monkeypatch.setattr(helper.native.ctypes, "WinError", _error, raising=False)
    with pytest.raises(OSError) as caught:
        with helper.native.owned_job(123):
            pytest.fail("An unassigned worker cannot start")
    assert caught.value.winerror == code  # type: ignore[attr-defined]
    if step == "CreateJobObjectW":
        library.CloseHandle.assert_not_called()
    else:
        library.CloseHandle.assert_called_once_with(77)


@pytest.mark.parametrize(
    "listeners", [[], [{"Transport": "HTTP", "CertificateThumbprint": "ignored"}]]
)
def test_winrm_without_https_returns_no_invented_fields_or_warning(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, listeners: list[dict[str, str]]
) -> None:
    winrm = helper.native.winrm
    monkeypatch.setattr(winrm, "_listeners", lambda: listeners)
    read = Mock()
    monkeypatch.setattr(winrm, "_certificate_expiry", read)
    facts: dict[str, object] = {}
    warnings: list[str] = []
    winrm.read_facts(facts, warnings)
    assert not facts and not warnings
    read.assert_not_called()


def test_winrm_selects_earliest_certificate_and_renders_local_expiry(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    winrm = helper.native.winrm
    monkeypatch.setattr(
        winrm,
        "_listeners",
        lambda: [
            {"Transport": "HTTPS", "CertificateThumbprint": "later"},
            {"Transport": "https", "CertificateThumbprint": "earlier"},
        ],
    )
    monkeypatch.setattr(
        winrm,
        "_certificate_expiry",
        lambda name: (20, "AA") if name == "later" else (10, "BB"),
    )
    local = datetime.datetime(2027, 3, 4, 5, 6, 7)
    ticks = ((local.toordinal() - 1) * 86400 + 5 * 3600 + 6 * 60 + 7) * 10000000
    convert = Mock(return_value=ticks)
    monkeypatch.setattr(winrm.uformat.native_time, "file_time_to_local_ticks", convert)
    render = Mock(return_value="2027-03-04 05:06:07")
    monkeypatch.setattr(winrm.uformat, "format_date", render)
    facts: dict[str, object] = {}
    winrm.read_facts(facts, [])
    assert facts == {
        "ansible_win_rm_certificate_expires": "2027-03-04 05:06:07",
        "ansible_win_rm_certificate_thumbprint": "BB",
    }
    convert.assert_called_once_with(10)
    render.assert_called_once_with(local, "%Y-%m-%d %H:%M:%S")


def test_winrm_failure_is_named_and_does_not_return_partial_certificate(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    winrm = helper.native.winrm
    monkeypatch.setattr(
        winrm, "_listeners", Mock(side_effect=OSError("native HRESULT 0x80338012"))
    )
    facts: dict[str, object] = {}
    warnings: list[str] = []
    winrm.read_facts(facts, warnings)
    assert not facts and warnings == [
        "Error during certificate expiration retrieval: native HRESULT 0x80338012"
    ]


@pytest.mark.parametrize("status", [0x80338012, 0x80070005])
def test_winrm_enumeration_hresult_matches_source_silent_provider_errors(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    winrm = helper.native.winrm

    def _create(*arguments: Any) -> int:
        ctypes.cast(arguments[-1], ctypes.POINTER(ctypes.c_void_p))[0] = 7
        return 0

    def _session(*arguments: Any) -> int:
        ctypes.cast(arguments[-1], ctypes.POINTER(ctypes.c_void_p))[0] = 8
        return 0

    enumeration = Mock(return_value=ctypes.c_int32(status).value)
    ole = SimpleNamespace(
        CoInitializeEx=Mock(return_value=0),
        CoUninitialize=Mock(),
        CoCreateInstance=Mock(side_effect=_create),
    )
    released = Mock()
    monkeypatch.setattr(winrm.wmi, "_libraries", lambda: (ole, Mock()))
    monkeypatch.setattr(winrm.wmi, "_release", released)
    monkeypatch.setattr(winrm.wmi, "_bstr", lambda *_arguments: 1)
    monkeypatch.setattr(winrm, "_interface", lambda pointer, *_arguments: pointer)
    monkeypatch.setattr(
        winrm.wmi,
        "_method",
        lambda _pointer, slot, *_arguments: _session if slot == 7 else enumeration,
    )
    assert winrm._listeners() == []
    resource = enumeration.call_args.args[1]
    assert resource.kind == 8 and resource.data.bstr == 1
    assert [call.args[0].value for call in released.call_args_list] == [8, 7]
    ole.CoUninitialize.assert_called_once_with()


def test_pre_vista_uptime_fallback_preserves_wmi_offset(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = helper.native

    class Clock(datetime.datetime):
        """A deterministic wall clock with the normal aware/naive distinction."""

        @classmethod
        def now(cls, tz: datetime.tzinfo | None = None) -> "Clock":
            """Return the fixed observed time.

            :param tz: Optional UTC marker used by the fallback calculation.
            :returns: The deterministic datetime with the requested timezone.
            """
            return cls(2026, 10, 2, 12, 0, tzinfo=tz)

    monkeypatch.setattr(native.datetime, "datetime", Clock)
    monkeypatch.setattr(
        native.ctypes, "WinDLL", lambda *_args, **_kw: SimpleNamespace(), raising=False
    )
    monkeypatch.setattr(
        native, "_one", lambda *_args: {"LastBootUpTime": "20261002163000.000000+330"}
    )
    facts: dict[str, object] = {}
    native._uptime(facts)
    assert facts == {
        "ansible_lastboot": "2026-10-02 11:00:00Z",
        "ansible_uptime_seconds": 3600,
    }
