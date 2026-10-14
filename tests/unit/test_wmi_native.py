"""Exercise shared native WMI through scalar and string-array operations."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes do not establish execution compatibility on Windows.
# pylint: disable=protected-access
# One COM/VARIANT substitute tracks ownership across scalar and array operations;
# splitting it would obscure the shared cleanup behavior these tests exercise.
# pylint: disable=too-many-lines

import ctypes
from datetime import datetime
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest.mock import Mock
from uuid import UUID

import pytest

from tests.unit.payload_support import ROOT, load_module

POINTER = ctypes.c_void_p
LONG = ctypes.c_int32
ULONG = ctypes.c_uint32
POINTER_OUT = ctypes.POINTER(POINTER)
FAILURE = -2147217405  # WBEM_E_ACCESS_DENIED, 0x80041003.
BOOT = "20260928081141.679063+000"
EXPECTED = datetime(2026, 9, 28, 8, 11, 41, 679063)


@pytest.fixture(name="helper")
def wmi_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the standalone target helper without Windows access.

    :param monkeypatch: Scoped target-helper import path.
    :returns: Fresh helper imported with the development interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_wmi.py",
        "tested_wmi_native",
    )


def _read_boot(helper: ModuleType) -> Any:
    boot = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_boot.py",
        "tested_boot_with_wmi",
    )
    setattr(boot, "WmiConnection", helper.WmiConnection)
    setattr(boot, "parse_datetime", helper.parse_datetime)
    return boot.last_boot_time()


def _set_pointer(destination: Any, value: int) -> None:
    ctypes.cast(destination, POINTER_OUT)[0] = value


# Keep native interfaces, allocated strings, and enumeration state visible
# together so each test can assert ownership across failed calls.
class _Wmi:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    def __init__(self, helper: ModuleType) -> None:
        self.helper = helper
        self.ole32 = Mock()
        self.automation = Mock()
        self.events: list[str] = []
        self.strings: dict[int, Any] = {}
        self.arrays: dict[int, list[str]] = {}
        self.options: dict[str, Any] = {"boot": BOOT, "returned": 1, "kind": 8}
        self.rows: list[dict[str, Any]] = []
        self.current: dict[str, Any] = {}
        self._bind_functions()

    def _bind_functions(self) -> None:
        self.ole32.CoInitializeEx.side_effect = self._initialize
        self.ole32.CoInitializeSecurity.side_effect = self._security
        self.ole32.CoUninitialize.side_effect = lambda: self.events.append(
            "uninitialize"
        )
        self.ole32.CoCreateInstance.side_effect = self._create
        self.ole32.CoSetProxyBlanket.side_effect = self._proxy
        self.automation.SysAllocString.side_effect = self._allocate
        self.automation.SysAllocStringLen.side_effect = self._allocate_string
        self.automation.SysFreeString.side_effect = self._free
        # BSTR length includes embedded NULs; ctypes buffer.value does not.
        self.automation.SysStringLen.side_effect = (
            lambda pointer: len(self.strings[pointer]) - 1
        )
        self.automation.VariantClear.side_effect = self._clear
        self.automation.SafeArrayCreateVector.side_effect = self._array_create
        self.automation.SafeArrayGetDim.side_effect = lambda _array: 1
        self.automation.SafeArrayGetLBound.side_effect = self._array_lower
        self.automation.SafeArrayGetUBound.side_effect = self._array_upper
        self.automation.SafeArrayGetElement.side_effect = self._array_get
        self.automation.SafeArrayPutElement.side_effect = self._array_put

    def _status(self, name: str) -> int:
        self.events.append(name)
        return int(self.options.get(name, 0))

    def _initialize(self, reserved: Any, flags: int) -> int:
        assert reserved is None and flags == 0
        return self._status("initialize")

    def _security(self, *arguments: Any) -> int:
        assert arguments == (None, -1, None, None, 0, 3, None, 0, None)
        return self._status("security")

    # Match CoCreateInstance's native arguments so the boundary stays explicit.
    def _create(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, clsid: Any, outer: Any, context: int, iid: Any, out: Any
    ) -> int:
        assert (
            ctypes.string_at(clsid, 16)
            == UUID("4590f811-1d3a-11d0-891f-00aa004b2e24").bytes_le
        )
        assert (
            ctypes.string_at(iid, 16)
            == UUID("dc12a687-737f-11cf-884d-00aa004b2e24").bytes_le
        )
        assert outer is None and context == 1
        status = self._status("create")
        if not status:
            _set_pointer(out, 101)
        return status

    def _proxy(self, interface: Any, *arguments: Any) -> int:
        assert interface.value == 102
        assert arguments == (
            10,
            0,
            None,
            3,
            3,
            None,
            self.options.get("proxy_capabilities", 0),
        )
        return self._status("proxy")

    def _allocate(self, value: str) -> int:
        self.events.append("allocate:" + value)
        if self.options.get("allocation_failure") == value:
            return 0
        buffer = ctypes.create_unicode_buffer(value)
        pointer = ctypes.addressof(buffer)
        self.strings[pointer] = buffer
        return pointer

    def _free(self, pointer: Any) -> None:
        if isinstance(pointer, POINTER):
            pointer = pointer.value
        self.events.append("free:" + self.strings.pop(pointer).value)

    def _allocate_string(self, value: str, units: int) -> int:
        assert units == len(value.encode("utf-16-le", "surrogatepass")) // 2
        return self._allocate(value)

    def _clear(self, pointer: Any) -> int:
        value = ctypes.cast(pointer, ctypes.POINTER(self.helper._Variant)).contents
        self.events.append("clear:" + str(value.kind))
        if value.kind == 8 and value.data.bstr:
            self._free(value.data.bstr)
        elif value.kind == 0x2008 and value.data.array:
            self.arrays.pop(value.data.array)
        value.kind = 0
        return int(self.options.get("clear", 0))

    def _array_create(self, kind: int, lower: int, count: int) -> int:
        assert kind == 8 and lower == 0
        if self.options.get("array_create_failure"):
            return 0
        pointer = 200 + len(self.arrays)
        self.arrays[pointer] = [""] * count
        return pointer

    def _array_lower(self, array: int, dimension: int, output: Any) -> int:
        assert array in self.arrays and dimension == 1
        ctypes.cast(output, ctypes.POINTER(LONG))[0] = self.options.get("lower", 0)
        return self._status("array_lower")

    def _array_upper(self, array: int, dimension: int, output: Any) -> int:
        assert dimension == 1
        ctypes.cast(output, ctypes.POINTER(LONG))[0] = (
            self.options.get("lower", 0) + len(self.arrays[array]) - 1
        )
        return self._status("array_upper")

    def _array_get(self, array: int, position: Any, output: Any) -> int:
        index = ctypes.cast(position, ctypes.POINTER(LONG))[0]
        status = self._status("array_get")
        if not status:
            _set_pointer(
                output,
                self._allocate(
                    self.arrays[array][index - self.options.get("lower", 0)]
                ),
            )
        return status

    def _array_put(self, array: int, position: Any, text: int) -> int:
        index = ctypes.cast(position, ctypes.POINTER(LONG))[0]
        status = self._status("array_put")
        if not status:
            self.arrays[array][index] = "".join(self.strings[text][:-1])
        return status

    def _method(
        self, interface: Any, slot: int, result: Any, arguments: list[Any]
    ) -> Callable[..., int]:
        if slot == 2:
            assert result is ULONG and arguments == []
            return self._release
        assert result is LONG
        signatures: dict[tuple[int, int], tuple[list[Any], Callable[..., int]]] = {
            (101, 3): (
                [
                    POINTER,
                    POINTER,
                    POINTER,
                    POINTER,
                    LONG,
                    POINTER,
                    POINTER,
                    POINTER_OUT,
                ],
                self._connect,
            ),
            (102, 20): (
                [POINTER, POINTER, LONG, POINTER, POINTER_OUT],
                self._query,
            ),
            (103, 4): (
                [LONG, ULONG, POINTER_OUT, ctypes.POINTER(ULONG)],
                self._next,
            ),
            (104, 4): (
                [
                    ctypes.c_wchar_p,
                    LONG,
                    ctypes.POINTER(self.helper._Variant),
                    ctypes.POINTER(LONG),
                    ctypes.POINTER(LONG),
                ],
                self._get,
            ),
        }
        signatures[102, 24] = (
            [POINTER, POINTER, LONG, POINTER, POINTER, POINTER_OUT, POINTER],
            self._execute,
        )
        signatures[105, 4] = signatures[104, 4]
        signatures[106, 4] = signatures[104, 4]
        signatures[102, 6] = (
            [POINTER, LONG, POINTER, POINTER_OUT, POINTER],
            self._get_object,
        )
        signatures[107, 19] = (
            [ctypes.c_wchar_p, LONG, POINTER_OUT, POINTER_OUT],
            self._get_method,
        )
        signatures[108, 15] = ([LONG, POINTER_OUT], self._spawn)
        signatures[109, 5] = (
            [ctypes.c_wchar_p, LONG, ctypes.POINTER(self.helper._Variant), LONG],
            self._put,
        )
        signatures[106, 5] = (
            [ctypes.c_wchar_p, LONG, ctypes.POINTER(self.helper._Variant), LONG],
            self._put_property,
        )
        signatures[102, 14] = (
            [POINTER, LONG, POINTER, POINTER_OUT],
            self._update_instance,
        )
        expected, callback = signatures[interface.value, slot]
        assert arguments == expected
        return callback

    def _release(self, interface: Any) -> int:
        return self._status("release:" + str(interface.value))

    def _connect(self, interface: Any, namespace: int, *arguments: Any) -> int:
        assert interface.value == 101
        assert self.strings[namespace].value == self.options.get(
            "namespace", "ROOT\\CIMV2"
        )
        assert arguments[:-1] == (None, None, None, 0x80, None, None)
        status = self._status("connect")
        if not status:
            _set_pointer(arguments[-1], 102)
        return status

    def _query(self, interface: Any, language: int, query: int, *arguments: Any) -> int:
        assert interface.value == 102
        assert self.strings[language].value == "WQL"
        self.events.append("query:" + self.strings[query].value)
        self.rows = list(
            self.options.get("rows", [{"LastBootUpTime": self.options["boot"]}])
        )
        assert arguments[:-1] == (self.options.get("query_flags", 0x30), None)
        status = self._status("query")
        if not status:
            _set_pointer(arguments[-1], 103)
        return status

    # Match IEnumWbemClassObject.Next's native argument list.
    def _next(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, interface: Any, timeout: int, count: int, out: Any, returned: Any
    ) -> int:
        assert interface.value == 103 and timeout == -1 and count == 1
        status = self._status("next")
        if status >= 0:
            count_returned = self.options["returned"] if self.rows else 0
            ctypes.cast(returned, ctypes.POINTER(ULONG))[0] = count_returned
            if count_returned:
                self.current = self.rows.pop(0)
                _set_pointer(out, 104)
        return status

    def _get(
        self, interface: Any, name: str, flags: int, out: Any, *metadata: Any
    ) -> int:
        assert interface.value in (104, 105, 106) and flags == 0
        cim_type, flavor = metadata
        assert flavor is None
        value = ctypes.cast(out, ctypes.POINTER(self.helper._Variant)).contents
        assert value.kind == 0 and value.data.bstr is None
        status = self._status("get")
        if not status:
            value.kind = self.options["kind"]
            item = (
                self.options.get("class_name", "CIM_DataFile")
                if interface.value == 106
                else self.current[name]
            )
            if isinstance(item, tuple):
                value.kind, integer, cim = item
                value.data.integer = integer
                ctypes.cast(cim_type, ctypes.POINTER(LONG))[0] = cim
            elif isinstance(item, list):
                value.kind = 0x2008
                value.data.array = self._array_create(8, 0, len(item))
                self.arrays[value.data.array] = list(item)
            elif value.kind == 8 and item is not None:
                value.data.bstr = self._allocate(item)
        return status

    def _execute(self, interface: Any, path: int, name: int, *arguments: Any) -> int:
        assert interface.value == 102
        assert self.strings[path].value == self.options.get(
            "method_path", 'Win32_Process.Handle="42"'
        )
        assert self.strings[name].value == self.options.get("method_name", "GetOwner")
        assert arguments[:2] == (0, None) and arguments[-1] is None
        if self.options.get("inputs") is not None:
            assert arguments[2].value == 109
        else:
            assert arguments[2] is None
        status = self._status("execute")
        if not status and not self.options.get("missing_output"):
            self.current = self.options.get("owner", {"Domain": "LAB", "User": "owner"})
            _set_pointer(arguments[3], 105)
        return status

    def _get_object(self, interface: Any, path: int, *arguments: Any) -> int:
        assert interface.value == 102
        assert arguments[:2] == (0, None) and arguments[-1] is None
        name = self.strings[path].value
        stage, pointer = (
            ("get_instance", 106)
            if name == self.options["method_path"]
            else ("get_class", 107)
        )
        assert name in (
            self.options["method_path"],
            self.options.get("class_name", "CIM_DataFile"),
        )
        status = self._status(stage)
        if not status and self.options.get("missing_pointer") != stage:
            _set_pointer(arguments[2], pointer)
        return status

    # GetMethod's separate input/output pointers are required by the COM ABI.
    def _get_method(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, interface: Any, name: str, flags: int, inputs: Any, outputs: Any
    ) -> int:
        assert interface.value == 107
        assert name == self.options["method_name"] and flags == 0 and outputs is None
        status = self._status("get_method")
        if not status and self.options.get("missing_pointer") != "get_method":
            _set_pointer(inputs, 108)
        return status

    def _spawn(self, interface: Any, flags: int, output: Any) -> int:
        assert interface.value == 108 and flags == 0
        status = self._status("spawn")
        if not status and self.options.get("missing_pointer") != "spawn":
            _set_pointer(output, 109)
        return status

    # Put receives a property name, flags, VARIANT pointer, and existing CIM type.
    def _put(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, interface: Any, name: str, flags: int, value: Any, cim_type: int
    ) -> int:
        assert interface.value == 109 and flags == cim_type == 0
        variant = ctypes.cast(value, ctypes.POINTER(self.helper._Variant)).contents
        expected = self.options["inputs"][name]
        if isinstance(expected, bool):
            assert variant.kind == 11
            assert variant.data.signed16 == (-1 if expected else 0)
        elif expected is None:
            assert variant.kind == 1 and not variant.data.bstr
        elif isinstance(expected, list):
            assert variant.kind == 0x2008
            assert self.arrays[variant.data.array] == expected
        else:
            assert variant.kind == 8
            assert "".join(self.strings[variant.data.bstr][:-1]) == expected
        return self._status("put")

    # Match IWbemClassObject.Put's complete ABI, including existing CIM type.
    def _put_property(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, interface: Any, name: str, flags: int, value: Any, cim_type: int
    ) -> int:
        assert interface.value == 106 and flags == cim_type == 0
        variant = ctypes.cast(value, ctypes.POINTER(self.helper._Variant)).contents
        if "integer_value" in self.options:
            assert name == "Enabled" and variant.kind == 3
            assert variant.data.signed32 == self.options["integer_value"]
        elif self.options["string_value"] is None:
            assert name == "Description"
            assert variant.kind == 1 and not variant.data.bstr
        else:
            assert name == "Description"
            assert variant.kind == 8
            assert (
                "".join(self.strings[variant.data.bstr][:-1])
                == self.options["string_value"]
            )
        return self._status("put_property")

    def _update_instance(self, interface: Any, *arguments: Any) -> int:
        assert interface.value == 102 and arguments[0].value == 106
        assert arguments[1:] == (1, None, None)
        return self._status("update_instance")


@pytest.fixture(name="wmi")
def native_wmi(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> _Wmi:
    """Replace only the Windows API boundaries with resource-tracking substitutes.

    :param helper: Loaded target helper.
    :param monkeypatch: Scoped native API replacements.
    :returns: Substitute API state, failures, and resource history.
    """
    native = _Wmi(helper)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        Mock(
            side_effect={
                "ole32": native.ole32,
                "oleaut32": native.automation,
            }.__getitem__
        ),
        raising=False,
    )
    monkeypatch.setattr(helper, "_method", native._method)
    return native


@pytest.mark.parametrize("dynamic_cloaking", [False, True])
def test_thread_identity_is_opt_in_without_global_security_changes(
    helper: ModuleType, wmi: _Wmi, dynamic_cloaking: bool
) -> None:
    wmi.options["proxy_capabilities"] = 0x40 if dynamic_cloaking else 0
    with helper.WmiConnection(dynamic_cloaking=dynamic_cloaking) as connection:
        assert (
            connection.query(
                "SELECT LastBootUpTime FROM Win32_OperatingSystem", ["LastBootUpTime"]
            )[0]["LastBootUpTime"]
            == BOOT
        )
    wmi.ole32.CoInitializeSecurity.assert_called_once_with(
        None, -1, None, None, 0, 3, None, 0, None
    )
    arguments = wmi.ole32.CoSetProxyBlanket.call_args.args
    assert arguments[-2] is None
    assert arguments[-1] == (0x40 if dynamic_cloaking else 0)
    assert not wmi.strings and wmi.events[-1] == "uninitialize"


def test_failed_thread_identity_proxy_releases_resources_and_allows_default_retry(
    helper: ModuleType, wmi: _Wmi
) -> None:
    wmi.options.update(proxy_capabilities=0x40, proxy=FAILURE)
    with pytest.raises(OSError, match="CoSetProxyBlanket"):
        with helper.WmiConnection(dynamic_cloaking=True):
            pytest.fail("A rejected proxy must not become usable.")
    assert not wmi.strings
    assert [event for event in wmi.events if event.startswith("release:")] == [
        "release:102",
        "release:101",
    ]
    assert wmi.events[-1] == "uninitialize"
    wmi.options.pop("proxy")
    wmi.options.pop("proxy_capabilities")
    assert _read_boot(helper) == EXPECTED


@pytest.mark.parametrize("invalid", [None, 0, 1, "true", []])
def test_thread_identity_requires_a_boolean(helper: ModuleType, invalid: Any) -> None:
    with pytest.raises(ValueError, match="dynamic_cloaking must be a boolean"):
        helper.WmiConnection(dynamic_cloaking=invalid)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (BOOT, EXPECTED),
        ("20260928111141.679063+180", EXPECTED),
        ("20260928041141.679063-240", EXPECTED),
        ("20240101001500.123456+060", datetime(2023, 12, 31, 23, 15, 0, 123456)),
        ("20231231234500.000001-060", datetime(2024, 1, 1, 0, 45, 0, 1)),
        ("20000229000000.999999-000", datetime(2000, 2, 29, microsecond=999999)),
        ("19691231235959.000000+000", datetime(1969, 12, 31, 23, 59, 59)),
    ],
)
def test_utc_boot_precision_and_offset(
    helper: ModuleType, wmi: _Wmi, value: str, expected: datetime
) -> None:
    wmi.options["boot"] = value
    assert _read_boot(helper) == expected
    assert not wmi.strings
    assert [event for event in wmi.events if event.startswith("release:")] == [
        "release:104",
        "release:103",
        "release:102",
        "release:101",
    ]
    assert wmi.events[-1] == "uninitialize"
    assert wmi.events.index("clear:8") < wmi.events.index("release:104")


@pytest.mark.parametrize(
    ("stage", "operation", "released"),
    [
        ("initialize", "CoInitializeEx", []),
        ("security", "CoInitializeSecurity", []),
        ("create", "CoCreateInstance", []),
        ("connect", "ConnectServer", [101]),
        ("proxy", "CoSetProxyBlanket", [102, 101]),
        ("query", "ExecQuery", [102, 101]),
        ("next", "Next", [103, 102, 101]),
        ("get", "Get", [104, 103, 102, 101]),
        ("clear", "VariantClear", [104, 103, 102, 101]),
    ],
)
def test_failures_release_acquisitions_and_allow_recovery(
    helper: ModuleType, wmi: _Wmi, stage: str, operation: str, released: list[int]
) -> None:
    wmi.options[stage] = FAILURE
    with pytest.raises(OSError, match=operation + r".*HRESULT 0x80041003"):
        _read_boot(helper)
    assert not wmi.strings
    assert [event for event in wmi.events if event.startswith("release:")] == [
        "release:" + str(pointer) for pointer in released
    ]
    assert wmi.events.count("uninitialize") == int(stage != "initialize")
    if stage == "get":
        assert "clear:0" in wmi.events
    wmi.options.pop(stage)
    wmi.events.clear()
    assert _read_boot(helper) == EXPECTED
    assert not wmi.strings
    assert wmi.events.count("uninitialize") == 1


@pytest.mark.parametrize("initialization", [0, 1, -2147417850])
@pytest.mark.parametrize("security", [0, -2147417831])
def test_existing_com_state_is_balanced(
    helper: ModuleType, wmi: _Wmi, initialization: int, security: int
) -> None:
    wmi.options.update(initialize=initialization, security=security)
    for _ in range(3):
        assert _read_boot(helper) == EXPECTED
    assert not wmi.strings
    assert wmi.events.count("uninitialize") == (0 if initialization < 0 else 3)
    assert wmi.events.count("release:101") == 3
    assert wmi.events.count("clear:8") == 3


@pytest.mark.parametrize("status", [0, 1])
def test_empty_operating_system_result_is_actionable(
    helper: ModuleType, wmi: _Wmi, status: int
) -> None:
    wmi.options.update(returned=0, next=status)
    with pytest.raises(OSError, match="no Win32_OperatingSystem instance"):
        _read_boot(helper)
    assert not wmi.strings
    assert "release:103" in wmi.events and "get" not in wmi.events
    assert wmi.events[-1] == "uninitialize"


def test_final_enumeration_status_can_include_a_result(
    helper: ModuleType, wmi: _Wmi
) -> None:
    wmi.options["next"] = 1
    assert _read_boot(helper) == EXPECTED


@pytest.mark.parametrize("kind", [0, 1, 3, 0x4008])
def test_missing_or_wrong_variant_type_is_cleared(
    helper: ModuleType, wmi: _Wmi, kind: int
) -> None:
    wmi.options["kind"] = kind
    with pytest.raises(ValueError, match="not a datetime string|unsupported VARIANT"):
        _read_boot(helper)
    assert "clear:" + str(kind) in wmi.events
    assert not wmi.strings
    assert wmi.events[-1] == "uninitialize"


def test_null_bstr_is_cleared(helper: ModuleType, wmi: _Wmi) -> None:
    wmi.options["boot"] = None
    with pytest.raises(ValueError, match="not a datetime string"):
        _read_boot(helper)
    assert "clear:8" in wmi.events and not wmi.strings


@pytest.mark.parametrize(
    "value",
    [
        "",
        BOOT[:-1],
        BOOT + "x",
        BOOT.replace(".", ","),
        BOOT.replace("+", ":"),
        BOOT.replace("+000", "+***"),
        "****0928081141.679063+000",
        "２０２６0928081141.679063+000",
        "20260230081141.679063+000",
        "20260928251141.679063+000",
        "20260928081160.679063+000",
        "00000928081141.679063+000",
    ],
)
def test_invalid_dmtf_is_not_silently_replaced(
    helper: ModuleType, wmi: _Wmi, value: str
) -> None:
    wmi.options["boot"] = value
    with pytest.raises(ValueError):
        _read_boot(helper)
    assert not wmi.strings and "clear:8" in wmi.events
    assert wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize(
    "value", ["00010101000000.000000+001", "99991231235959.999999-001"]
)
def test_utc_range_overflow_releases_resources(
    helper: ModuleType, wmi: _Wmi, value: str
) -> None:
    wmi.options["boot"] = value
    with pytest.raises(OverflowError):
        _read_boot(helper)
    assert not wmi.strings and wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize(
    "value", ["ROOT\\CIMV2", "WQL", "SELECT LastBootUpTime FROM Win32_OperatingSystem"]
)
def test_query_allocation_failure_releases_prior_resources(
    helper: ModuleType, wmi: _Wmi, value: str
) -> None:
    wmi.options["allocation_failure"] = value
    with pytest.raises(MemoryError, match="WMI query string"):
        _read_boot(helper)
    assert not wmi.strings
    assert "release:101" in wmi.events and wmi.events[-1] == "uninitialize"


def test_native_layout_and_function_signatures(helper: ModuleType, wmi: _Wmi) -> None:
    assert _read_boot(helper) == EXPECTED
    assert ctypes.sizeof(helper._Guid) == 16
    assert helper._Variant.data.offset == 8
    assert ctypes.sizeof(helper._Variant) == (24 if ctypes.sizeof(POINTER) == 8 else 16)
    assert wmi.ole32.CoInitializeEx.argtypes == [POINTER, ULONG]
    assert wmi.ole32.CoInitializeEx.restype is LONG
    assert wmi.ole32.CoUninitialize.argtypes == []
    assert wmi.ole32.CoUninitialize.restype is None
    assert wmi.ole32.CoInitializeSecurity.argtypes == [
        POINTER,
        LONG,
        POINTER,
        POINTER,
        ULONG,
        ULONG,
        POINTER,
        ULONG,
        POINTER,
    ]
    assert wmi.ole32.CoCreateInstance.argtypes == [
        ctypes.POINTER(helper._Guid),
        POINTER,
        ULONG,
        ctypes.POINTER(helper._Guid),
        POINTER_OUT,
    ]
    assert wmi.ole32.CoSetProxyBlanket.argtypes == [
        POINTER,
        ULONG,
        ULONG,
        ctypes.c_wchar_p,
        ULONG,
        ULONG,
        POINTER,
        ULONG,
    ]
    assert wmi.automation.SysAllocString.argtypes == [ctypes.c_wchar_p]
    assert wmi.automation.SysAllocString.restype is POINTER
    assert wmi.automation.SysAllocStringLen.argtypes == [ctypes.c_wchar_p, ULONG]
    assert wmi.automation.SysAllocStringLen.restype is POINTER
    assert wmi.automation.SysFreeString.argtypes == [POINTER]
    assert wmi.automation.SysFreeString.restype is None
    assert wmi.automation.SysStringLen.argtypes == [POINTER]
    assert wmi.automation.SysStringLen.restype is ULONG
    assert wmi.automation.VariantClear.argtypes == [ctypes.POINTER(helper._Variant)]
    assert wmi.automation.VariantClear.restype is LONG


def test_vtable_dispatch_preserves_native_argument_widths(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    received: list[tuple[int, int, int]] = []

    def _advance(this: int, timeout: int, count: int, out: Any, returned: Any) -> int:
        received.append((this, timeout, count))
        out[0] = 1234
        returned[0] = 1
        return FAILURE

    prototype = ctypes.CFUNCTYPE(
        LONG, POINTER, LONG, ULONG, POINTER_OUT, ctypes.POINTER(ULONG)
    )
    callback = prototype(_advance)
    table = (POINTER * 5)()
    table[4] = ctypes.cast(callback, POINTER)
    interface = ctypes.pointer(ctypes.cast(table, ctypes.POINTER(POINTER)))
    factory = Mock(side_effect=ctypes.CFUNCTYPE)
    monkeypatch.setattr(helper.ctypes, "WINFUNCTYPE", factory, raising=False)
    method = helper._method(
        interface, 4, LONG, [LONG, ULONG, POINTER_OUT, ctypes.POINTER(ULONG)]
    )
    result, returned = POINTER(), ULONG()
    assert (
        method(interface, -1, 1, ctypes.byref(result), ctypes.byref(returned))
        == FAILURE
    )
    assert result.value == 1234 and returned.value == 1
    assert received == [(ctypes.addressof(interface.contents), -1, 1)]
    factory.assert_called_once_with(
        LONG, POINTER, LONG, ULONG, POINTER_OUT, ctypes.POINTER(ULONG)
    )


def test_non_windows_is_rejected(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(OSError, match="requires Windows"):
        _read_boot(helper)


def test_provider_order_and_scalar_types(helper: ModuleType, wmi: _Wmi) -> None:
    wmi.options["namespace"] = r"ROOT\StandardCimv2"
    wmi.options["rows"] = [
        {"value": "é\x00tail"},
        {"value": (3, -1, 19)},
        {"value": (3, -2, 3)},
        {"value": (2, -3, 2)},
        {"value": (17, 255, 17)},
        {"value": (18, 65535, 18)},
        {"value": (19, 4294967295, 19)},
        {"value": (11, -1, 11)},
        {"value": (11, 0, 11)},
        {"value": None},
    ]
    with helper.WmiConnection(namespace=r"ROOT\StandardCimv2") as connection:
        assert connection.query("SELECT value FROM Example", ["value"]) == [
            {"value": item}
            for item in [
                "é\x00tail",
                4294967295,
                -2,
                -3,
                255,
                65535,
                4294967295,
                True,
                False,
                None,
            ]
        ]
    assert not wmi.strings
    assert wmi.events.count("release:104") == 10


def _compression_call(connection: Any, wmi: _Wmi, recursive: bool = True) -> Any:
    wmi.options.update(
        method_path=r'CIM_DataFile.Name="C:\\test.txt"',
        method_name="CompressEx",
        inputs={"Recursive": recursive},
        owner={"ReturnValue": (3, 0, 19)},
    )
    return connection.call_method(
        wmi.options["method_path"],
        "CompressEx",
        ["ReturnValue"],
        {"Recursive": recursive},
    )


@pytest.mark.parametrize("recursive", [False, True])
def test_boolean_method_inputs_use_provider_schema_and_are_released(
    helper: ModuleType, wmi: _Wmi, recursive: bool
) -> None:
    with helper.WmiConnection() as connection:
        assert _compression_call(connection, wmi, recursive) == {"ReturnValue": 0}
        assert "clear:11" in wmi.events
        assert [event for event in wmi.events if event.startswith("release:")] == [
            "release:105",
            "release:109",
            "release:108",
            "release:107",
            "release:106",
        ]
    assert not wmi.strings and wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize(
    ("stage", "released"),
    [
        ("get_instance", []),
        ("get", [106]),
        ("get_class", [106]),
        ("get_method", [107, 106]),
        ("spawn", [108, 107, 106]),
        ("put", [109, 108, 107, 106]),
        ("execute", [109, 108, 107, 106]),
    ],
)
def test_input_method_failures_release_resources_and_allow_recovery(
    helper: ModuleType, wmi: _Wmi, stage: str, released: list[int]
) -> None:
    with helper.WmiConnection() as connection:
        wmi.options[stage] = FAILURE
        with pytest.raises(OSError, match="HRESULT 0x80041003"):
            _compression_call(connection, wmi)
        assert [event for event in wmi.events if event.startswith("release:")] == [
            "release:" + str(pointer) for pointer in released
        ]
        if stage == "put":
            assert "clear:11" in wmi.events
        wmi.options.pop(stage)
        assert _compression_call(connection, wmi) == {"ReturnValue": 0}
    assert not wmi.strings


@pytest.mark.parametrize(
    ("stage", "message"),
    [
        ("get_instance", "no object"),
        ("get_class", "no object"),
        ("get_method", "no input signature"),
        ("spawn", "no method input instance"),
    ],
)
def test_missing_method_input_objects_fail_actionably(
    helper: ModuleType, wmi: _Wmi, stage: str, message: str
) -> None:
    wmi.options["missing_pointer"] = stage
    with helper.WmiConnection() as connection:
        with pytest.raises(OSError, match=message):
            _compression_call(connection, wmi)
    assert not wmi.strings


@pytest.mark.parametrize("class_name", [None, ""])
def test_method_without_class_name_fails_actionably(
    helper: ModuleType, wmi: _Wmi, class_name: str | None
) -> None:
    wmi.options["class_name"] = class_name
    with helper.WmiConnection() as connection:
        with pytest.raises(OSError, match="no class name"):
            _compression_call(connection, wmi)
    assert not wmi.strings


@pytest.mark.parametrize("value", [0, 1, [0], [None], {}])
def test_method_rejects_unsupported_inputs_before_provider_work(
    helper: ModuleType, wmi: _Wmi, value: Any
) -> None:
    with helper.WmiConnection() as connection:
        with pytest.raises(
            ValueError,
            match="Recursive must be boolean, string, a string list, or None",
        ):
            connection.call_method(
                "file", "CompressEx", [], {"Name": "valid", "Recursive": value}
            )
        assert "get_instance" not in wmi.events and "execute" not in wmi.events
    assert not wmi.strings


def _rename_call(connection: Any, wmi: _Wmi, name: str | None = "NEW") -> Any:
    inputs = {"Name": name, "UserName": None, "Password": None}
    wmi.options.update(
        method_path='Win32_ComputerSystem.Name="OLD"',
        method_name="Rename",
        class_name="Win32_ComputerSystem",
        inputs=inputs,
        owner={"ReturnValue": (3, 0, 19)},
    )
    return connection.call_method(
        wmi.options["method_path"], "Rename", ["ReturnValue"], inputs
    )


@pytest.mark.parametrize("name", [None, "", "NEW", "雪😀", "before\x00after"])
def test_string_and_null_method_inputs_preserve_values_and_release_resources(
    helper: ModuleType, wmi: _Wmi, name: str | None
) -> None:
    with helper.WmiConnection() as connection:
        connection_strings = dict(wmi.strings)
        assert _rename_call(connection, wmi, name) == {"ReturnValue": 0}
        assert wmi.events.count("put") == 3
        assert wmi.events.count("clear:1") == (3 if name is None else 2)
        assert [event for event in wmi.events if event.startswith("release:")] == [
            "release:105",
            "release:109",
            "release:108",
            "release:107",
            "release:106",
        ]
        assert wmi.strings == connection_strings
    assert not wmi.strings and wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize("stage", ["allocation_failure", "put", "execute"])
def test_string_method_input_failures_release_resources_and_allow_recovery(
    helper: ModuleType, wmi: _Wmi, stage: str
) -> None:
    with helper.WmiConnection() as connection:
        connection_strings = dict(wmi.strings)
        wmi.options[stage] = "NEW" if stage == "allocation_failure" else FAILURE
        error = MemoryError if stage == "allocation_failure" else OSError
        message = (
            "allocate the WMI property string" if error is MemoryError else "HRESULT"
        )
        with pytest.raises(error, match=message):
            _rename_call(connection, wmi)
        assert "clear:8" in wmi.events
        assert [event for event in wmi.events if event.startswith("release:")] == [
            "release:109",
            "release:108",
            "release:107",
            "release:106",
        ]
        assert wmi.strings == connection_strings
        if stage != "execute":
            assert "execute" not in wmi.events
        wmi.options.pop(stage)
        assert _rename_call(connection, wmi) == {"ReturnValue": 0}
    assert not wmi.strings and wmi.events[-1] == "uninitialize"


def test_projected_process_query_requests_a_locatable_method_target(
    helper: ModuleType, wmi: _Wmi
) -> None:
    path = 'Win32_Process.Handle="42"'
    wmi.options["query_flags"] = 0x130
    wmi.options["rows"] = [{"Name": "worker.exe", "__PATH": path}]
    with helper.WmiConnection() as connection:
        assert connection.query(
            "SELECT Name FROM Win32_Process", ["Name", "__PATH"]
        ) == [{"Name": "worker.exe", "__PATH": path}]
    assert not wmi.strings


@pytest.mark.parametrize("kind", [0, 1])
def test_null_variants(helper: ModuleType, wmi: _Wmi, kind: int) -> None:
    wmi.options["kind"] = kind
    with helper.WmiConnection() as connection:
        assert connection.query(
            "SELECT LastBootUpTime FROM Win32_OperatingSystem", ["LastBootUpTime"]
        ) == [{"LastBootUpTime": None}]
    assert not wmi.strings


def test_no_input_method_copies_outputs_and_releases_them(
    helper: ModuleType, wmi: _Wmi
) -> None:
    with helper.WmiConnection() as connection:
        result = connection.call_method(
            'Win32_Process.Handle="42"', "GetOwner", ["Domain", "User"]
        )
        assert result == {"Domain": "LAB", "User": "owner"}
        assert "release:105" in wmi.events
        assert "release:102" not in wmi.events
    assert not wmi.strings
    assert wmi.events[-1] == "uninitialize"


def test_empty_inputs_supply_provider_defaults_without_an_array(
    helper: ModuleType, wmi: _Wmi
) -> None:
    wmi.options.update(
        method_path='Win32_NetworkAdapterConfiguration.Index="4"',
        method_name="SetDNSServerSearchOrder",
        class_name="Win32_NetworkAdapterConfiguration",
        inputs={},
        owner={"ReturnValue": (3, 0, 19)},
    )
    with helper.WmiConnection() as connection:
        assert connection.call_method(
            wmi.options["method_path"],
            wmi.options["method_name"],
            ["ReturnValue"],
            {},
        ) == {"ReturnValue": 0}
    assert "release:109" in wmi.events
    assert not wmi.strings and not wmi.arrays


@pytest.mark.parametrize(
    "values", [[], [""], ["192.0.2.1", "2001:db8::2"], ["雪😀", "before\x00after"]]
)
@pytest.mark.parametrize("lower", [0, 3])
def test_array_queries_preserve_order_and_strings_and_release_elements(
    helper: ModuleType, wmi: _Wmi, values: list[str], lower: int
) -> None:
    wmi.options.update(rows=[{"Servers": values}], lower=lower)
    with helper.WmiConnection() as connection:
        assert connection.query("SELECT Servers FROM Example", ["Servers"]) == [
            {"Servers": values}
        ]
    assert not wmi.strings and not wmi.arrays
    assert "clear:8200" in wmi.events


@pytest.mark.parametrize("stage", ["array_lower", "array_upper", "array_get"])
def test_array_query_failure_releases_array_and_all_copied_strings(
    helper: ModuleType, wmi: _Wmi, stage: str
) -> None:
    wmi.options.update(
        rows=[{"Servers": ["192.0.2.1", "192.0.2.2"]}], **{stage: FAILURE}
    )
    with helper.WmiConnection() as connection:
        with pytest.raises(OSError, match="SafeArray"):
            connection.query("SELECT Servers FROM Example", ["Servers"])
    assert not wmi.strings and not wmi.arrays


@pytest.mark.parametrize(
    "values", [[], ["192.0.2.1", "192.0.2.2"], ["雪😀", "before\x00after"]]
)
def test_array_method_inputs_copy_values_and_release_resources(
    helper: ModuleType, wmi: _Wmi, values: list[str]
) -> None:
    inputs = {"DNSServerSearchOrder": values}
    wmi.options.update(
        method_path='Win32_NetworkAdapterConfiguration.Index="4"',
        method_name="SetDNSServerSearchOrder",
        class_name="Win32_NetworkAdapterConfiguration",
        inputs=inputs,
        owner={"ReturnValue": (3, 0, 19)},
    )
    with helper.WmiConnection() as connection:
        assert connection.call_method(
            wmi.options["method_path"],
            wmi.options["method_name"],
            ["ReturnValue"],
            inputs,
        ) == {"ReturnValue": 0}
    assert not wmi.strings and not wmi.arrays


@pytest.mark.parametrize(
    "stage",
    ["array_create_failure", "allocation_failure", "array_put", "put", "execute"],
)
def test_array_method_failure_releases_allocations_and_allows_retry(
    helper: ModuleType, wmi: _Wmi, stage: str
) -> None:
    inputs = {"DNSServerSearchOrder": ["192.0.2.1", "192.0.2.2"]}
    wmi.options.update(
        method_path='Win32_NetworkAdapterConfiguration.Index="4"',
        method_name="SetDNSServerSearchOrder",
        class_name="Win32_NetworkAdapterConfiguration",
        inputs=inputs,
        owner={"ReturnValue": (3, 0, 19)},
    )
    wmi.options[stage] = "192.0.2.2" if stage == "allocation_failure" else FAILURE
    with helper.WmiConnection() as connection:
        existing = dict(wmi.strings)
        with pytest.raises((MemoryError, OSError)):
            connection.call_method(
                wmi.options["method_path"],
                wmi.options["method_name"],
                ["ReturnValue"],
                inputs,
            )
        assert wmi.strings == existing and not wmi.arrays
        wmi.options.pop(stage)
        assert connection.call_method(
            wmi.options["method_path"],
            wmi.options["method_name"],
            ["ReturnValue"],
            inputs,
        ) == {"ReturnValue": 0}
    assert not wmi.strings and not wmi.arrays


@pytest.mark.parametrize("stage", ["execute", "get", "clear"])
def test_method_failures_release_and_allow_recovery(
    helper: ModuleType, wmi: _Wmi, stage: str
) -> None:
    with helper.WmiConnection() as connection:
        wmi.options[stage] = FAILURE
        with pytest.raises(OSError, match="HRESULT 0x80041003") as caught:
            connection.call_method(
                'Win32_Process.Handle="42"', "GetOwner", ["Domain", "User"]
            )
        assert getattr(caught.value, "hresult") == 0x80041003
        assert sum(event == "release:105" for event in wmi.events) == int(
            stage != "execute"
        )
        wmi.options.pop(stage)
        assert (
            connection.call_method(
                'Win32_Process.Handle="42"', "GetOwner", ["Domain", "User"]
            )["User"]
            == "owner"
        )
    assert not wmi.strings


def test_method_without_output_is_actionable(helper: ModuleType, wmi: _Wmi) -> None:
    wmi.options["missing_output"] = True
    with helper.WmiConnection() as connection:
        with pytest.raises(OSError, match="returned no output"):
            connection.call_method('Win32_Process.Handle="42"', "GetOwner", ["User"])
    assert not wmi.strings


def test_opted_in_empty_method_output_is_source_exact_and_releases_resources(
    helper: ModuleType, wmi: _Wmi
) -> None:
    wmi.options["missing_output"] = True
    with helper.WmiConnection() as connection:
        assert (
            connection.call_method(
                'Win32_Process.Handle="42"', "GetOwner", ["User"], allow_empty=True
            )
            == {}
        )
    assert not wmi.strings and not wmi.arrays
    assert "release:105" not in wmi.events
    assert wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize("allow_empty", [False, True])
def test_empty_output_opt_in_does_not_hide_native_failures(
    helper: ModuleType, wmi: _Wmi, allow_empty: bool
) -> None:
    wmi.options.update(missing_output=True, execute=FAILURE)
    with helper.WmiConnection() as connection:
        with pytest.raises(OSError, match="HRESULT 0x80041003"):
            connection.call_method(
                'Win32_Process.Handle="42"',
                "GetOwner",
                ["User"],
                allow_empty=allow_empty,
            )
    assert not wmi.strings and not wmi.arrays
    assert wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize("allow_empty", [False, True])
def test_empty_output_opt_in_preserves_nonempty_properties_and_cleanup(
    helper: ModuleType, wmi: _Wmi, allow_empty: bool
) -> None:
    with helper.WmiConnection() as connection:
        assert connection.call_method(
            'Win32_Process.Handle="42"', "GetOwner", ["User"], allow_empty=allow_empty
        ) == {"User": "owner"}
    assert not wmi.strings and not wmi.arrays
    assert wmi.events.count("release:105") == 1
    assert wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize("value", ['Win32_Process.Handle="42"', "GetOwner"])
def test_method_allocation_failure_releases_acquisitions(
    helper: ModuleType, wmi: _Wmi, value: str
) -> None:
    wmi.options["allocation_failure"] = value
    with helper.WmiConnection() as connection:
        with pytest.raises(MemoryError):
            connection.call_method('Win32_Process.Handle="42"', "GetOwner", ["User"])
    assert not wmi.strings
    assert wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize("value", [None, "", "text", "雪😀", "before\0after"])
def test_string_property_update_preserves_text_and_releases_resources(
    helper: ModuleType, wmi: _Wmi, value: str | None
) -> None:
    path = "Win32_OperatingSystem=@"
    wmi.options.update(method_path=path, string_value=value)
    with helper.WmiConnection() as connection:
        assert connection.set_string_property(path, "Description", value) is None
    assert "put_property" in wmi.events and "update_instance" in wmi.events
    assert wmi.events.index("clear:" + ("1" if value is None else "8")) < (
        wmi.events.index("update_instance")
    )
    assert wmi.events.index("release:106") < wmi.events.index("release:102")
    assert not wmi.strings


@pytest.mark.parametrize(
    "operation", ["get_instance", "put_property", "update_instance", "clear"]
)
def test_string_property_failures_release_resources_and_allow_retry(
    helper: ModuleType, wmi: _Wmi, operation: str
) -> None:
    path = "Win32_OperatingSystem=@"
    wmi.options.update(method_path=path, string_value="new", **{operation: FAILURE})
    with helper.WmiConnection() as connection:
        with pytest.raises(OSError):
            connection.set_string_property(path, "Description", "new")
        wmi.options[operation] = 0
        connection.set_string_property(path, "Description", "new")
    assert not wmi.strings


def test_string_property_allocation_failure_releases_instance(
    helper: ModuleType, wmi: _Wmi
) -> None:
    path = "Win32_OperatingSystem=@"
    wmi.options.update(method_path=path, string_value="new", allocation_failure="new")
    with helper.WmiConnection() as connection:
        with pytest.raises(MemoryError):
            connection.set_string_property(path, "Description", "new")
    assert "update_instance" not in wmi.events
    assert "release:106" in wmi.events and not wmi.strings


@pytest.mark.parametrize("value", [False, 1, [], {}])
def test_string_property_rejects_non_strings_before_provider_work(
    helper: ModuleType, wmi: _Wmi, value: Any
) -> None:
    with helper.WmiConnection() as connection:
        with pytest.raises(ValueError, match="string or None"):
            connection.set_string_property(
                "Win32_OperatingSystem=@", "Description", value
            )
    assert "get_instance" not in wmi.events and not wmi.strings
    assert wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize("value", [-(2**31), -1, 0, 1, 2, 4, 2**31 - 1])
def test_integer_property_preserves_vt_i4_values_and_releases_resources(
    helper: ModuleType, wmi: _Wmi, value: int
) -> None:
    path = 'MSFT_NetFirewallProfile.InstanceID="Domain"'
    wmi.options.update(method_path=path, integer_value=value)
    with helper.WmiConnection() as connection:
        assert connection.set_integer_property(path, "Enabled", value) is None
    assert wmi.events.index("clear:3") < wmi.events.index("update_instance")
    assert wmi.events.index("release:106") < wmi.events.index("release:102")
    assert not wmi.strings


@pytest.mark.parametrize(
    "operation", ["get_instance", "put_property", "update_instance", "clear"]
)
def test_integer_property_failure_releases_resources_and_allows_recovery(
    helper: ModuleType, wmi: _Wmi, operation: str
) -> None:
    path = 'MSFT_NetFirewallProfile.InstanceID="Domain"'
    wmi.options.update(method_path=path, integer_value=2, **{operation: FAILURE})
    with helper.WmiConnection() as connection:
        with pytest.raises(OSError):
            connection.set_integer_property(path, "Enabled", 2)
        wmi.options[operation] = 0
        connection.set_integer_property(path, "Enabled", 2)
    if operation in ("get_instance", "put_property", "clear"):
        assert wmi.events.count("update_instance") == 1
    else:
        assert wmi.events.count("update_instance") == 2
    assert not wmi.strings and wmi.events[-1] == "uninitialize"


@pytest.mark.parametrize(
    "value", [True, False, None, "1", 1.0, [], {}, -(2**31) - 1, 2**31]
)
def test_integer_property_rejects_invalid_values_before_provider_work(
    helper: ModuleType, wmi: _Wmi, value: Any
) -> None:
    with helper.WmiConnection() as connection:
        with pytest.raises(ValueError, match="integer"):
            connection.set_integer_property("unused", "Enabled", value)
    assert "get_instance" not in wmi.events and not wmi.strings
    assert wmi.events[-1] == "uninitialize"
