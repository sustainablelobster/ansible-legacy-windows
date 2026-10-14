"""Exercise product-reader native boundaries without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import json
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module

REFERENCE = json.loads(
    (ROOT / "tests/fixtures/product_license_reference.json").read_text(encoding="utf-8")
)
_LICENSE_COLUMNS = ["PartialProductKey", "Name", "ProductKeyChannel", "LicenseStatus"]


@pytest.fixture(name="helper")
def product_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the reader and isolate the separately tested binary decoder.

    :param monkeypatch: Scoped import path and decoder substitution.
    :returns: Reader imported with the development interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_product.py",
        "tested_product",
    )
    monkeypatch.setattr(helper, "decode_product_key", Mock(return_value="decoded key"))
    return helper


@pytest.fixture(name="connection")
def product_connection(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Provide context-managed WMI rows and observable query ordering.

    :param helper: Loaded reader.
    :param monkeypatch: Scoped native connection substitute.
    :returns: Connection with mutable synthetic rows keyed by class name.
    """
    native = MagicMock()
    native.__enter__.return_value = native
    native.rows = {
        "SoftwareLicensingService": [{"OA3xOriginalProductKey": "firmware key"}],
        "SoftwareLicensingProduct": [],
        "Win32_OperatingSystem": [{"SerialNumber": "product identifier"}],
    }

    def _query(wql: str, properties: list[str]) -> Any:
        assert all(property_name in wql for property_name in properties)
        rows = native.rows[wql.rsplit(" ", 1)[1]]
        if isinstance(rows, Exception):
            raise rows
        return rows

    native.query.side_effect = _query
    monkeypatch.setattr(helper, "WmiConnection", lambda: native)
    return native


@pytest.fixture(name="registry")
def product_registry(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Substitute native registry handles without bypassing close behavior.

    :param helper: Loaded reader.
    :param monkeypatch: Scoped winreg substitute.
    :returns: Registry operations and their synthetic named values.
    """
    key = MagicMock()
    key.__enter__.return_value = key
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE="machine hive",
        OpenKey=Mock(return_value=key),
        QueryValueEx=Mock(),
        key=key,
        values={"DigitalProductId": None, "DigitalProductId4": None},
    )

    def _query(handle: Any, name: str) -> tuple[Any, int]:
        assert handle is key
        value = registry.values[name]
        if isinstance(value, Exception):
            raise value
        return value, 3

    registry.QueryValueEx.side_effect = _query
    monkeypatch.setattr(helper, "winreg", registry)
    return registry


@pytest.fixture(name="mapper")
def product_name_mapper(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Provide finite en-US casing responses, not a Windows runtime assertion.

    :param helper: Loaded reader.
    :param monkeypatch: Scoped native casing boundary.
    :returns: Observable two-call string mapper.
    """
    mapping = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    mapping[ord("İ")] = ord("i")

    # Keep the native six-argument LCMapStringW signature visible at this boundary.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _map(
        locale: int, flags: int, source: str, length: int, buffer: Any, size: int
    ) -> int:
        assert locale == 0x400 and flags in (0x01000100, 0x100)
        assert length == len(source.encode("utf-16-le", "surrogatepass")) // 2
        lowered = source.translate(mapping)
        if buffer is None:
            assert size == 0
        else:
            assert size == len(lowered)
            for index, character in enumerate(lowered):
                buffer[index] = character
        return len(lowered)

    operation = Mock(side_effect=_map)
    monkeypatch.setattr(helper, "_name_mapper", lambda: operation)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        ctypes,
        "WinError",
        lambda code: OSError(code, "native mapping failed"),
        raising=False,
    )
    return operation


def _license(
    name: Any = "Windows fixture", status: Any = 1, channel: Any = None
) -> dict[str, Any]:
    return {
        "PartialProductKey": "synthetic partial key",
        "Name": name,
        "LicenseStatus": status,
        "ProductKeyChannel": channel,
    }


def test_firmware_precedes_registry_and_queries_close_in_upstream_order(
    helper: ModuleType, connection: Any, registry: Any
) -> None:
    warnings: list[str] = []
    assert helper.read_facts(warnings) == {
        "ansible_os_product_id": "product identifier",
        "ansible_os_product_key": "firmware key",
        "ansible_os_license_edition": None,
        "ansible_os_license_channel": None,
        "ansible_os_license_status": None,
    }
    assert not warnings
    registry.OpenKey.assert_not_called()
    helper.decode_product_key.assert_not_called()
    assert connection.query.call_args_list == [
        call(
            "SELECT OA3xOriginalProductKey FROM SoftwareLicensingService",
            ["OA3xOriginalProductKey"],
        ),
        call(
            "SELECT PartialProductKey, Name, ProductKeyChannel, LicenseStatus "
            "FROM SoftwareLicensingProduct",
            _LICENSE_COLUMNS,
        ),
        call("SELECT SerialNumber FROM Win32_OperatingSystem", ["SerialNumber"]),
    ]
    connection.__exit__.assert_called_once_with(None, None, None)


@pytest.mark.parametrize(
    "firmware",
    [
        [],
        [{"OA3xOriginalProductKey": None}],
        [{"OA3xOriginalProductKey": ""}],
        OSError("firmware read denied"),
    ],
)
def test_missing_firmware_uses_first_present_registry_value(
    helper: ModuleType, connection: Any, registry: Any, firmware: Any
) -> None:
    connection.rows["SoftwareLicensingService"] = firmware
    data = bytes(range(67))
    registry.values["DigitalProductId"] = data
    assert helper.read_facts([])["ansible_os_product_key"] == "decoded key"
    helper.decode_product_key.assert_called_once_with(data)
    registry.OpenKey.assert_called_once_with(
        "machine hive", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    )
    registry.QueryValueEx.assert_called_once_with(registry.key, "DigitalProductId")
    registry.key.__exit__.assert_called_once_with(None, None, None)


@pytest.mark.parametrize(
    "first", [None, b"", b"\x00", bytearray([0]), [0], OSError("registry denied")]
)
def test_falsy_first_registry_value_falls_back_including_singleton_zero(
    helper: ModuleType, connection: Any, registry: Any, first: Any
) -> None:
    connection.rows["SoftwareLicensingService"] = []
    registry.values.update(DigitalProductId=first, DigitalProductId4=b"fallback")
    assert helper.read_facts([])["ansible_os_product_key"] == "decoded key"
    helper.decode_product_key.assert_called_once_with(b"fallback")
    assert registry.QueryValueEx.call_args_list == [
        call(registry.key, "DigitalProductId"),
        call(registry.key, "DigitalProductId4"),
    ]
    assert registry.key.__exit__.call_count == 2


@pytest.mark.parametrize("data", [b"\x01", b"\x00\x00", bytearray([0, 0]), [0, 0]])
def test_present_registry_values_are_decoded_without_content_truth_coercion(
    helper: ModuleType, connection: Any, registry: Any, data: Any
) -> None:
    connection.rows["SoftwareLicensingService"] = []
    registry.values["DigitalProductId"] = data
    assert helper.read_facts([])["ansible_os_product_key"] == "decoded key"
    helper.decode_product_key.assert_called_once_with(data)
    registry.QueryValueEx.assert_called_once_with(registry.key, "DigitalProductId")


@pytest.mark.parametrize("firmware", [None, ""])
@pytest.mark.parametrize("failure", ["open", "read"])
def test_registry_failures_preserve_missing_or_empty_firmware_and_recover(
    helper: ModuleType, connection: Any, registry: Any, firmware: Any, failure: str
) -> None:
    connection.rows["SoftwareLicensingService"] = [{"OA3xOriginalProductKey": firmware}]
    operation = registry.OpenKey if failure == "open" else registry.QueryValueEx
    previous = operation.side_effect
    operation.side_effect = OSError("registry unavailable")
    assert helper.read_facts([])["ansible_os_product_key"] == firmware
    assert registry.key.__exit__.call_count == (0 if failure == "open" else 2)
    operation.side_effect = previous
    registry.values["DigitalProductId"] = b"available again"
    assert helper.read_facts([])["ansible_os_product_key"] == "decoded key"
    assert connection.__exit__.call_count == 2


@pytest.mark.parametrize("values", [[None, ""], ["firmware A", "firmware B"]])
def test_multiple_firmware_values_retain_shape_and_do_not_read_registry(
    helper: ModuleType, connection: Any, registry: Any, values: list[Any]
) -> None:
    connection.rows["SoftwareLicensingService"] = [
        {"OA3xOriginalProductKey": value} for value in values
    ]
    assert helper.read_facts([])["ansible_os_product_key"] == values
    registry.OpenKey.assert_not_called()


@pytest.mark.parametrize("case", REFERENCE["licenses"])
def test_license_shapes_and_status_order_match_recorded_synthetic_reference(
    helper: ModuleType, connection: Any, mapper: Mock, case: dict[str, Any]
) -> None:
    connection.rows["SoftwareLicensingProduct"] = [
        _license("Windows status " + str(status), status) for status in case["statuses"]
    ]
    result = helper.read_facts([])
    assert result["ansible_os_license_edition"] == case["edition"]
    assert result["ansible_os_license_channel"] == case["channel"]
    assert result["ansible_os_license_status"] == case["status"]
    assert mapper.call_count == len(case["statuses"]) * 2


@pytest.mark.parametrize("case", REFERENCE["names"])
def test_name_selection_matches_reference_with_explicit_native_mapping_substitute(
    helper: ModuleType, connection: Any, mapper: Mock, case: dict[str, Any]
) -> None:
    connection.rows["SoftwareLicensingProduct"] = [_license(case["name"])]
    result = helper.read_facts([])
    assert result["ansible_os_license_edition"] == (
        case["name"] if case["matched"] else None
    )
    assert mapper.call_count == 2


def test_selection_preserves_order_duplicate_rows_empty_channels_and_null_statuses(
    helper: ModuleType, connection: Any, mapper: Mock
) -> None:
    connection.rows["SoftwareLicensingProduct"] = [
        dict(_license("Windows ignored"), PartialProductKey=""),
        dict(_license("Windows ignored"), PartialProductKey=None),
        _license(None),
        _license(""),
        _license("Office"),
        _license("Windows B", None, ""),
        _license("Windows A", 1, "Retail"),
        _license("Windows B", -1, None),
    ]
    result = helper.read_facts([])
    assert result["ansible_os_license_edition"] == [
        "Windows B",
        "Windows A",
        "Windows B",
    ]
    assert result["ansible_os_license_channel"] == ["", "Retail", None]
    assert result["ansible_os_license_status"] == [None, "Licensed", None]
    assert mapper.call_count == 8


@pytest.mark.parametrize("serials", [[], [None], [""], ["ID B", None, "ID A"]])
def test_operating_system_product_ids_retain_shape_and_order(
    helper: ModuleType, connection: Any, serials: list[Any]
) -> None:
    connection.rows["Win32_OperatingSystem"] = [
        {"SerialNumber": value} for value in serials
    ]
    expected = None if not serials else serials[0] if len(serials) == 1 else serials
    assert helper.read_facts([])["ansible_os_product_id"] == expected


@pytest.mark.parametrize("major", [5, 6, 10])
@pytest.mark.parametrize(
    "hresult", [0x80041010, 0x80041003, 0x80070005, 0x80070426, None]
)
def test_only_legacy_invalid_class_returns_null_license_fields_and_named_warnings(
    helper: ModuleType,
    connection: Any,
    monkeypatch: pytest.MonkeyPatch,
    major: int,
    hresult: int | None,
) -> None:
    error = OSError("licensing unavailable")
    if hresult is not None:
        setattr(error, "hresult", hresult)
    connection.rows["SoftwareLicensingProduct"] = error
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        helper.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=major),
        raising=False,
    )
    # pylint: enable=duplicate-code
    warnings: list[str] = []
    if major == 5 and hresult == 0x80041010:
        result = helper.read_facts(warnings)
        assert result["ansible_os_product_key"] == "firmware key"
        assert result["ansible_os_product_id"] == "product identifier"
        assert all(
            result["ansible_os_license_" + field] is None
            for field in ("edition", "channel", "status")
        )
        assert warnings == [
            "ansible_os_license_"
            + field
            + " is unavailable: this Windows version does not provide SoftwareLicensingProduct."
            for field in ("edition", "channel", "status")
        ]
    else:
        with pytest.raises(OSError) as caught:
            helper.read_facts(warnings)
        assert caught.value is error and not warnings
        assert connection.query.call_count == 2
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize("count", [0, 1, 2])
def test_missing_channel_projection_retains_available_license_fields_and_recovers(
    helper: ModuleType,
    connection: Any,
    mapper: Mock,
    monkeypatch: pytest.MonkeyPatch,
    count: int,
) -> None:
    query = connection.query.side_effect
    missing_channel = OSError("undefined property in projection")
    setattr(missing_channel, "hresult", 0x80041017)
    rows = [
        {
            "PartialProductKey": "synthetic partial key",
            "Name": "Windows " + str(index),
            "LicenseStatus": index,
        }
        for index in range(count)
    ]
    version = Mock(side_effect=AssertionError("fallback must not depend on OS version"))
    monkeypatch.setattr(helper.sys, "getwindowsversion", version, raising=False)

    def _query(wql: str, properties: list[str]) -> Any:
        if wql.endswith("FROM SoftwareLicensingProduct"):
            if "ProductKeyChannel" in properties:
                raise missing_channel
            return rows
        return query(wql, properties)

    connection.query.side_effect = _query
    warnings: list[str] = []
    result = helper.read_facts(warnings)
    assert result["ansible_os_product_id"] == "product identifier"
    assert result["ansible_os_product_key"] == "firmware key"
    assert result["ansible_os_license_edition"] == (
        None
        if count == 0
        else "Windows 0" if count == 1 else ["Windows 0", "Windows 1"]
    )
    assert result["ansible_os_license_channel"] == (None if count < 2 else [None, None])
    assert result["ansible_os_license_status"] == (
        None
        if count == 0
        else "Unlicensed" if count == 1 else ["Unlicensed", "Licensed"]
    )
    assert warnings == [
        "ansible_os_license_channel is unavailable: SoftwareLicensingProduct "
        "does not provide ProductKeyChannel."
    ]
    assert connection.query.call_args_list[2] == call(
        "SELECT PartialProductKey, Name, LicenseStatus FROM SoftwareLicensingProduct",
        ["PartialProductKey", "Name", "LicenseStatus"],
    )
    assert connection.query.call_count == 4
    assert mapper.call_count == count * 2
    connection.__exit__.assert_called_once_with(None, None, None)
    version.assert_not_called()

    connection.query.side_effect = query
    connection.rows["SoftwareLicensingProduct"] = [_license(channel="Retail")]
    next_warnings: list[str] = []
    assert helper.read_facts(next_warnings)["ansible_os_license_channel"] == "Retail"
    assert not next_warnings and connection.query.call_count == 7
    assert connection.__exit__.call_count == 2


@pytest.mark.parametrize(
    "hresult", [0x80041017, 0x80041010, 0x80041003, 0x80070005, 0x80070426, None]
)
def test_failed_reduced_projection_propagates_without_claiming_missing_channel(
    helper: ModuleType,
    connection: Any,
    monkeypatch: pytest.MonkeyPatch,
    hresult: int | None,
) -> None:
    original_query = connection.query.side_effect
    missing_channel = OSError("undefined property in projection")
    setattr(missing_channel, "hresult", 0x80041017)
    retry_error = OSError("reduced query failed")
    if hresult is not None:
        setattr(retry_error, "hresult", hresult)
    monkeypatch.setattr(
        helper.sys, "getwindowsversion", lambda: SimpleNamespace(major=5), raising=False
    )
    connection.query.side_effect = [
        [{"OA3xOriginalProductKey": "firmware key"}],
        missing_channel,
        retry_error,
    ]
    warnings: list[str] = []
    with pytest.raises(OSError) as caught:
        helper.read_facts(warnings)
    assert caught.value is retry_error
    assert not warnings and connection.query.call_count == 3
    assert connection.query.call_args == call(
        "SELECT PartialProductKey, Name, LicenseStatus FROM SoftwareLicensingProduct",
        ["PartialProductKey", "Name", "LicenseStatus"],
    )
    connection.__exit__.assert_called_once()
    assert connection.__exit__.call_args.args[1] is retry_error

    connection.query.side_effect = original_query
    result = helper.read_facts(warnings)
    assert result["ansible_os_product_id"] == "product identifier"
    assert result["ansible_os_license_channel"] is None
    assert not warnings and connection.query.call_count == 6
    assert connection.__exit__.call_count == 2


@pytest.mark.parametrize("phase", ["firmware", "license", "operating_system", "decode"])
def test_unhandled_read_failure_releases_connection_and_next_read_recovers(
    helper: ModuleType, connection: Any, registry: Any, phase: str
) -> None:
    error_type: type[Exception]
    if phase == "decode":
        connection.rows["SoftwareLicensingService"] = []
        registry.values["DigitalProductId"] = b"invalid binary"
        helper.decode_product_key.side_effect = ValueError("invalid key data")
        error_type = ValueError
    else:
        class_name = {
            "firmware": "SoftwareLicensingService",
            "license": "SoftwareLicensingProduct",
            "operating_system": "Win32_OperatingSystem",
        }[phase]
        connection.rows[class_name] = MemoryError("query allocation failed")
        error_type = MemoryError
    with pytest.raises(error_type):
        helper.read_facts([])
    connection.__exit__.assert_called_once()
    assert connection.__exit__.call_args.args[0] is error_type
    if phase == "decode":
        helper.decode_product_key.side_effect = None
        registry.key.__exit__.assert_called_once_with(None, None, None)
    else:
        connection.rows[class_name] = []
    assert set(helper.read_facts([])) == {
        "ansible_os_product_id",
        "ansible_os_product_key",
        "ansible_os_license_edition",
        "ansible_os_license_channel",
        "ansible_os_license_status",
    }
    assert connection.__exit__.call_count == 2


@pytest.mark.parametrize("name", ["prefix\x00Windows", "😀Windows", "\ud800Windows"])
def test_native_name_mapping_uses_explicit_utf16_length_and_full_output(
    helper: ModuleType, connection: Any, mapper: Mock, name: str
) -> None:
    connection.rows["SoftwareLicensingProduct"] = [_license(name)]
    assert helper.read_facts([])["ansible_os_license_edition"] == name
    sizing, writing = mapper.call_args_list
    assert sizing.args[:4] == (
        0x400,
        0x01000100,
        name,
        len(name.encode("utf-16-le", "surrogatepass")) // 2,
    )
    assert sizing.args[4:] == (None, 0)
    assert writing.args[4] is not None and writing.args[5] == len(name)


def test_legacy_invalid_flags_retries_without_linguistic_casing(
    helper: ModuleType, connection: Any, mapper: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection.rows["SoftwareLicensingProduct"] = [_license()]
    original = mapper.side_effect
    attempts = 0

    def _map(*args: Any) -> int:
        nonlocal attempts
        attempts += 1
        return 0 if attempts == 1 else int(original(*args))

    mapper.side_effect = _map
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1004)
    assert helper.read_facts([])["ansible_os_license_edition"] == "Windows fixture"
    assert [item.args[1] for item in mapper.call_args_list] == [
        0x01000100,
        0x100,
        0x100,
    ]


@pytest.mark.parametrize("failure", ["size", "write", "legacy_retry"])
def test_native_mapping_failures_propagate_and_close_wmi_without_false_nonmatch(
    helper: ModuleType,
    connection: Any,
    mapper: Mock,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    connection.rows["SoftwareLicensingProduct"] = [_license()]
    mapper.side_effect = [4, 0] if failure == "write" else [0, 0]
    monkeypatch.setattr(
        ctypes, "get_last_error", lambda: 1004 if failure == "legacy_retry" else 5
    )
    with pytest.raises(OSError, match="native mapping failed") as caught:
        helper.read_facts([])
    assert caught.value.errno == (1004 if failure == "legacy_retry" else 5)
    assert mapper.call_count == (1 if failure == "size" else 2)
    connection.__exit__.assert_called_once()


def test_native_mapper_declares_windows_fixed_width_signature(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation = Mock()
    loader = Mock(return_value=SimpleNamespace(LCMapStringW=operation))
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    # This focused ABI test inspects the private native binding, not its consumers.
    assert helper._name_mapper() is operation  # pylint: disable=protected-access
    loader.assert_called_once_with("kernel32", use_last_error=True)
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert operation.argtypes == [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    # pylint: enable=duplicate-code
    assert operation.restype is ctypes.c_int
