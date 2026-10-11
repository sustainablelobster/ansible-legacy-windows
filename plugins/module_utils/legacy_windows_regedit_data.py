# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Convert registry values and compare the reference module's data forms."""

import ctypes
import re

import legacy_windows_module as module  # pylint: disable=import-error

_KINDS = {
    "none": "None",
    "binary": "Binary",
    "dword": "DWord",
    "expandstring": "ExpandString",
    "multistring": "MultiString",
    "string": "String",
    "qword": "QWord",
    # Readable legacy kinds such as big-endian DWORDs are diffable, not inputs.
    "unknown": "Unknown",
}


class DataValidationError(ValueError):
    """Report a data failure for which upstream preserves its result fields."""


def _invariant_text(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Reuse the measured numeric formatter before its caller applies the
        # account's decimal/sign symbols; multistring uses invariant culture.
        return module._number_text(value, "data")  # pylint: disable=protected-access
    if isinstance(value, (str, bool)):
        return str(value)
    if value is None:
        raise ValueError("You cannot call a method on a null-valued expression.")
    raise ValueError(
        'Cannot find an overload for "ToString" and the argument count: "1".'
    )


def _hex_byte(value):
    if not re.match(r"^(?:0x)?[0-9a-f]+$", value, re.IGNORECASE):
        raise ValueError("Cannot convert hexadecimal registry data to a byte: " + value)
    result = int(value, 16)
    if result > 255:
        raise ValueError("Registry byte value is outside the range 0 to 255.")
    return result


def _binary_text(data):
    value = re.sub(r"^hex:", "", data.lower())
    value = re.sub(r"[^a-f0-9\\,x\-:]", "", value).replace(",", ":")
    if not value:
        return []
    if len(value) == 1:
        parts = [value]
    elif len(value) % 2 == 0 and ":" not in value:
        parts = [part for part in re.split(r"([a-f0-9]{2})", value) if part]
    elif ":" in value:
        parts = re.split(":+", value)
    else:
        return []
    return [_hex_byte(part) for part in parts]


def _byte(value):
    if value is None:
        return 0
    if isinstance(value, (int, float, bool)):
        result = int(round(value))
    elif isinstance(value, str):
        result = _integer_text(value)
    else:
        raise ValueError("Cannot convert registry data to a byte.")
    if not 0 <= result <= 255:
        raise ValueError("Registry byte value is outside the range 0 to 255.")
    return result


def _integer_text(value):
    if value == "":
        return 0
    text = value.strip(module.DOTNET_WHITESPACE)
    if not text:
        raise ValueError("Index was outside the bounds of the array.")
    if re.match(r"^[+-]?[0-9]+$", text):
        return int(text, 10)
    if re.match(r"^[+-]?0x[0-9a-f]+$", text, re.IGNORECASE):
        return int(text, 16)
    if re.match(
        r"^[+-]?(?:[0-9][0-9,]*(?:\.[0-9]*)?|\.[0-9]+)(?:e[+-]?[0-9]+)?$",
        text,
        re.IGNORECASE,
    ):
        try:
            # Non-integer strings use the reference's Double fallback. It
            # rounds halfway to even and can lose precision near UInt64.Max.
            return int(round(float(text.replace(",", ""))))
        except (ValueError, OverflowError):
            pass
    raise ValueError("Input string was not in a correct format.")


def _unsigned_text(value):
    try:
        result = _integer_text(value)
        if not 0 <= result < 1 << 64:
            reason = "Value was either too large or too small for a UInt64."
            if not re.match(
                r"^[+-]?(?:[0-9]+|0x[0-9a-f]+)$",
                value.strip(module.DOTNET_WHITESPACE),
                re.IGNORECASE,
            ):
                reason = "Input string was not in a correct format."
            raise ValueError(reason)
        return result
    except ValueError as error:
        raise ValueError(
            'Cannot convert value "{0}" to type "System.UInt64". Error: "{1}"'.format(
                value, error
            )
        ) from error


def _binary_data(data):
    if data is None:
        return []
    if isinstance(data, str):
        return _binary_text(data)
    if isinstance(data, list):
        return [_byte(value) for value in data]
    if (
        isinstance(data, int)
        and not isinstance(data, bool)
        and -(1 << 31) <= data < 1 << 31
    ):
        if data > 255:
            raise DataValidationError(
                "cannot convert binary data '{0}' to byte array, please specify "
                "this value as a yaml byte array or a comma separated hex value "
                "string".format(data)
            )
        return [_byte(data)]
    return data


def _integer_data(data, kind):
    bits = 32 if kind == "dword" else 64
    if data is None:
        data = 0
    elif isinstance(data, str):
        data = _unsigned_text(data)
    elif isinstance(data, float):
        if data % 1:
            raise DataValidationError(
                "data '{0}' cannot be a decimal or float value with a remainder "
                "when type is dword or qword".format(module.as_string(data, "data"))
            )
        if data < 0:
            raise ValueError(
                "Cannot convert registry data to an unsigned 64-bit integer."
            )
        data = int(data)
    elif isinstance(data, bool):
        data = int(data)
    if not isinstance(data, int):
        raise ValueError("Cannot convert registry data to an integer.")
    if data >= 1 << bits:
        raise DataValidationError(
            "data cannot be larger than 0x{0} when type is {1}".format(
                "f" * (bits // 4), kind
            )
        )
    if data < -(1 << (bits - 1)):
        raise ValueError(
            "Registry data is outside the signed {0}-bit range.".format(bits)
        )
    if data >= 1 << (bits - 1):
        data -= 1 << bits
    return data


def convert_data(data, kind, named):
    """Prepare input data using the selected registry kind.

    String data stays raw until the native setter, preserving requested diff
    values. A null unnamed string leaves its existing default value untouched.
    An explicit empty multistring list also returns ``None`` to skip writing.

    :param data: Raw JSON registry data, including an omitted value as ``None``.
    :type data: object
    :param kind: Validated, lowercase registry kind.
    :type kind: str
    :param named: Whether a nonempty registry value name was selected.
    :type named: bool
    :returns: Prepared data; integer kinds use their signed representation.
    :rtype: object
    :raises DataValidationError: For an explicit upstream data validation failure.
    :raises ValueError: If conversion fails or the kind is unknown.
    :raises OSError: If numeric formatting cannot read Windows locale settings.
    """
    if kind in ("binary", "none"):
        return _binary_data(data)
    if kind in ("dword", "qword"):
        return _integer_data(data, kind)
    if kind in ("string", "expandstring"):
        return "" if data is None and named else data
    if kind == "multistring":
        if data is None:
            return []
        # Upstream assigns the output of a foreach pipeline to string[]. An
        # explicit empty list emits no output, becoming null rather than [].
        if data == []:
            return None
        entries = data if isinstance(data, list) else [data]
        return [_invariant_text(entry) for entry in entries]
    raise ValueError("Unknown registry value kind: " + str(kind))


def diff_value(kind, value):
    """Describe a registry value using the upstream diff representation.

    :param kind: Lowercase registry kind, or ``unknown`` for a readable legacy kind.
    :type kind: str
    :param value: Converted data or a value read from the registry.
    :type value: object
    :returns: A mapping containing the registry type and formatted value.
    :rtype: dict
    :raises ValueError: If the kind name is unrecognized or diff formatting fails.
    """
    if kind not in _KINDS:
        raise ValueError("Unknown registry value kind: " + str(kind))
    if kind in ("binary", "none"):
        entries = value if isinstance(value, list) else [value]
        value = [_binary_diff(entry) for entry in entries]
    elif kind in ("dword", "qword"):
        bits = 32 if kind == "dword" else 64
        value = "0x{0:0{1}x}".format(value & ((1 << bits) - 1), bits // 4)
    return {"type": _KINDS[kind], "value": value}


def _binary_diff(value):
    if isinstance(value, bool):
        return "0x" + str(value)
    if isinstance(value, dict):
        return "0xSystem.Collections.Hashtable"
    if isinstance(value, int) and -(1 << 63) <= value < 1 << 63:
        if value < 0:
            value &= (1 << 64) - 1
        return "0x{0:02x}".format(value)
    raise ValueError("Error formatting a string: Format specifier was invalid..")


def _strings_equal(left, right, ignore_case):
    if left == right:
        return True
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    compare = kernel.CompareStringW
    # This Win32 signature also appears in read-only helpers. Keeping it here
    # avoids importing unrelated registry or environment operations.
    # pylint: disable=duplicate-code
    compare.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    compare.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    result = compare(
        0x7F,
        1 if ignore_case else 0,
        left,
        len(left.encode("utf-16-le", "surrogatepass")) // 2,
        right,
        len(right.encode("utf-16-le", "surrogatepass")) // 2,
    )
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result == 2


def _scalar_equal(existing, desired, ignore_case):
    if isinstance(existing, str):
        if not isinstance(desired, str):
            desired = _comparison_text(desired)
        return _strings_equal(existing, desired, ignore_case)
    if isinstance(existing, int):
        if isinstance(desired, str):
            try:
                desired = _integer_text(desired)
            except ValueError:
                return False
        return existing == desired
    return existing == desired


def _comparison_text(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(_comparison_text(entry) for entry in value)
    if isinstance(value, dict):
        return "System.Collections.Hashtable"
    return _invariant_text(value)


def values_equal(existing, desired):
    """Compare current and requested data with the reference's array rules.

    Scalar text comparison is case-sensitive. Array entries compare without
    case sensitivity, in order; a scalar desired value forms one entry.

    :param existing: Decoded registry value, using signed integer values.
    :type existing: object
    :param desired: Converted requested data.
    :type desired: object
    :returns: Whether the data compares equal independently of registry kind.
    :rtype: bool
    :raises ValueError: If a scalar cannot be converted for comparison.
    :raises OSError: If Windows string comparison fails.
    """
    if isinstance(existing, list):
        desired = desired if isinstance(desired, list) else [desired]
        return len(existing) == len(desired) and all(
            _scalar_equal(left, right, True) for left, right in zip(existing, desired)
        )
    return _scalar_equal(existing, desired, False)
