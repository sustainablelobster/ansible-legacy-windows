# SPDX-License-Identifier: GPL-3.0-or-later
"""Read and return Ansible WANT_JSON messages under Python 3.4.4."""

import ctypes
import decimal
import json
import math
import os
import re
import sys
import traceback
from collections import OrderedDict

# Upstream String.Trim() excludes the U+001C-U+001F separators that Python's
# default strip() removes. Keep command and comma-separated argument trimming
# consistent with upstream.
DOTNET_WHITESPACE = (
    "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
    "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)


def _invalid_constant(value):
    raise ValueError("The argument file contains a non-JSON number: " + value)


def as_bool(value, name):
    """Convert a boolean argument or controller flag.

    :param value: JSON value to convert.
    :type value: object
    :param name: Parameter name used in validation errors.
    :type name: str
    :returns: The converted boolean.
    :rtype: bool
    :raises ValueError: If the value does not identify a boolean.
    """
    if isinstance(value, bool):
        return value
    text = str(value).strip(DOTNET_WHITESPACE).lower()
    if text in ("true", "yes", "on", "1", "y", "t", "1.0"):
        return True
    if text in ("false", "no", "off", "0", "n", "f", "0.0"):
        return False
    raise ValueError("Expected a boolean for " + name + ".")


def as_string(value, name):
    """Convert a string argument while preserving an explicit null.

    :param value: JSON value to convert.
    :type value: object
    :param name: Parameter name used in validation errors.
    :type name: str
    :returns: Text, or None for an explicit null.
    :rtype: str or None
    :raises ValueError: If a number cannot be represented by the upstream types.
    :raises OSError: If Windows cannot return the account's numeric symbols.
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, list):
        return "System.Object[]"
    if isinstance(value, dict):
        return "System.Collections.Hashtable"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        text = _number_text(value, name)
        if text.isdecimal():
            return text
        separator, positive, negative = _number_symbols()
        return text.translate(
            str.maketrans({".": separator, "+": positive, "-": negative})
        )
    return str(value)


def _dictionary_fields(value):
    fields = []
    buffer = []
    quote = None
    escaped = False
    for character in value:
        if escaped:
            buffer.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote is None and character in "\"'":
            quote = character
        elif quote == character:
            quote = None
        elif quote is None and character in ", ":
            if buffer:
                fields.append("".join(buffer))
                buffer = []
        else:
            buffer.append(character)
    if buffer:
        fields.append("".join(buffer))
    return fields


def as_dictionary(value, name):
    """Convert a dictionary argument, preserving explicit null and key order.

    String input accepts a JSON object or the upstream key=value form with
    quoting, backslash escapes, and space or comma separators.

    :param value: JSON argument value to convert.
    :type value: object
    :param name: Parameter name used in validation errors.
    :type name: str
    :returns: The mapping, or None for an explicit null.
    :rtype: dict or None
    :raises ValueError: If the value cannot be converted or key=value input
        repeats a key with conflicting fields. Identical fields are deduplicated;
        JSON input retains the last value for a repeated key.
    """
    if value is None or isinstance(value, dict):
        return value
    if not isinstance(value, str):
        raise ValueError(name + " must be a dictionary or dictionary string.")
    if value.startswith("{") and value.endswith("}"):
        result = json.loads(value, object_pairs_hook=OrderedDict)
        if not isinstance(result, dict):
            raise ValueError(name + " JSON must contain a dictionary.")
        return result
    if "=" not in value:
        raise ValueError(
            "string cannot be converted to a dict, must either be a JSON string "
            "or in the key=value form"
        )
    result = OrderedDict()
    seen = set()
    for field in _dictionary_fields(value):
        if field in seen:
            continue
        seen.add(field)
        key, separator, text = field.partition("=")
        if key in result:
            raise ValueError("Duplicate variable name in dictionary string: " + key)
        result[key] = text if separator else None
    return result


def as_string_list(value, name):
    """Convert an optional list of strings with upstream argument coercions.

    String input is split on commas and trimmed. A signed 64-bit integer is
    accepted as one element; list elements use the ordinary string conversion.

    :param value: JSON argument value to convert.
    :type value: object
    :param name: Parameter name used in validation errors.
    :type name: str
    :returns: Converted strings, or None for an explicit null.
    :rtype: list or None
    :raises ValueError: If the value cannot be converted or contains null.
    :raises OSError: If numeric conversion cannot read Windows locale settings.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return [part.strip(DOTNET_WHITESPACE) for part in value.split(",")]
    if isinstance(value, int) and not isinstance(value, bool):
        if -(2**63) <= value < 2**63:
            return [as_string(value, name)]
    if not isinstance(value, list):
        raise ValueError("Expected a list for " + name + ".")
    if any(entry is None for entry in value):
        raise ValueError(name + " must not contain null entries.")
    return [as_string(entry, name) for entry in value]


def _number_text(value, name):
    if isinstance(value, int):
        # JSON integers beyond Int64 still become Decimal while they fit 96 bits.
        if abs(value) <= 79228162514264337593543950335:
            return str(value)
        try:
            value = float(value)
        except OverflowError as error:
            raise ValueError(
                "Number is outside the supported range for " + name + "."
            ) from error
    if not math.isfinite(value):
        raise ValueError("Expected a finite number for " + name + ".")

    # Ansible and Python 3.4 serialize finite floats using their shortest repr.
    # PowerShell's JSON reader treats dotted tokens as Decimal, exponent tokens
    # as Double. Recovering that notation preserves Decimal's trailing .0.
    token = repr(value)
    if "e" not in token:
        return token.lstrip("-") if value == 0 else token

    # Framework Double.ToString uses G15 with midpoint rounding away from zero.
    # Python's .15G uses ties-to-even, so round the exact binary value explicitly.
    with decimal.localcontext() as context:
        context.prec = 15
        context.rounding = decimal.ROUND_HALF_UP
        rounded = +decimal.Decimal.from_float(value)
    if -4 <= rounded.adjusted() < 15:
        text = format(rounded, "f")
        return text.rstrip("0").rstrip(".") if "." in text else text
    mantissa, exponent = format(rounded, "E").split("E")
    if "." in mantissa:
        mantissa = mantissa.rstrip("0").rstrip(".")
    return mantissa + "E" + format(int(exponent), "+03d")


def _number_symbols():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_info = kernel.GetLocaleInfoW
    get_info.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.c_int]
    get_info.restype = ctypes.c_int
    symbols = []
    # User-default decimal separator, positive sign, and negative sign. These
    # NLS fields include user overrides and are available on Windows XP.
    for field in (0xE, 0x50, 0x51):
        size = get_info(0x400, field, None, 0)
        if not size:
            raise ctypes.WinError()
        buffer = ctypes.create_unicode_buffer(size)
        if not get_info(0x400, field, buffer, size):
            raise ctypes.WinError()
        symbols.append(buffer.value)
    # .NET NumberFormatInfo replaces Windows' empty positive sign with '+'.
    return symbols[0], symbols[1] or "+", symbols[2]


def expand_environment(value):
    """Expand Windows percent-delimited environment variables once.

    :param value: Text to expand, or an explicit null.
    :type value: str or None
    :returns: Expanded text, leaving unknown variables and null unchanged.
    :rtype: str or None
    """
    if value is None:
        return None
    environment = {key.upper(): text for key, text in os.environ.items()}
    return re.sub(
        r"%([^%]+)%",
        lambda match: environment.get(match.group(1).upper(), match.group(0)),
        value,
    )


def as_path(value, name):
    """Convert and expand a Windows path argument.

    :param value: JSON value to convert.
    :type value: object
    :param name: Parameter name used in validation errors.
    :type name: str
    :returns: Expanded text, or None for an explicit null.
    :rtype: str or None
    :raises ValueError: If conversion fails or the path has invalid characters.
    :raises OSError: If numeric conversion cannot read Windows locale settings.
    """
    value = as_string(value, name)
    if value is None or value.startswith("\\\\?\\"):
        return value
    value = expand_environment(value)
    if any(ord(character) < 32 or character in '<>"|?*' for character in value):
        raise ValueError("Invalid Windows path characters in " + name + ".")
    return value


def read_arguments(supported_parameters, module_name, allow_unknown=False):
    """Read the flat argument file and validate parameter names.

    Known parameters and controller flags are matched case-insensitively.
    Modules apply defaults and value validation after this function returns.

    :param supported_parameters: Supported parameter names, including aliases.
    :type supported_parameters: iterable of str
    :param module_name: Fully qualified module name for validation errors.
    :type module_name: str
    :param allow_unknown: Preserve the permissive argument handling of modules
        whose upstream implementation uses the legacy PowerShell parser.
    :type allow_unknown: bool
    :returns: Arguments with known names normalized to lowercase.
    :rtype: dict
    :raises OSError: If the argument file cannot be read.
    :raises UnicodeError: If the argument file is not UTF-8.
    :raises ValueError: If arguments are malformed or contain unsupported names.
    """
    if len(sys.argv) != 2:
        raise ValueError("Expected one path to a JSON argument file.")
    with open(sys.argv[1], "r", encoding="utf-8-sig") as argument_file:
        arguments = json.load(
            argument_file,
            object_pairs_hook=OrderedDict,
            parse_constant=_invalid_constant,
        )
    if not isinstance(arguments, dict):
        raise ValueError("The argument file must contain a JSON object.")

    supported = set(supported_parameters)
    normalized = {}
    for name, value in arguments.items():
        lower_name = name.lower()
        if lower_name in supported or lower_name.startswith("_ansible_"):
            name = lower_name
        normalized[name] = value

    unsupported = sorted(
        name
        for name in normalized
        if name not in supported and not name.startswith("_ansible_")
    )
    ignore_unknown = allow_unknown or as_bool(
        normalized.get("_ansible_ignore_unknown_opts", False),
        "_ansible_ignore_unknown_opts",
    )
    if unsupported and not ignore_unknown:
        raise ValueError(
            "Unsupported parameters for ("
            + module_name
            + ") module: "
            + ", ".join(unsupported)
            + ". Supported parameters include: "
            + ", ".join(sorted(supported))
        )
    return normalized


def run_module(handler):
    """Execute a module and report its result through the JSON protocol.

    :param handler: No-argument function returning a JSON-serializable result.
    :type handler: callable
    :raises SystemExit: With status one for failure or zero for success.
    """
    try:
        result = handler()
    except (OSError, UnicodeError, ValueError) as error:
        result = {"changed": False, "failed": True, "msg": str(error)}
    # The target entry point must report unexpected failures as Ansible JSON.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result = {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + str(error),
            "exception": traceback.format_exc(),
        }

    # ASCII JSON escapes preserve Unicode under legacy console code pages.
    sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")
    sys.exit(1 if result.get("failed") else 0)
