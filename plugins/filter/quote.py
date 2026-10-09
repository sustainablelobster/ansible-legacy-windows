"""Format literal arguments for Windows command lines and shell expressions."""

# SPDX-License-Identifier: GPL-3.0-or-later

import re
from collections.abc import Callable, Sequence
from typing import cast

# Ansible's filter and conversion interfaces do not ship typing metadata.
from ansible.errors import AnsibleFilterError  # type: ignore[import-untyped]
from ansible.module_utils.common.collections import (  # type: ignore[import-untyped]
    is_sequence,
)
from ansible.module_utils.common.text.converters import (  # type: ignore[import-untyped]
    to_text,
)
from ansible.plugins.shell import cmd  # type: ignore[import-untyped]

_C_NEEDS_QUOTES = re.compile(r'\s|"')
_POWERSHELL_QUOTES = re.compile("['\u2018\u2019\u201a\u201b]")
_CMD_QUOTER = cmd.ShellModule()


def _quote_c(value: str) -> str:
    if not value:
        return '""'
    if not _C_NEEDS_QUOTES.search(value):
        return value

    result = ['"']
    backslashes = 0
    for index, character in enumerate(value):
        if character == "\\":
            backslashes += 1
            continue
        if character == '"':
            count = 2 * backslashes + 1
        elif character == "\n" and index == len(value) - 1:
            # The baseline also treats the position before a final LF as an end.
            count = 2 * backslashes
        else:
            count = backslashes
        result.append("\\" * count)
        result.append(character)
        backslashes = 0
    result.append("\\" * (2 * backslashes))
    result.append('"')
    return "".join(result)


def _quote_powershell(value: str) -> str:
    if not value:
        return "''"
    return "'" + _POWERSHELL_QUOTES.sub(lambda match: match[0] * 2, value) + "'"


def quote(value: object, shell: object = None) -> str:
    """Quote arguments using the selected Windows command-language rules.

    Sequences supply separate arguments. Dictionaries supply MSI property
    assignments, quoting each value while leaving its property name unquoted.
    Byte strings are decoded by Ansible's text converter. Other input values
    are passed through to the selected quoting operation, as in the baseline.

    :param value: One argument, a sequence of arguments, or MSI properties.
    :param shell: ``cmd``, ``powershell``, or a falsy value for C-runtime quoting.
    :returns: The formatted arguments joined with single spaces.
    :raises AnsibleTemplatePluginError: Raised through AnsibleFilterError if a
        truthy shell value is not recognized.
    :raises TypeError: If an argument contains an unsupported non-string value.
    """
    quote_argument: Callable[[str], str]
    if not shell:
        quote_argument = _quote_c
    elif shell == "cmd":
        quote_argument = _CMD_QUOTER.quote
    elif shell == "powershell":
        quote_argument = _quote_powershell
    else:
        raise AnsibleFilterError(
            "Invalid shell specified, valid shell are None, 'cmd', or 'powershell'"
        )

    arguments = cast(Sequence[object], value) if is_sequence(value) else (value,)
    result: list[str] = []
    for argument in arguments:
        if isinstance(argument, dict):
            for name, item in argument.items():
                property_name = to_text(name, errors="surrogate_or_strict")
                property_value = to_text(
                    item, errors="surrogate_or_strict", nonstring="passthru"
                )
                result.append(f"{property_name}={quote_argument(property_value)}")
        else:
            text = to_text(argument, errors="surrogate_or_strict", nonstring="passthru")
            result.append(quote_argument(text))
    return " ".join(result)


# Ansible's filter plugin interface requires only the filters registration method.
class FilterModule:  # pylint: disable=too-few-public-methods
    """Expose the collection's Windows quoting filter to Ansible."""

    def filters(self) -> dict[str, Callable[[object, object], str]]:
        """Register the public filter name.

        :returns: The filter implementation indexed by its Ansible name.
        """
        return {"quote": quote}
