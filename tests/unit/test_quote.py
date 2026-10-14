"""Check the public Windows quote filter without contacting a target."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy

import pytest

# Ansible's public exception does not ship typing metadata.
from ansible.errors import AnsibleFilterError  # type: ignore[import-untyped]

# Pytest resolves the checkout's source-only plugin namespace.
from ansible_collections.sustainablelobster.legacy_windows.plugins.filter.quote import (  # pylint: disable=import-error
    FilterModule,
    quote,
)

_SHELLS = (None, "cmd", "powershell")


def test_filter_registration_exposes_the_public_function() -> None:
    assert FilterModule().filters() == {"quote": quote}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain", "plain"),
        ("two words", '"two words"'),
        ("C:\\no-space\\", "C:\\no-space\\"),
        ("C:\\two words\\", '"C:\\two words\\\\"'),
        ('say "yes"', '"say \\"yes\\""'),
        ("'single'", "'single'"),
        ("^()%!<>&|", "^()%!<>&|"),
        ("雪-Café-🚀", "雪-Café-🚀"),
        ("a\0b", "a\0b"),
    ],
)
def test_default_uses_c_runtime_argument_rules(value: str, expected: str) -> None:
    assert quote(value) == expected


@pytest.mark.parametrize("count", [0, 1, 2, 3, 7, 16])
def test_c_runtime_preserves_backslash_runs_before_quotes(count: int) -> None:
    value = "left" + "\\" * count + '"right'
    expected = '"left' + "\\" * (2 * count + 1) + '"right"'
    assert quote(value) == expected


@pytest.mark.parametrize("count", [0, 1, 2, 3, 7, 16])
def test_c_runtime_doubles_only_quoted_trailing_backslashes(count: int) -> None:
    assert quote("two words" + "\\" * count) == (
        '"two words' + "\\" * (2 * count) + '"'
    )
    assert quote("one" + "\\" * count) == "one" + "\\" * count


@pytest.mark.parametrize("count", [1, 2, 7])
@pytest.mark.parametrize(
    ("suffix", "multiplier"),
    [("\n", 2), ("\r\n", 1), ("\n\n", 1), ("\nmore", 1), ("\u2028", 1)],
)
def test_c_runtime_preserves_the_baseline_final_newline_quirk(
    count: int, suffix: str, multiplier: int
) -> None:
    # The baseline doubles runs before a final LF as well as at string end.
    value = "two words" + "\\" * count + suffix
    expected = '"two words' + "\\" * (count * multiplier) + suffix + '"'
    assert quote(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain", "plain"),
        ("two words", '^"two words^"'),
        ("C:\\two words\\", '^"C:\\two words\\^"'),
        ('\\"', '^"' + "\\\\" + '^"^"'),
        ("'single'", "'single'"),
        ("雪-Café-🚀", "雪-Café-🚀"),
        ("a\0b", "a\0b"),
        ("^", '^"^^^"'),
        ("(", '^"^(^"'),
        (")", '^"^)^"'),
        ("%", '^"^%^"'),
        ("!", '^"^!^"'),
        ('"', '^"\\^"^"'),
        ("<", '^"^<^"'),
        (">", '^"^>^"'),
        ("&", '^"^&^"'),
        ("|", '^"^|^"'),
        ('^()%!"<>&|', '^"^^^(^)^%^!\\^"^<^>^&^|^"'),
        ("before^&after", '^"before^^^&after^"'),
        ("%PATH%", '^"^%PATH^%^"'),
        ("!delayed!", '^"^!delayed^!^"'),
    ],
)
def test_cmd_quotes_and_escapes_shell_metacharacters(value: str, expected: str) -> None:
    assert quote(value, shell="cmd") == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain", "'plain'"),
        ("two words", "'two words'"),
        ("can't", "'can''t'"),
        ("‘left’", "'‘‘left’’'"),
        ("‚low‛reverse", "'‚‚low‛‛reverse'"),
        ("'‘’‚‛", "'''‘‘’’‚‚‛‛'"),
        ('$env:PATH; `"x" & (whoami)', "'$env:PATH; `\"x\" & (whoami)'"),
        ("C:\\two words\\", "'C:\\two words\\'"),
        ("雪-Café-🚀", "'雪-Café-🚀'"),
        ("a\0b", "'a\0b'"),
    ],
)
def test_powershell_always_uses_literal_single_quoted_strings(
    value: str, expected: str
) -> None:
    assert quote(value, shell="powershell") == expected


@pytest.mark.parametrize("shell", _SHELLS)
@pytest.mark.parametrize(
    "space", [" ", "\t", "\r", "\n", "\v", "\f", "\u0085", "\u00a0", "\u2028"]
)
def test_ascii_and_unicode_whitespace_require_quoting(
    shell: str | None, space: str
) -> None:
    delimiters = {None: ('"', '"'), "cmd": ('^"', '^"'), "powershell": ("'", "'")}
    opening, closing = delimiters[shell]
    assert quote("left" + space + "right", shell) == (
        opening + "left" + space + "right" + closing
    )


@pytest.mark.parametrize("shell", _SHELLS)
@pytest.mark.parametrize("value", [None, False, 0, 0.0, 0j, "", b"", set()])
def test_falsy_scalar_inputs_produce_an_empty_argument(
    shell: str | None, value: object
) -> None:
    assert quote(value, shell) == ("''" if shell == "powershell" else '""')


@pytest.mark.parametrize("shell", _SHELLS)
@pytest.mark.parametrize("value", [[], (), {}, range(0), bytearray()])
def test_empty_argument_collections_produce_no_arguments(
    shell: str | None, value: object
) -> None:
    assert quote(value, shell) == ""


@pytest.mark.parametrize("shell", [None, "", False, 0, 0.0, [], {}])
def test_every_falsy_shell_selector_uses_c_runtime_quoting(shell: object) -> None:
    assert quote('two "words"', shell) == '"two \\"words\\""'


@pytest.mark.parametrize(
    "shell", ["CMD", "PowerShell", "sh", "none", True, 1, ["cmd"], {"cmd": True}]
)
def test_unknown_shells_raise_the_public_filter_error(shell: object) -> None:
    with pytest.raises(AnsibleFilterError) as error:
        quote("value", shell)
    assert str(error.value) == (
        "Invalid shell specified, valid shell are None, 'cmd', or 'powershell'"
    )


@pytest.mark.parametrize(
    ("shell", "expected"),
    [
        (None, 'first "two words" INSTALLDIR="C:\\Program Files\\App" EMPTY="" last'),
        (
            "cmd",
            'first ^"two words^" INSTALLDIR=^"C:\\Program Files\\App^" EMPTY="" last',
        ),
        (
            "powershell",
            "'first' 'two words' INSTALLDIR='C:\\Program Files\\App' EMPTY='' 'last'",
        ),
    ],
)
def test_mixed_sequences_preserve_argument_and_msi_property_order(
    shell: str | None, expected: str
) -> None:
    value = [
        "first",
        "two words",
        {"INSTALLDIR": "C:\\Program Files\\App", "EMPTY": None},
        "last",
    ]
    original = copy.deepcopy(value)
    assert quote(value, shell) == expected
    assert quote(tuple(value), shell) == expected
    assert quote(value, shell) == expected
    assert value == original


@pytest.mark.parametrize(
    ("shell", "expected"),
    [
        (None, '42="x y" None=plain with space=""'),
        ("cmd", '42=^"x y^" None=plain with space=""'),
        ("powershell", "42='x y' None='plain' with space=''"),
    ],
)
def test_msi_keys_are_converted_to_text_but_are_not_quoted(
    shell: str | None, expected: str
) -> None:
    assert quote({42: "x y", None: "plain", "with space": None}, shell) == expected


@pytest.mark.parametrize("shell", _SHELLS)
def test_empty_nested_dictionary_adds_no_argument(shell: str | None) -> None:
    empty_argument = "''" if shell == "powershell" else '""'
    assert quote([[], {}, (), None], shell) == " ".join([empty_argument] * 3)


@pytest.mark.parametrize("shell", _SHELLS)
@pytest.mark.parametrize(
    "value",
    [True, 1, -1, 1.5, 1j, [["nested"]], {"KEY": ["nested"]}, bytearray(b"x")],
)
def test_truthy_non_text_values_are_not_silently_stringified(
    shell: str | None, value: object
) -> None:
    with pytest.raises(TypeError, match="expected string or bytes-like object"):
        quote(value, shell)


@pytest.mark.parametrize("shell", _SHELLS)
def test_utf8_bytes_and_undecodable_bytes_use_ansible_text_conversion(
    shell: str | None,
) -> None:
    assert quote("Café 雪".encode(), shell) == quote("Café 雪", shell)
    assert quote(b"name-\xff", shell) == quote("name-\udcff", shell)
    assert quote({b"KEY-\xff": b"value-\xff"}, shell) == (
        "KEY-\udcff=" + quote("value-\udcff", shell)
    )
