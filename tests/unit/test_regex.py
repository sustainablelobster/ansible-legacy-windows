"""Exercise fixed category membership and UTF16 matching with stdlib re."""

# SPDX-License-Identifier: GPL-3.0-or-later

import builtins
import importlib.util
import re
from types import ModuleType
from typing import Any

import pytest

from tests.unit.payload_support import ROOT


@pytest.fixture(name="helper")
def regex_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target regex helper with its independently staged sibling data.

    :param monkeypatch: Restore the sibling-module search path after each test.
    :returns: The isolated regex helper.
    """
    source = ROOT / "legacy_windows/plugins/module_utils/legacy_windows_regex.py"
    monkeypatch.syspath_prepend(str(source.parent))
    spec = importlib.util.spec_from_file_location("tested_regex", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("text", "pattern", "expected"),
    [
        ("python.exe", r"^\p{L}+[.]exe$", True),
        ("1.exe", r"^\p{L}+[.]exe$", False),
        ("É", r"^\p{L}$", True),
        ("\u037f", r"^\p{Lu}$", True),
        ("\u08b3", r"^\p{Lo}$", True),
        ("\u20be", r"^\p{Sc}$", True),
        ("\u180e", r"^\p{Cf}$", True),
        ("\u0378", r"^\p{Cn}$", True),
        ("\u0345", r"^\p{L}$", False),
        ("\u0345", r"^\p{Lu}$", False),
        ("\u0345", r"^\p{Ll}$", False),
        ("\u0345", r"^\p{Lt}$", False),
        ("\u0345", r"^\p{Mn}$", True),
        ("\u0345", r"^\p{M}$", True),
        ("Ι", r"^\p{Mn}$", False),
        ("ι", r"^\p{Mn}$", False),
        ("ι", r"^\p{Mn}$", False),
        ("ι", r"^\p{Lm}$", False),
        ("ι", r"^\p{Lu}$", True),
        ("ι", r"^\P{Mn}$", True),
        ("\u0345", r"^\P{L}$", True),
        ("\u0345", r"^\P{M}$", False),
        ("\u0345\u0345", r"^\p{Mn}{2}$", True),
        ("\u0345ι", r"^\p{Mn}{2}$", False),
        ("a\u0345", r"^\p{L}{2}$", False),
        ("a\u0345", r"^[\p{L}\p{Mn}]{2}$", True),
        ("ι", r"^[\p{Mn}!]$", False),
        ("!", r"^[\p{Mn}!]$", True),
        ("\u0345", r"^[\p{Mn}!]$", True),
        ("ι", r"^[^\p{Mn}!]$", True),
        ("\u0345", r"^[^\p{Mn}!]$", False),
        ("ι", r"^[\P{Mn}]$", True),
        ("\u0345", r"^[\P{Mn}]$", False),
        ("-", r"^[\p{L}-a]$", True),
        ("a", r"^[\p{L}-a]$", True),
        ("b", r"^[a-c\p{Mn}]$", True),
        ("ι", r"^[a-c\p{Mn}]$", False),
        ("\u0345", r"^[a-c\p{Mn}]$", True),
        ("]", r"^[]\p{L}]$", True),
        ("1", r"^[\p{L}^_]$", False),
        ("_", r"^[\p{L}^_]$", True),
        ("^", r"^[\p{L}^_]$", True),
        ("a", r"^[\p{L}^_]$", True),
        ("1", r"^[^\p{L}^_]$", True),
        ("_", r"^[^\p{L}^_]$", False),
        ("^", r"^[^\p{L}^_]$", False),
        ("a", r"^[^\p{L}^_]$", False),
        ("\u0345b", r"(?<=\p{Mn})b", True),
        ("ιb", r"(?<=\p{Mn})b", False),
        ("😀", r"^\p{Cs}{2}$", True),
        ("😀", r"^\P{L}{2}$", True),
        ("😀", r"^\P{L}$", False),
        ("\U00010400", r"^\p{L}$", False),
        ("😀", r"^😀\p{L}?$", True),
        ("😀", r"^.$", False),
        ("😀", r"^..$", True),
        ("😀", r"^(?# \p{L}).$", False),
        ("😀", "(?x)^ # \\p{L}\n.$", False),
        ("😀", r"^😀$", True),
        ("😀😀", r"^(?<item>😀)\k<item>$", True),
        ("😀A", r"(?<=😀)A$", True),
        ("😀", r"^.{2}$", True),
        ("😀", r"^.{1}$", False),
        (r"\p{L}", r"^\\p\{L\}$", True),
    ],
)
def test_observable_category_and_noncategory_matching(
    helper: ModuleType, text: str, pattern: str, expected: bool
) -> None:
    assert helper.search(text, pattern) is expected


@pytest.mark.parametrize(
    ("text", "pattern", "sensitive", "expected"),
    [
        ("a", r"^\p{Lu}$", True, False),
        ("a", r"^\p{Lu}$", False, True),
        ("A", r"^\p{Ll}$", True, False),
        ("A", r"^\p{Ll}$", False, True),
        ("ǅ", r"^\p{Lt}$", True, True),
        ("a", r"^\p{Lt}$", True, False),
        ("a", r"(?i)^\p{Lu}$", True, True),
        ("\u0345", r"(?i)^\p{Lu}$", True, False),
        ("PYTHON.exe", r"^\p{L}+[.]exe$", True, True),
        ("PYTHON.EXE", r"^\p{L}+[.]exe$", True, False),
        ("PYTHON.EXE", r"^\p{L}+[.]exe$", False, True),
    ],
)
def test_category_casing_does_not_change_surrounding_literals(
    helper: ModuleType, text: str, pattern: str, sensitive: bool, expected: bool
) -> None:
    assert helper.search(text, pattern, case_sensitive=sensitive) is expected


@pytest.mark.parametrize(
    "pattern",
    [
        r"\pL",
        r"\p{L",
        r"\p{}",
        r"\p{l}",
        r"\p{LC}",
        r"\p{Bogus}",
        r"\p{IsBasicLatin}",
        r"[a-\p{L}]",
        r"(?a)\p{L}",
        r"(?L)\p{L}",
        r"(?a)\w",
        r"(?L)\d",
        r"(?a)\b",
        r"^\p{Lu}(?i)a$",
        r"^a(?i)\p{Lu}$",
        r"(?i)^\p{Lu}(?m)a$",
    ],
)
def test_invalid_or_unimplemented_category_forms_are_actionable(
    helper: ModuleType, pattern: str
) -> None:
    with pytest.raises(ValueError):
        helper.search("a", pattern)


def test_ordinary_expressions_do_not_import_category_data(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = builtins.__import__

    def _import(name: str, *arguments: Any, **keywords: Any) -> Any:
        if name.endswith("legacy_windows_regex_categories"):
            raise ImportError("Category facts were not staged for this consumer.")
        return original(name, *arguments, **keywords)

    monkeypatch.setattr(builtins, "__import__", _import)
    assert helper.search("python.exe", r"^python[.]exe$")
    assert helper.search("😀", r"^..$")
    with pytest.raises(ImportError, match="not staged"):
        helper.search("python.exe", r"^\p{L}+[.]exe$")


@pytest.mark.parametrize(
    "pattern",
    [r"^a(?i)a$", r"a(?s).", r"(foo(?i)bar)", r"(?i)^a(?m)b$"],
)
def test_positional_flags_fail_before_runtime_dependent_matching(
    helper: ModuleType, pattern: str
) -> None:
    with pytest.raises(ValueError, match="non-prefix inline options.*pattern prefix"):
        helper.search("AA", pattern, case_sensitive=True)


def test_leading_flags_and_literal_option_text_remain_supported(
    helper: ModuleType,
) -> None:
    assert helper.search("aA", r"(?i)^\p{Lu}a$", case_sensitive=True)
    assert helper.search("(?i)", r"^\(\?i\)$", case_sensitive=True)
    assert helper.search("x", r"(?x)^x$ # (?i) ignored comment", case_sensitive=True)


@pytest.mark.parametrize(
    ("text", "anchor", "expected"),
    [
        ("done", r"\Z", True),
        ("done\n", r"\Z", True),
        ("done\r\n", r"\Z", False),
        ("done\n\n", r"\Z", False),
        ("done\nmore", r"\Z", False),
        ("done", r"\z", True),
        ("done\n", r"\z", False),
        ("done\r\n", r"\z", False),
    ],
)
@pytest.mark.parametrize("options", ["", "(?m)", "(?s)", "(?x)"])
def test_terminal_newline_anchor_is_distinct_from_strict_end(
    helper: ModuleType, text: str, anchor: str, expected: bool, options: str
) -> None:
    assert helper.search(text, options + "done" + anchor) is expected


def test_terminal_anchor_keeps_cr_and_zero_width_semantics(helper: ModuleType) -> None:
    assert helper.search("done\r\n", r"done\r\Z")
    assert helper.search("done\n", r"done\Z\n\z")
    assert not helper.search("done\n", r"done\Z.\z")
    assert helper.search(r"done\Z", r"done\\Z\z")


def test_fixed_ranges_cover_every_bmp_code_unit_once(helper: ModuleType) -> None:
    data = importlib.import_module("legacy_windows_regex_categories")
    assert data.UNICODE_VERSION == "8.0.0"
    values: list[str | None] = [None] * 65536
    for name, ranges in data.CATEGORY_RANGES.items():
        for first, last in ranges:
            assert 0 <= first <= last <= 65535
            assert all(value is None for value in values[first : last + 1])
            values[first : last + 1] = [name] * (last - first + 1)
    assert len(data.CATEGORY_RANGES) == 30
    assert None not in values
    assert values[0x0345] == "Mn" and values[0x1FBE] == "Ll"
    assert helper.search("\ud800", r"^\p{Cs}$", case_sensitive=True)


@pytest.mark.parametrize(
    ("text", "pattern", "expected"),
    [
        ("a\u0301", r"^\w+$", True),
        ("a\u203f", r"^[\w]+$", True),
        ("\u08b3", r"^\w$", True),
        ("\u0de6", r"^\d$", True),
        ("\u0de6", r"^[\D]$", False),
        ("²", r"^\w$", False),
        ("Ⅳ", r"^\w$", False),
        ("²", r"^\W$", True),
        ("\u200c", r"^\w$", False),
        ("\u200d", r"^\W$", True),
        ("\u001c", r"^\s$", False),
        ("\u001c", r"^[\S]$", True),
        ("\u0085", r"^\s$", True),
        ("\u00a0", r"^\s$", True),
        ("\u2028", r"^\s$", True),
        ("a\u0301", r"^\ba\u0301\b$", True),
        ("a\u200c", r"^\ba\u200c\b$", True),
        ("a\u200d", r"^\ba\u200d\b$", True),
        ("a\u0301", r"^a\B", True),
        ("a\u0301", r"^a\b", False),
        ("²", r"^\b", False),
        ("²", r"^\B", True),
        ("", r"\b", False),
        ("", r"\B", True),
        ("\u0008", r"^[\b]$", True),
        ("w", r"^[\\w]$", True),
        (r"\w", r"^\\w$", True),
        ("😀", r"^\W{2}$", True),
        ("a_", r"^[\w^_]{2}$", True),
        ("^", r"^[^\w^_]$", False),
        ("1", r"^[a\d]$", True),
        ("a\u0301a\u0301", r"^(?<word>\w+)\k<word>$", True),
    ],
)
def test_shorthand_and_boundary_observable_matching(
    helper: ModuleType, text: str, pattern: str, expected: bool
) -> None:
    assert helper.search(text, pattern) is expected
    assert helper.search(text, pattern, case_sensitive=True) is expected


@pytest.mark.parametrize("kind", ["w", "W", "d", "D", "s", "S"])
def test_sensitive_shorthand_membership_matches_fixed_bmp_facts(
    helper: ModuleType, kind: str
) -> None:
    data = importlib.import_module("legacy_windows_regex_categories")
    categories = {
        # These codes name the fixed Unicode general-category facts.
        "w": {"Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Nd", "Pc"},  # codespell:ignore nd
        "d": {"Nd"},  # codespell:ignore nd
        "s": {"Zs", "Zl", "Zp"},
    }[kind.lower()]
    expected = {
        code
        for name, ranges in data.CATEGORY_RANGES.items()
        if name in categories
        for first, last in ranges
        for code in range(first, last + 1)
    }
    if kind.lower() == "s":
        expected.update(range(9, 14))
        expected.add(0x85)
    # Test the translated standard-re expression directly without a development
    # Unicode case-fold table standing in for the actual Python3.4 target.
    # pylint: disable-next=protected-access
    translated, _categories = helper._regex_expression("^\\" + kind + "$", False)
    expression = re.compile(translated)
    for code in range(65536):
        member = code in expected
        assert bool(expression.search(chr(code))) is (
            not member if kind.isupper() else member
        )
