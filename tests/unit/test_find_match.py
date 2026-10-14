"""Exercise observable filename matching and native culture call contracts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes and parser entry points are inspected without contacting hosts.
# pylint: disable=protected-access

import ctypes
import importlib.util
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT


@pytest.fixture(name="helper")
def matching_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper without invoking Windows APIs.

    :param monkeypatch: Fixture restoring the sibling-helper import path.
    :returns: The isolated helper module.
    """
    source = ROOT / "legacy_windows/plugins/module_utils/legacy_windows_find_match.py"
    monkeypatch.syspath_prepend(str(source.parent))
    spec = importlib.util.spec_from_file_location("tested_find_match", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(name="matcher")
def matching_culture(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Provide the observed en-US single-character casing for behavior tests.

    :param helper: The imported matching helper.
    :param monkeypatch: Fixture restoring the native boundary substitute.
    :returns: The helper with deterministic filename casing.
    """

    def _lower(character: str) -> str:
        return {"İ": "i", "ẞ": "ß", "K": "k"}.get(character, character.lower())

    monkeypatch.setattr(helper, "_current_lower", lambda: _lower)
    return helper


@pytest.mark.parametrize(
    ("name", "pattern", "expected"),
    [
        ("LOG.txt", "*.txt", True),
        ("x.log.bak", "*.log", False),
        ("log", "*.*", False),
        ("", "*", True),
        ("", "", True),
        ("a", "", False),
        (".hidden", "*", True),
        ("a\nb", "a?b", True),
        ("a\nb", "a*b", True),
        ("a\n", "a", False),
        ("[a].txt", "`[a`].txt", True),
        ("x`.txt", "x``.txt", True),
        ("x.txt", "x.txt`", False),
        ("x.txt`", "x.txt`", True),
        ("", "`", True),
        ("`", "`", False),
        ("a", "`a", True),
        ("a.txt", "[!a].txt", True),
        ("!.txt", "[!a].txt", True),
        ("b.txt", "[!a].txt", False),
        ("a.txt", "[^a].txt", True),
        ("^.txt", "[^a].txt", True),
        ("b.txt", "[^a].txt", False),
        ("].txt", "[]].txt", True),
        ("[.txt", "[[].txt", True),
        ("B", "[a-c]", True),
        ("b", "[A-C]", True),
        ("-", "[a`-c]", True),
        ("b", "[a`-c]", False),
        ("z", "[Z-a]", True),
        ("_", "[Z-a]", True),
        ("b", "[Z-a]", False),
        ("É", "[é]", True),
        ("İ", "i", True),
        ("ı", "i", False),
        ("😀.txt", "?.txt", False),
        ("😀.txt", "??.txt", True),
        ("😀.txt", "😀.txt", True),
        ("\ud800", "?", True),
    ],
)
def test_wildcard_matching(
    matcher: ModuleType, name: str, pattern: str, expected: bool
) -> None:
    assert matcher.matches(name, [pattern]) is expected


@pytest.mark.parametrize("pattern", ["[", "[]", "[z-a]", "[`]", "[abc`"])
def test_invalid_wildcard_is_actionable(matcher: ModuleType, pattern: str) -> None:
    with pytest.raises(ValueError, match="wildcard character pattern is not valid"):
        matcher.matches("name", [pattern])


def test_unicode_bracket_literals_and_singletons(matcher: ModuleType) -> None:
    assert matcher.matches("É", ["[éÉ]"])
    assert matcher.matches("É", ["[É-É]"])


@pytest.mark.parametrize(
    ("name", "pattern", "expected"),
    [
        ("RpcSs", "Rpc[A-Ž]s", True),
        ("RpcSs", "Rpc[a-ž]s", True),
        ("É", "[À-Ö]", True),
        ("÷", "[Ö-Ø]", True),
        ("÷", "[ÖØ]", False),
        ("÷", "[×-×]", False),
        ("×", "[×-×]", True),
        ("ÿ", "[ŷ-Ź]", True),
        ("þ", "[ŷ-Ź]", False),
        ("ǆ", "[Ǆ-ǅ]", True),
        ("ǉ", "[Ǆ-ǅ]", False),
        ("ā", "[Ā-Ă]", True),
        ("ă", "[ā-Ă]", True),
        ("ą", "[Ā-Ă]", False),
        ("ĺ", "[Ĺ-Ľ]", True),
        ("ľ", "[ĺ-Ľ]", True),
        ("ń", "[Ĺ-Ľ]", False),
        ("έ", "[Έ-Ή]", True),
        ("ή", "[Έ-Ή]", True),
        ("ί", "[Έ-Ή]", False),
        ("ἀ", "[Ἀ-Ἁ]", True),
        ("ἁ", "[Ἀ-Ἁ]", True),
        ("ἂ", "[Ἀ-Ἁ]", False),
        ("ა", "[Ⴀ-Ⴁ]", True),
        ("ⴀ", "[Ⴀ-Ⴁ]", False),
        ("Ⴀ", "[Ⴀ-Ⴁ]", False),
        ('"', "[!-$]", True),
        ("%", "[!-$]", False),
        ("\uff3b", "[\uff3b-\uff3d]", True),
        ("\uff3e", "[\uff3b-\uff3d]", False),
        ("\ud801", "[\ud800-\ud802]", True),
        ("\ud803", "[\ud800-\ud802]", False),
        ("ı", "[I-I]", False),
    ],
)
def test_unicode_ranges_preserve_framework_expansion(
    matcher: ModuleType, name: str, pattern: str, expected: bool
) -> None:
    assert matcher.matches(name, [pattern]) is expected


@pytest.mark.parametrize("pattern", ["[@-[]", "prefix[@-[]suffix"])
def test_range_ending_at_open_bracket_retains_upstream_failure(
    matcher: ModuleType, pattern: str
) -> None:
    with pytest.raises(ValueError) as failure:
        matcher.matches("A", [pattern])
    assert str(failure.value) == 'parsing "[@-[]" - Unterminated [] set.'


def test_wildcards_ignore_case_sensitive_option(matcher: ModuleType) -> None:
    assert matcher.matches("a.txt", ["*.TXT"], case_sensitive=True)


def test_repeated_stars_do_not_require_regex_backtracking(matcher: ModuleType) -> None:
    assert matcher.matches("a" * 180, ["*a" * 30 + "*"])
    assert not matcher.matches("a" * 180, ["*a" * 30 + "b"])


def test_turkish_literals_and_ascii_ranges(
    matcher: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _lower(character: str) -> str:
        return {"I": "ı", "İ": "i"}.get(character, character.lower())

    monkeypatch.setattr(matcher, "_current_lower", lambda: _lower)
    assert not matcher.matches("I", ["i"])
    assert matcher.matches("I", ["ı"])
    assert matcher.matches("I", ["[I]"])
    assert matcher.matches("I", ["[I-I]"])
    assert matcher.matches("ı", ["[I-I]"])
    assert not matcher.matches("ı", ["[I-J]"])
    assert not matcher.matches("I", ["[A-Z]"])
    assert matcher.matches("i", ["[A-Z]"])


@pytest.mark.parametrize("use_regex", [False, True])
def test_patterns_are_lazy_alternatives(matcher: ModuleType, use_regex: bool) -> None:
    assert matcher.matches("name", ["absent", "name", "["], use_regex=use_regex)
    assert not matcher.matches("name", [], use_regex=use_regex)
    assert matcher.matches("name", None, use_regex=use_regex)
    with pytest.raises(ValueError):
        matcher.matches("name", ["absent", "["], use_regex=use_regex)


def test_lazy_pattern_iterable(matcher: ModuleType) -> None:
    def _patterns() -> Any:
        yield "name"
        raise AssertionError("The successful alternative must stop iteration.")

    assert matcher.matches("name", _patterns())


@pytest.mark.parametrize(
    ("name", "pattern", "expected"),
    [
        ("before-log.txt-after", r"log\.txt", True),
        ("LOG.txt", r"^log\.txt$", True),
        ("log.txt", r"^log\.txt\z", True),
        ("log.txt\n", r"^log\.txt\z", False),
        ("aa.txt", r"^(?<letter>a)\k<letter>\.txt$", True),
        ("ab.txt", r"^(?<letter>a)\k<letter>\.txt$", False),
        ("aa", r"^(?'letter'a)\k'letter'$", True),
        ("aa", r"^(?P<letter>a)(?P=letter)$", True),
        ("aaa-b.txt", r"(?<=a-)b", True),
        ("aab", r"(a)\1b", True),
        ("a", r"(?#\p{L})a", True),
        ("a", "(?x)a # \\p{L}", True),
        ("a", "(?ix)a # \\p{L}\n", True),
        ("\\p{L}", r"\\p\{L\}", True),
        ("(?<x>a)", r"\(\?<x>a\)", True),
        ("p", r"[(?<x>a)p]", True),
        ("baa", r"[^]](?<x>a)\k<x>", True),
        ("baa", r"[^^](?<x>a)\k<x>", True),
        ("^aa", r"[^^](?<x>a)\k<x>", False),
        ("a", r"(?#\) \p{L})a", True),
        ("a}}", r"a}+", True),
        ("a\x01", r"(?<x>a)[\1]", True),
        ("😀", r"^.$", False),
        ("😀", r"^..$", True),
        ("a\u0301", r"^\w+$", True),
        ("ı", r"^i$", True),
    ],
)
def test_regex_boundary_and_translations(
    helper: ModuleType, name: str, pattern: str, expected: bool
) -> None:
    assert helper.matches(name, [pattern], use_regex=True) is expected


def test_regex_case_sensitive_option(helper: ModuleType) -> None:
    assert helper.matches("LOG.txt", [r"^log\.txt$"], use_regex=True)
    assert not helper.matches(
        "LOG.txt", [r"^log\.txt$"], use_regex=True, case_sensitive=True
    )


@pytest.mark.parametrize(
    ("pattern", "feature"),
    [
        (r"\p{IsBasicLatin}", "Unicode general category"),
        (r"\Gname", "escape"),
        (r"\e", "escape"),
        (r"\cA", "escape"),
        (r"(?<n>a)+(?<-n>b)", "balancing group"),
        (r"(?'n'a)+(?'result-n'b)", "balancing group"),
        (r"[a-z-[aeiou]]", "subtraction"),
        (r"(?<name>a)(b)\1", "numeric reference"),
        (r"(?<name>a)(?(1)b|c)", "numeric reference"),
        (r"(?<1>a)", "group name"),
        (r"(?<é>a)", "group name"),
        (r"(?>a+)", "atomic group"),
        (r"(?i:a)", "inline options"),
        (r"(?-i)a", "inline options"),
        (r"(?n)a", "inline options"),
        (r"a++", "possessive"),
        (r"a*+", "possessive"),
        (r"a?+", "possessive"),
        (r"a{1,2}+", "possessive"),
    ],
)
def test_unsupported_regex_fails_explicitly(
    helper: ModuleType, pattern: str, feature: str
) -> None:
    with pytest.raises(ValueError, match="Unsupported.*" + feature):
        helper.matches("anything", [pattern], use_regex=True)


@pytest.mark.parametrize(
    "pattern", [r"(?<=a+)b", "[", "(?<name", "(?#unfinished", r"\kname", r"\k<name"]
)
def test_invalid_regex_is_value_error(helper: ModuleType, pattern: str) -> None:
    with pytest.raises(ValueError):
        helper.matches("anything", [pattern], use_regex=True)


@pytest.fixture(name="native")
def native_culture(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace the native library and emulate buffer writes, not Windows rules.

    :param helper: The imported helper.
    :param monkeypatch: Fixture restoring native-call substitutes.
    :returns: A controllable kernel library substitute.
    """
    kernel = Mock()
    kernel.GetUserDefaultLCID.return_value = 1055
    kernel.CompareStringW.return_value = 2

    def _mapping(
        _locale: int, _flags: int, value: str, _length: int, buffer: Any, _size: int
    ) -> int:
        result = value.lower()
        if buffer is not None:
            buffer[: len(result)] = result
        return len(result)

    kernel.LCMapStringW.side_effect = _mapping
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 87, raising=False)
    monkeypatch.setattr(
        helper.ctypes,
        "WinError",
        lambda code: OSError(code, "native error"),
        raising=False,
    )
    return kernel


def test_path_key_uses_invariant_mapping(helper: ModuleType, native: Any) -> None:
    assert helper.path_key("C:\\ABC") == "c:\\abc"
    first, second = native.LCMapStringW.call_args_list
    assert first.args == (0x7F, 0x100, "C:\\ABC", 6, None, 0)
    assert second.args[:4] == (0x7F, 0x100, "C:\\ABC", 6)
    assert second.args[5] == 6


def test_empty_path_key_needs_no_mapping(helper: ModuleType, native: Any) -> None:
    assert helper.path_key("") == ""
    native.LCMapStringW.assert_not_called()


def test_current_lower_caches_units_and_preserves_surrogates(
    helper: ModuleType, native: Any
) -> None:
    lower = helper._current_lower()
    assert lower("A") == "a"
    assert lower("A") == "a"
    assert lower("\ud801") == "\ud801"
    assert lower("\udc00") == "\udc00"
    assert native.LCMapStringW.call_count == 2
    assert native.LCMapStringW.call_args_list[0].args == (
        1055,
        0x01000100,
        "A",
        1,
        None,
        0,
    )


@pytest.mark.parametrize("failure_at", [0, 1])
def test_mapping_failure_is_not_silently_retried(
    helper: ModuleType, native: Any, failure_at: int
) -> None:
    native.LCMapStringW.side_effect = [0] if failure_at == 0 else [2, 0]
    with pytest.raises(OSError) as error:
        helper.path_key("AB")
    assert error.value.errno == 87
    assert native.LCMapStringW.call_count == failure_at + 1


@pytest.mark.parametrize("native_result", [1, 2, 3])
def test_compare_paths_native_flags_and_utf16_lengths(
    helper: ModuleType, native: Any, native_result: int
) -> None:
    native.CompareStringW.return_value = native_result
    assert helper.compare_paths("😀A", "B") == native_result - 2
    native.CompareStringW.assert_called_once_with(1055, 0x08000001, "😀A", 3, "B", 1)


def test_comparison_failure_is_actionable(helper: ModuleType, native: Any) -> None:
    native.CompareStringW.return_value = 0
    with pytest.raises(OSError):
        helper.compare_paths("A", "B")
    assert native.CompareStringW.call_count == 1


def test_xp_comparison_retries_only_the_unavailable_flag(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 1004)
    native.CompareStringW.side_effect = [0, 3]
    assert helper.compare_paths("A", "B") == 1
    assert [call.args for call in native.CompareStringW.call_args_list] == [
        (1055, 0x08000001, "A", 1, "B", 1),
        (1055, 1, "A", 1, "B", 1),
    ]


def test_mapping_retries_unavailable_linguistic_flag(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 1004)
    mapping = native.LCMapStringW.side_effect

    def _legacy_mapping(*arguments: Any) -> int:
        if arguments[1] == 0x01000100:
            return 0
        return int(mapping(*arguments))

    native.LCMapStringW.side_effect = _legacy_mapping
    assert helper._current_lower()("A") == "a"
    assert [call.args[1] for call in native.LCMapStringW.call_args_list] == [
        0x01000100,
        0x100,
        0x100,
    ]


def test_invariant_mapping_does_not_retry_invalid_flags(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 1004)
    native.LCMapStringW.side_effect = [0]
    with pytest.raises(OSError):
        helper.path_key("A")
    assert native.LCMapStringW.call_count == 1


def test_failed_comparison_retry_still_raises(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 1004)
    native.CompareStringW.side_effect = [0, 0]
    with pytest.raises(OSError):
        helper.compare_paths("A", "B")
    assert native.CompareStringW.call_count == 2


@pytest.mark.parametrize(
    ("left", "right", "expected"), [("", "", 0), ("", "a", -1), ("a", "", 1)]
)
def test_empty_path_comparison(
    helper: ModuleType, left: str, right: str, expected: int
) -> None:
    assert helper.compare_paths(left, right) == expected


def test_kernel_bindings(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = Mock()
    loader = Mock(return_value=kernel)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    assert helper._kernel() is kernel
    loader.assert_called_once_with("kernel32", use_last_error=True)
    assert kernel.GetUserDefaultLCID.argtypes == []
    assert kernel.GetUserDefaultLCID.restype is ctypes.c_uint32
    assert kernel.LCMapStringW.argtypes[0] is ctypes.c_uint32
    assert kernel.LCMapStringW.argtypes[2] is ctypes.c_wchar_p
    assert kernel.CompareStringW.argtypes[3] is ctypes.c_int
    assert kernel.CompareStringW.restype is ctypes.c_int


def test_native_operations_require_windows(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="Windows target"):
        helper.path_key("C:\\file")
