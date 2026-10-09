"""Check path edits and registry boundaries without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

from types import ModuleType, SimpleNamespace
from unittest.mock import ANY, MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="helper")
def path_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper with deterministic ASCII comparison.

    :param monkeypatch: Scoped import and native substitutions.
    :returns: Imported path helper.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(HELPER.parent / "legacy_windows_path.py", "tested_path_native")
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right, invariant=True: left.lower() == right.lower(),
    )
    return module


@pytest.fixture(name="native")
def registry_substitute(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Replace native registry calls with observable handles and operations.

    :param helper: Imported path helper.
    :param monkeypatch: Scoped native substitutions.
    :returns: Mock registry and raw value reader.
    """
    native = Mock()
    native.winreg = MagicMock()
    native.winreg.HKEY_CURRENT_USER = 0x80000001
    native.winreg.HKEY_LOCAL_MACHINE = 0x80000002
    native.winreg.KEY_READ = 0x20019
    native.winreg.KEY_WRITE = 0x20006
    native.winreg.REG_EXPAND_SZ = 2
    native.reader.read_value.return_value = ("%RAW%;C:\\old", 2)
    monkeypatch.setattr(helper, "winreg", native.winreg)
    monkeypatch.setattr(helper, "registry", native.reader)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    return native


@pytest.mark.parametrize(
    ("scope", "root", "path"),
    [
        ("user", 0x80000001, "Environment"),
        (
            "machine",
            0x80000002,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
    ],
)
def test_read_opens_readonly_and_closes_without_expanding(
    helper: ModuleType, native: Mock, scope: str, root: int, path: str
) -> None:
    assert helper.read_value("Fixture", scope) == "%RAW%;C:\\old"
    native.winreg.OpenKey.assert_called_once_with(root, path, 0, 0x20019)
    key = native.winreg.OpenKey.return_value.__enter__.return_value
    native.reader.read_value.assert_called_once_with(key, "Fixture")
    native.winreg.OpenKey.return_value.__exit__.assert_called_once()
    native.winreg.QueryValueEx.assert_not_called()


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("", 1),
        (-2147483648, 4),
        (-9223372036854775808, 11),
        ([1, 255], 3),
        (["a", "b"], 7),
    ],
)
def test_read_retains_raw_native_type(
    helper: ModuleType, native: Mock, value: object, kind: int
) -> None:
    native.reader.read_value.return_value = (value, kind)
    assert helper.read_value("Fixture", "user") is value


def test_missing_or_unsupported_value_is_empty(
    helper: ModuleType, native: Mock
) -> None:
    native.reader.read_value.return_value = (None, None)
    assert helper.read_value("Fixture", "user") == ""


@pytest.mark.parametrize("name", [None, "", "(default)", "(DEFAULT)"])
def test_read_passes_default_and_alias_names_to_raw_reader(
    helper: ModuleType, native: Mock, name: str | None
) -> None:
    helper.read_value(name, "user")
    key = native.winreg.OpenKey.return_value.__enter__.return_value
    native.reader.read_value.assert_called_once_with(key, name)


@pytest.mark.parametrize("name", [None, ""])
def test_write_rejects_null_and_empty_names_before_open(
    helper: ModuleType, native: Mock, name: str | None
) -> None:
    with pytest.raises(ValueError, match="Cannot bind argument to parameter 'Name'"):
        helper.set_value(name, "new", "user")
    native.winreg.OpenKey.assert_not_called()
    native.winreg.SetValueEx.assert_not_called()


@pytest.mark.parametrize("name", ["(default)", "(DEFAULT)", "(de\u00adfault)"])
def test_write_uses_current_culture_comparison_for_provider_default_alias(
    helper: ModuleType, native: Mock, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    compare = Mock(return_value=True)
    monkeypatch.setattr(helper.environment, "values_equal", compare)
    helper.set_value(name, "new", "user")
    compare.assert_called_once_with(name, "(default)", invariant=False)
    key = native.winreg.OpenKey.return_value.__enter__.return_value
    native.winreg.SetValueEx.assert_called_once_with(key, "", 0, 2, "new")


def test_write_comparison_failure_closes_handle_without_writing(
    helper: ModuleType, native: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    compare = Mock(side_effect=OSError(87, "comparison failed"))
    monkeypatch.setattr(helper.environment, "values_equal", compare)
    with pytest.raises(OSError, match="comparison failed"):
        helper.set_value("Fixture", "new", "user")
    native.winreg.OpenKey.return_value.__exit__.assert_called_once()
    native.winreg.SetValueEx.assert_not_called()


@pytest.mark.parametrize("scope", ["user", "machine"])
@pytest.mark.parametrize("value", ["", "%RAW%;C:\\new", "雪"])
def test_write_uses_expandable_string_and_does_not_delete_or_notify(
    helper: ModuleType,
    native: Mock,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    value: str,
) -> None:
    broadcast = Mock()
    monkeypatch.setattr(helper.environment, "broadcast_change", broadcast)
    helper.set_value("Fixture", value, scope)
    assert native.winreg.OpenKey.call_args.args[3] == 0x2001F
    key = native.winreg.OpenKey.return_value.__enter__.return_value
    native.winreg.SetValueEx.assert_called_once_with(key, "Fixture", 0, 2, value)
    native.winreg.OpenKey.return_value.__exit__.assert_called_once()
    native.winreg.CreateKeyEx.assert_not_called()
    native.winreg.DeleteValue.assert_not_called()
    broadcast.assert_not_called()


@pytest.mark.parametrize("operation", ["read", "write"])
@pytest.mark.parametrize("code", [2, 3, 5])
def test_missing_or_denied_parent_key_fails_without_creating_it(
    helper: ModuleType, native: Mock, operation: str, code: int
) -> None:
    failure = OSError(code, "registry opening failed")
    native.winreg.OpenKey.side_effect = failure
    with pytest.raises(OSError) as caught:
        if operation == "read":
            helper.read_value("Fixture", "user")
        else:
            helper.set_value("Fixture", "new", "user")
    assert caught.value is failure
    native.winreg.CreateKeyEx.assert_not_called()
    native.reader.read_value.assert_not_called()
    native.winreg.SetValueEx.assert_not_called()


@pytest.mark.parametrize("operation", ["read", "write"])
def test_operation_failure_closes_open_handle(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    failure = OSError(5, "registry operation failed")
    if operation == "read":
        native.reader.read_value.side_effect = failure
    else:
        native.winreg.SetValueEx.side_effect = failure
    with pytest.raises(OSError) as caught:
        if operation == "read":
            helper.read_value("Fixture", "machine")
        else:
            helper.set_value("Fixture", "new", "machine")
    assert caught.value is failure
    native.winreg.OpenKey.return_value.__exit__.assert_called_once_with(
        OSError, failure, ANY
    )


@pytest.mark.parametrize("operation", ["read", "write"])
@pytest.mark.parametrize("scope", ["process", None, ""])
def test_invalid_scope_fails_before_open(
    helper: ModuleType, native: Mock, operation: str, scope: str | None
) -> None:
    with pytest.raises(ValueError, match="scope"):
        if operation == "read":
            helper.read_value("Fixture", scope)
        else:
            helper.set_value("Fixture", "new", scope)
    native.winreg.OpenKey.assert_not_called()


@pytest.mark.parametrize("operation", ["read", "write"])
def test_native_operations_reject_non_windows(
    helper: ModuleType, operation: str
) -> None:
    with pytest.raises(ValueError, match="Windows"):
        if operation == "read":
            helper.read_value("Fixture", "user")
        else:
            helper.set_value("Fixture", "new", "user")


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        ("", ""),
        (";;;", ""),
        (";a;;b;", "a;b"),
        ('a;"b;c";d', 'a;"b;c";d'),
        ('a; \t"b;c"\n ;d', 'a; \t"b;c"\n ;d'),
        ('"";a', '"";a'),
        ('"unterminated;a', '"unterminated;a'),
        ('a;"b"suffix;c', 'a;"b"suffix;c'),
        ("a; ;b", "a; ;b"),
    ],
)
def test_parser_returns_normalized_segments_without_claiming_change(
    helper: ModuleType, current: str, expected: str
) -> None:
    assert helper.edit_value(current, [], "present") == {
        "changed": False,
        "path_value": expected,
    }


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        ([65], "65;A"),
        ([65, 66], "65 66;A"),
        (["X;Y"], "X;Y;A"),
        (["X;Y", "Z"], "X;Y Z;A"),
        (["X", "", "Y"], "X  Y;A"),
        ([""], "A"),
        (-1, "-1;A"),
        (-2147483648, "-2147483648;A"),
        (-9223372036854775808, "-9223372036854775808;A"),
        (0, "0;A"),
    ],
)
def test_raw_registry_values_coerce_like_reference_pipeline_output(
    helper: ModuleType, current: object, expected: str
) -> None:
    assert helper.edit_value(current, ["A"], "present") == {
        "changed": True,
        "path_value": expected,
    }


@pytest.mark.parametrize("current", [[], None])
@pytest.mark.parametrize("state", ["present", "absent", None])
def test_empty_registry_arrays_fail_before_editing_even_without_requests(
    helper: ModuleType, current: object, state: str | None
) -> None:
    with pytest.raises(ValueError, match="null or an empty registry array"):
        helper.edit_value(current, [], state)


@pytest.mark.parametrize(
    "space", list("\t\n\v\f\r \x85\xa0\u1680\u2000\u2028\u2029\u202f\u205f\u3000")
)
def test_parser_uses_dotnet_whitespace_around_quoted_semicolons(
    helper: ModuleType, space: str
) -> None:
    element = space + '"a;b"' + space
    assert helper.edit_value(element + ";tail", [element], "absent") == {
        "changed": True,
        "path_value": "tail",
        "removed_idx": 0,
    }


@pytest.mark.parametrize("space", ["\x1c", "\x1d", "\x1e", "\x1f"])
def test_python_only_whitespace_does_not_enable_quoted_semicolon_parsing(
    helper: ModuleType, space: str
) -> None:
    current = space + '"a;b"'
    assert helper.edit_value(current, [space + '"a'], "absent") == {
        "changed": True,
        "path_value": 'b"',
        "removed_idx": 0,
    }


@pytest.mark.parametrize(
    ("current", "elements", "expected", "changed"),
    [
        ("", ["a", "b"], "a;b", True),
        ("untouched;a;b;tail", ["a", "b"], "untouched;a;b;tail", False),
        ("a;b;c", ["c", "a"], "b;c;a", True),
        ("a;b;c", ["new", "b", "a"], "c;new;b;a", True),
        ("A;b;c", ["c", "a"], "b;c;a", True),
        ("a;b;a;c", ["c", "a"], "b;a;c;a", True),
        ("a;a;b", ["a", "a"], "a;a;b", False),
        ("a;b;a", ["b", "a", "a"], "b;a;a", True),
        ("a;a", ["new", "a", "a"], "new;a;a", True),
        ("a;a;b", ["b", "a", "a"], "b;a;a", True),
        ("a;a", ["a", "a", "a"], "a;a", False),
        ("a;b", ["a;b"], "a;b;a;b", True),
        ("", [""], "", True),
        ("a", ["", "a"], ";a", True),
    ],
)
def test_present_preserves_order_and_moves_only_first_matching_occurrence(
    helper: ModuleType, current: str, elements: list[str], expected: str, changed: bool
) -> None:
    assert helper.edit_value(current, elements, "present") == {
        "changed": changed,
        "path_value": expected,
    }


@pytest.mark.parametrize(
    ("current", "elements", "expected"),
    [
        ("a;b;c", ["b"], {"path_value": "a;c", "changed": True, "removed_idx": 1}),
        ("a;a;b", ["a"], {"path_value": "a;b", "changed": True, "removed_idx": 0}),
        ("a;a;b", ["a", "a"], {"path_value": "b", "changed": True, "removed_idx": 0}),
        (
            "a;b",
            ["b", "missing"],
            {"path_value": "a", "changed": True, "removed_idx": -1},
        ),
        (
            "a;b",
            ["missing"],
            {"path_value": "a;b", "changed": False, "removed_idx": -1},
        ),
        ("a;b", ["a", "b"], {"path_value": "", "changed": True, "removed_idx": 0}),
        (";;", [""], {"path_value": "", "changed": False, "removed_idx": -1}),
    ],
)
def test_absent_reports_last_lookup_and_removes_only_requested_occurrences(
    helper: ModuleType,
    current: str,
    elements: list[str],
    expected: dict[str, object],
) -> None:
    assert helper.edit_value(current, elements, "absent") == expected


@pytest.mark.parametrize("elements", [[], None])
@pytest.mark.parametrize("state", ["present", "absent", None])
def test_no_elements_does_not_add_removed_index(
    helper: ModuleType, elements: list[str] | None, state: str | None
) -> None:
    assert helper.edit_value(";a;;b;", elements, state) == {
        "changed": False,
        "path_value": "a;b",
    }


def test_null_state_does_not_apply_elements(helper: ModuleType) -> None:
    assert helper.edit_value(";a;;b;", ["new"], None) == {
        "changed": False,
        "path_value": "a;b",
    }


@pytest.mark.parametrize(
    ("current", "requested", "matches"),
    [
        (r"C:\AbC", r"c:\abc", True),
        ('"C:\\AbC\\"', r"c:\abc", True),
        (r"\\C:\AbC\\", r"c:\abc", True),
        ('""C:\\AbC""', r"c:\abc", True),
        ('\\"C:\\AbC"\\', r"c:\abc", False),
        (" a ", "a", False),
        ("a/", "a", False),
        ("a\\b", "a/b", False),
    ],
)
def test_matching_trims_quotes_then_backslashes_but_not_spaces_or_slashes(
    helper: ModuleType, current: str, requested: str, matches: bool
) -> None:
    result = helper.edit_value(current, [requested], "present")
    assert result == {
        "changed": not matches,
        "path_value": current if matches else current + ";" + requested,
    }


def test_matching_delegates_to_shared_invariant_comparison(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    compare = Mock(return_value=True)
    monkeypatch.setattr(helper.environment, "values_equal", compare)
    assert helper.edit_value('"I\\"', ['"ı"'], "present") == {
        "changed": False,
        "path_value": '"I\\"',
    }
    compare.assert_called_once_with("I", "ı")


def test_native_comparison_failure_is_not_reported_as_no_match(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    compare = Mock(side_effect=OSError(87, "comparison failed"))
    monkeypatch.setattr(helper.environment, "values_equal", compare)
    with pytest.raises(OSError, match="comparison failed"):
        helper.edit_value("a", ["b"], "present")
