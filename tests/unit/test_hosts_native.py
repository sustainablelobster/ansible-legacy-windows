"""Check hosts text editing, observed IP spellings, and file I/O boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Private helper access makes target I/O replaceable without touching Windows.
# pylint: disable=protected-access

import codecs
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def hosts_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the hosts helper with ASCII comparison on the developer platform.

    :param monkeypatch: Scoped import path and native equality replacement.
    :returns: Real text editor with only Windows comparison substituted.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    module = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_hosts.py",
        "tested_hosts_native",
    )
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: (
            left == right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    return module


@pytest.mark.parametrize(
    "supplied, expected",
    [
        ("127.1", (4, "127.0.0.1")),
        ("2130706433", (4, "127.0.0.1")),
        ("0177.0.0.1", (4, "127.0.0.1")),
        ("0x7f.0.0.1", (4, "127.0.0.1")),
        ("192.0.2.010", (4, "192.0.2.8")),
        ("00", (4, "0.0.0.0")),
        ("1.2.65535", (4, "1.2.255.255")),
        ("[::1]", (6, "::1")),
        ("[::1]:80", (6, "::1")),
        ("fe80::1%12", (6, "fe80::1%12")),
        ("fe80::1%0", (6, "fe80::1")),
        ("::ffff:192.0.2.1", (6, "::ffff:192.0.2.1")),
        ("::ffff:c000:201", (6, "::ffff:192.0.2.1")),
        ("::192.0.2.1", (6, "::192.0.2.1")),
        ("::1:2", (6, "::0.1.0.2")),
        ("::2", (6, "::2")),
        ("::0:2", (6, "::2")),
        ("2001:0DB8:0:0:0:0:0:1", (6, "2001:db8::1")),
        (" 127.0.0.1 ", None),
        ("127.0.0.1 ", None),
        ("127.0.0.1 ignored", None),
        ("127.0.0.1\nignored", None),
        ("127.0.0.1\tignored", None),
        ("127.1 ignored", None),
        ("127.0.0.1junk", None),
        ("127.0.0.1/8", None),
        ("[::1]:65536", None),
        ("[::1]:nope", None),
        ("fe80::1%4294967296", None),
        ("fe80::1%eth0", None),
        ("09", None),
        ("1.2.65536", None),
        ("", None),
        ("127.0.0.1\0ignored", None),
    ],
)
def test_ip_literals_match_recorded_reference(
    helper: ModuleType, supplied: str, expected: tuple[int, str] | None
) -> None:
    assert helper.parse_address(supplied) == expected


@pytest.mark.parametrize("scope", [2147483648, 4294967295])
def test_scope_conversion_preserves_observed_parser_failure(
    helper: ModuleType, scope: int
) -> None:
    with pytest.raises(ValueError) as raised:
        helper.parse_address(f"fe80::1%{scope}")
    assert str(raised.value) == (
        "Unhandled exception while executing module: Exception calling "
        '"TryParse" with "2" argument(s): "Specified argument was out of '
        'the range of valid values.\r\nParameter name: scopeid"'
    )


def _edit(
    helper: ModuleType, lines: list[str], **parameters: object
) -> tuple[list[str], bool]:
    options = {
        "state": "present",
        "canonical_name": "host.invalid",
        "ip_address": "192.0.2.1",
        "aliases": None,
        "action": "set",
        **parameters,
    }
    result: tuple[list[str], bool] = helper.edit_lines(lines, options)
    return result


def test_global_removal_preserves_unrecognized_text(helper: ModuleType) -> None:
    preserved = [" # comment", "", "unrecognized-fixture-line", "192.0.2.1"]
    initial = preserved + ["192.0.2.1 host.invalid", "::1 other.invalid"]
    assert _edit(
        helper, initial, state="absent", canonical_name=None, ip_address=None
    ) == (preserved, True)
    assert len(initial) == 6


@pytest.mark.parametrize("state", ["present", "absent"])
def test_invalid_ip_entry_preserves_upstream_failure_before_any_write(
    helper: ModuleType, state: str
) -> None:
    original = ["192.0.2.1 host.invalid", "bad name.invalid"]
    with pytest.raises(ValueError) as raised:
        _edit(helper, original, state=state)
    assert str(raised.value) == (
        "Unhandled exception while executing module: The property "
        "'IPAddressToString' cannot be found on this object. "
        "Verify that the property exists."
    )
    assert original == ["192.0.2.1 host.invalid", "bad name.invalid"]
    assert _edit(helper, original, state=None) == (original, False)


def test_name_selector_matches_canonical_names_not_aliases(helper: ModuleType) -> None:
    lines = ["192.0.2.1 HOST.invalid alias.invalid", "::1 host.invalid"]
    assert _edit(helper, lines, state="absent", ip_address=None) == ([], True)
    assert _edit(
        helper,
        lines,
        state="absent",
        ip_address=None,
        canonical_name="alias.invalid",
    ) == (lines, False)


def test_raw_short_address_does_not_match_canonical_entry(helper: ModuleType) -> None:
    original = ["127.1 host.invalid"]
    assert _edit(helper, original, ip_address="127.1") == (
        ["127.1 host.invalid "],
        True,
    )
    assert _edit(helper, original, state="absent", ip_address="127.1") == (
        original,
        False,
    )
    assert _edit(helper, ["127.1 host.invalid "], ip_address="127.1") == (
        ["127.1 host.invalid "],
        True,
    )


@pytest.mark.parametrize(
    "action, aliases",
    [
        ("set", ["new.invalid"]),
        ("add", ["new.invalid", "carry.invalid"]),
        ("remove", ["carry.invalid"]),
    ],
)
def test_same_family_move_preserves_other_family(
    helper: ModuleType, action: str, aliases: list[str]
) -> None:
    other_family = "2001:db8::1 host.invalid six.invalid"
    original = ["192.0.2.9 host.invalid carry.invalid", other_family]
    updated, changed = _edit(helper, original, action=action, aliases=["new.invalid"])
    assert changed
    assert updated == [other_family, "192.0.2.1 host.invalid " + " ".join(aliases)]
    assert original[0].endswith("carry.invalid")


def test_alias_transfer_preserves_order_and_case_insensitive_deduplication(
    helper: ModuleType,
) -> None:
    original = [
        "192.0.2.9 host.invalid OLD.invalid carry.invalid",
        "192.0.2.8 renamed.invalid extra.invalid CARRY.invalid",
    ]
    assert _edit(
        helper, original, action="add", aliases=["old.invalid", "renamed.invalid"]
    ) == (
        [
            "192.0.2.1 host.invalid old.invalid renamed.invalid carry.invalid extra.invalid"
        ],
        True,
    )


def test_alias_updates_preserve_comment_spacing(helper: ModuleType) -> None:
    original = ["192.0.2.1 host.invalid old.invalid # keep"]
    updated, changed = _edit(helper, original, aliases=["new.invalid"])
    assert changed and updated == ["192.0.2.1 host.invalid  new.invalid # keep"]
    assert _edit(helper, updated, aliases=["NEW.invalid"]) == (updated, False)


def test_last_name_removal_changes_diff_but_not_changed_flag(
    helper: ModuleType,
) -> None:
    original = ["192.0.2.1 host.invalid", "192.0.2.9 lone.invalid"]
    assert _edit(helper, original, action="remove", aliases=["lone.invalid"]) == (
        original,
        False,
    )
    # A canonical name on the same address is removed even with action=remove.
    same_address = ["192.0.2.9 lone.invalid", "192.0.2.9 host.invalid"]
    assert _edit(
        helper, same_address, ip_address="192.0.2.9", aliases=["lone.invalid"]
    ) == (["192.0.2.9 host.invalid lone.invalid "], True)


def test_nonwriting_last_name_removal_from_alias_conflict(helper: ModuleType) -> None:
    original = ["192.0.2.9 lone.invalid", "192.0.2.1 host.invalid"]
    assert _edit(helper, original, aliases=["lone.invalid"], action="remove") == (
        original,
        False,
    )
    original = ["192.0.2.1 lone.invalid", "192.0.2.1 host.invalid"]
    assert _edit(helper, original, aliases=["lone.invalid"], action="remove") == (
        ["192.0.2.1 host.invalid"],
        False,
    )


def test_duplicate_aliases_follow_existing_and_new_entry_behavior(
    helper: ModuleType,
) -> None:
    aliases = ["duplicate.invalid", "duplicate.invalid"]
    assert _edit(helper, [], aliases=aliases) == (
        ["192.0.2.1 host.invalid duplicate.invalid duplicate.invalid"],
        True,
    )
    assert _edit(helper, ["192.0.2.1 host.invalid"], aliases=aliases) == (
        ["192.0.2.1 host.invalid duplicate.invalid "],
        True,
    )


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"", []),
        (
            "# Café\rone\ntwo\r\n\r\n".encode("cp1252"),
            ["# Café", "one", "two", ""],
        ),
        (codecs.BOM_UTF8 + "# 雪\none".encode(), ["# 雪", "one"]),
        (codecs.BOM_UTF16_LE + "# 雪\none".encode("utf-16-le"), ["# 雪", "one"]),
        ("one\u2028two".encode("utf-8"), ["one\u2028two"]),
    ],
)
def test_reads_use_bom_and_preserve_logical_lines(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    data: bytes,
    expected: list[str],
) -> None:
    path = tmp_path / "hosts"
    path.write_bytes(data)
    monkeypatch.setattr(helper, "_hosts_path", lambda: str(path))
    monkeypatch.setattr(
        helper,
        "_read_encoding",
        lambda: "utf-8" if b"\xe2\x80\xa8" in data else "cp1252",
    )
    assert helper.read_hosts() == expected


def test_write_uses_native_encoding_crlf_and_existing_file_object(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "hosts"
    path.write_bytes(b"old")
    identity = path.stat().st_ino
    monkeypatch.setattr(helper, "_hosts_path", lambda: str(path))
    encoder = Mock(side_effect=lambda text, *_: text.encode("cp1252", "replace"))
    monkeypatch.setattr(helper.codecs, "encode", encoder)
    helper.write_hosts(["# Café 雪", "192.0.2.1 host.invalid "])
    encoder.assert_called_once_with(
        "# Café 雪\r\n192.0.2.1 host.invalid \r\n", "mbcs", "replace"
    )
    assert path.read_bytes() == "# Café ?\r\n192.0.2.1 host.invalid \r\n".encode(
        "cp1252"
    )
    assert path.stat().st_ino == identity
    helper.write_hosts([])
    assert path.read_bytes() == b""


def test_failed_read_then_recovery(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "hosts"
    monkeypatch.setattr(helper, "_hosts_path", lambda: str(path))
    monkeypatch.setattr(helper, "_read_encoding", lambda: "cp1252")
    with pytest.raises(FileNotFoundError):
        helper.read_hosts()
    path.write_bytes(b"192.0.2.1 host.invalid")
    assert helper.read_hosts() == ["192.0.2.1 host.invalid"]
