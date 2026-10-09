"""Check observable search behavior without contacting a Windows host."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct calls isolate payload behavior from the native boundaries.
# pylint: disable=protected-access

import json
import ntpath
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import load_payload

ROOT = r"C:\Data"
EPOCH = 621355968000000000
ENTRY = {
    "name": "small.txt",
    "attributes": 32,
    "creation_time": EPOCH + 10000001,
    "access_time": EPOCH + 20000002,
    "modification_time": EPOCH + 30000003,
    "size": 3,
}


@pytest.fixture(name="payload")
def find_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Replace only native operations with deterministic search fixtures.

    :param monkeypatch: Scoped native-operation replacements.
    :returns: The payload using a single-directory fixture.
    """
    module = load_payload("win_find", monkeypatch)
    for target, name, replacement in (
        (module.links, "enable_backup_privilege", Mock()),
        (module.links, "get_link_info", Mock(return_value=None)),
        (module.filesystem, "file_info", Mock(return_value={"attributes": 16})),
        (module.filesystem, "directory_entries", Mock(return_value=[dict(ENTRY)])),
        (module.filesystem, "full_path", Mock(side_effect=ntpath.normpath)),
        (module.filesystem, "owner", Mock(return_value=r"HOST\user")),
        (module.filesystem, "shares", Mock(return_value=[])),
        (module.filesystem, "checksum", Mock(return_value="abc123")),
        (module.filesystem, "hardlink_count", Mock(return_value=1)),
        (
            module.timestamps,
            "file_time_to_local_ticks",
            Mock(side_effect=lambda value: value),
        ),
        (
            module.timestamps,
            "current_local_ticks",
            Mock(return_value=EPOCH + 100000000),
        ),
        (module.matching, "path_key", str.lower),
        (
            module.matching,
            "compare_paths",
            lambda left, right: (left.lower() > right.lower())
            - (left.lower() < right.lower()),
        ),
    ):
        monkeypatch.setattr(target, name, replacement)
    return module


def _find(payload: ModuleType, **options: object) -> dict[str, Any]:
    result: dict[str, Any] = payload._find(
        payload._parameters({"paths": [ROOT], **options})
    )
    return result


def test_complete_file_result_and_repeated_read(payload: ModuleType) -> None:
    result = _find(payload)
    assert result == {
        "changed": False,
        "examined": 1,
        "matched": 1,
        "files": [
            {
                "path": ROOT + r"\small.txt",
                "filename": "small.txt",
                "exists": True,
                "attributes": "Archive",
                "owner": r"HOST\user",
                "isarchive": True,
                "isdir": False,
                "ishidden": False,
                "isreadonly": False,
                "isreg": True,
                "islnk": False,
                "isjunction": False,
                "isshared": False,
                "sharename": None,
                "extension": ".txt",
                "size": 3,
                "checksum": "abc123",
                "nlink": 1,
                "hlnk_targets": [],
                "lnk_source": None,
                "lnk_target": None,
                "creationtime": float(10000001) * 1e-7,
                "lastaccesstime": float(20000002) * 1e-7,
                "lastwritetime": float(30000003) * 1e-7,
            }
        ],
    }
    assert _find(payload) == result


@pytest.mark.parametrize(
    ("ticks", "expected", "expected_type"),
    [
        (0, 0, int),
        (-10000000, -1, int),
        (10000000, 1, int),
        (2500000, 0.25, float),
        (-2500000, -0.25, float),
        (14779590050000000, 1477959005, int),
    ],
)
def test_timestamp_json_projection_preserves_fractional_and_signed_values(
    payload: ModuleType, ticks: int, expected: int | float, expected_type: type
) -> None:
    entry = dict(ENTRY)
    for field in ("creation_time", "access_time", "modification_time"):
        entry[field] = EPOCH + ticks
    payload.filesystem.directory_entries.return_value = [entry]
    result = _find(payload)["files"][0]
    for field in ("creationtime", "lastaccesstime", "lastwritetime"):
        assert result[field] == expected
        # JSON distinguishes integral seconds from a numerically equal float.
        # pylint: disable-next=unidiomatic-typecheck
        assert type(result[field]) is expected_type


@pytest.mark.parametrize("paths", [None, []])
def test_no_roots_returns_empty_result(payload: ModuleType, paths: object) -> None:
    assert _find(payload, paths=paths) == {
        "changed": False,
        "examined": 0,
        "matched": 0,
        "files": [],
    }
    payload.filesystem.directory_entries.assert_not_called()


@pytest.mark.parametrize(
    "options,expected",
    [
        ({"patterns": None}, 1),
        ({"patterns": []}, 0),
        ({"patterns": "", "use_regex": True}, 1),
        ({"patterns": ["TXT"], "use_regex": True}, 1),
        ({"patterns": ["TXT"], "use_regex": True, "case_sensitive": True}, 0),
        (
            {
                "patterns": ["["],
                "regex": ["missing"],
                "regexp": ["txt"],
                "use_regex": True,
            },
            1,
        ),
        ({"file_type": None}, 0),
        ({"file_type": "DIRECTORY"}, 0),
        ({"file_type": "ANY"}, 1),
        ({"size": "3"}, 1),
        ({"size": "4"}, 0),
        ({"size": "-2"}, 0),
        ({"size": "-3"}, 1),
        ({"size": "1B\n"}, 1),
        ({"age": "6s"}, 1),
        ({"age": "8"}, 0),
        ({"age": "-8"}, 1),
        ({"age": "-6"}, 0),
        ({"age": "1", "age_stamp": None}, 1),
        ({"age": "-1", "age_stamp": None}, 0),
    ],
)
def test_filters(
    payload: ModuleType, options: dict[str, object], expected: int
) -> None:
    result = _find(payload, **options)
    assert result["examined"] == 1
    assert result["matched"] == expected
    assert len(result["files"]) == expected


@pytest.mark.parametrize(
    "name",
    ["get_checksum", "follow", "hidden", "recurse", "use_regex", "case_sensitive"],
)
def test_boolean_null_is_false(payload: ModuleType, name: str) -> None:
    assert payload._parameters({"paths": [], name: None})[name] is False


@pytest.mark.parametrize("value", [None, False])
def test_checksum_disabled(payload: ModuleType, value: object) -> None:
    assert _find(payload, get_checksum=value)["files"][0]["checksum"] is None
    payload.filesystem.checksum.assert_not_called()


def test_checksum_failure_is_suppressed_and_recovers(payload: ModuleType) -> None:
    payload.filesystem.checksum.side_effect = [OSError("sharing violation"), "digest"]
    failed_read = _find(payload)
    assert failed_read["files"][0]["checksum"] is None
    assert "warnings" not in failed_read
    assert "failed" not in failed_read
    assert _find(payload)["files"][0]["checksum"] == "digest"


@pytest.mark.parametrize(
    "info,message", [(None, "does not exist"), ({"attributes": 32}, "not a directory")]
)
def test_invalid_root_warns_and_skips(
    payload: ModuleType, info: object, message: str
) -> None:
    payload.filesystem.file_info.return_value = info
    result = _find(payload)
    assert result["examined"] == result["matched"] == 0
    assert message in result["warnings"][0]
    payload.filesystem.directory_entries.assert_not_called()


@pytest.mark.parametrize("character", ["*", "?", "\x00", '"', "<", ">", "|", "\t"])
def test_invalid_ordinary_root_fails_before_native_path_operations(
    payload: ModuleType, character: str
) -> None:
    with pytest.raises(ValueError):
        _find(payload, paths=[ROOT + "\\bad" + character + "root"])
    payload.filesystem.full_path.assert_not_called()
    payload.filesystem.file_info.assert_not_called()
    payload.filesystem.directory_entries.assert_not_called()


@pytest.mark.parametrize("suffix", ["\\*.txt", "\x00suffix"])
def test_invalid_root_json_failure_discards_prior_root_results(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    suffix: str,
) -> None:
    monkeypatch.setattr(
        payload,
        "read_arguments",
        lambda *_args: {"paths": [ROOT, ROOT + suffix]},
    )
    with pytest.raises(SystemExit) as error:
        payload.main()
    assert error.value.code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["failed"] is True and result["changed"] is False
    assert not {"examined", "matched", "files"} & result.keys()
    payload.filesystem.full_path.assert_called_once_with(ROOT)
    payload.filesystem.file_info.assert_called_once_with(ROOT)
    payload.filesystem.directory_entries.assert_called_once_with(ROOT)


def test_root_environment_reference_remains_literal(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LEGACY_FIND_TEST", "expanded*value")
    path = r"C:\%legacy_find_test%\folder"
    assert _find(payload, paths=[path])["matched"] == 1
    payload.filesystem.full_path.assert_called_once_with(path)
    payload.filesystem.file_info.assert_called_once_with(path)
    payload.filesystem.directory_entries.assert_called_once_with(path)


@pytest.mark.parametrize(
    "path",
    [r"C:\雪 [folder]", r"\\?\C:\雪 [folder]", r"\\?\UNC\server\share\雪 [folder]"],
)
def test_literal_root_spelling_reaches_native_resolution_unchanged(
    payload: ModuleType, path: str
) -> None:
    assert _find(payload, paths=[path])["matched"] == 1
    payload.filesystem.full_path.assert_called_once_with(path)
    payload.filesystem.file_info.assert_called_once_with(path)
    payload.filesystem.directory_entries.assert_called_once_with(path)


def test_extended_wildcard_directory_retains_native_enumeration_failure(
    payload: ModuleType,
) -> None:
    path = r"\\?\C:\Data\*"
    error = OSError(
        "The filename, directory name, or volume label syntax is incorrect."
    )
    # The developer host's OSError lacks Windows' native error-code attribute.
    error.winerror = 123  # type: ignore[attr-defined]
    payload.filesystem.directory_entries.side_effect = error
    with pytest.raises(OSError) as failure:
        _find(payload, paths=[path])
    assert failure.value is error
    payload.filesystem.full_path.assert_called_once_with(path)
    payload.filesystem.file_info.assert_called_once_with(path)
    payload.filesystem.directory_entries.assert_called_once_with(path)


@pytest.mark.parametrize("path", [r"\\?\C:\Data\*", r"\\?\C:\Data\fil?.txt"])
@pytest.mark.parametrize(
    "info,message",
    [
        (None, "does not exist or is not accessible"),
        ({"attributes": 32}, "is a file not a directory"),
    ],
)
def test_extended_wildcard_missing_or_file_root_warns_and_skips(
    payload: ModuleType, path: str, info: object, message: str
) -> None:
    payload.filesystem.file_info.return_value = info
    assert _find(payload, paths=[path]) == {
        "changed": False,
        "examined": 0,
        "matched": 0,
        "files": [],
        "warnings": [f"Argument path '{path}' {message}, skipping"],
    }
    payload.filesystem.full_path.assert_called_once_with(path)
    payload.filesystem.file_info.assert_called_once_with(path)
    payload.filesystem.directory_entries.assert_not_called()


@pytest.mark.parametrize(
    "size,matched", [("0", 1), ("1", 1), ("2", 0), ("-1", 1), ("-2", 1)]
)
def test_directory_uses_scalar_one_for_size_filter(
    payload: ModuleType, size: str, matched: int
) -> None:
    payload.filesystem.directory_entries.return_value = [
        {**ENTRY, "name": "folder", "attributes": 16}
    ]
    result = _find(payload, file_type="directory", size=size)
    assert result["matched"] == matched
    if matched:
        info = result["files"][0]
        assert info["size"] is info["checksum"] is info["extension"] is None
        assert info["isdir"] and not info["isreg"]
    payload.filesystem.checksum.assert_not_called()


@pytest.mark.parametrize(
    "depth,examined,names",
    [
        (1, 3, ["small.txt"]),
        (2, 5, ["child.txt", "small.txt"]),
        (None, 6, ["child.txt", "deep.txt", "small.txt"]),
        (0, 6, ["child.txt", "deep.txt", "small.txt"]),
        (-1, 6, ["child.txt", "deep.txt", "small.txt"]),
    ],
)
def test_depth_hidden_traversal_and_duplicate_roots(
    payload: ModuleType, depth: object, examined: int, names: list[str]
) -> None:
    tree = {
        ROOT.lower(): [
            dict(ENTRY),
            {**ENTRY, "name": "hidden", "attributes": 18},
            {**ENTRY, "name": "empty", "attributes": 16},
        ],
        (ROOT + r"\hidden").lower(): [
            {**ENTRY, "name": "child.txt"},
            {**ENTRY, "name": "deeper", "attributes": 16},
        ],
        (ROOT + r"\hidden\deeper").lower(): [{**ENTRY, "name": "deep.txt"}],
        (ROOT + r"\empty").lower(): [],
    }
    payload.filesystem.directory_entries.side_effect = lambda path: tree[path.lower()]
    result = _find(payload, paths=[ROOT, ROOT.lower()], recurse=True, depth=depth)
    assert result["examined"] == examined
    assert sorted(entry["filename"] for entry in result["files"]) == names
    paths = [entry["path"] for entry in result["files"]]
    assert paths == sorted(paths, key=str.lower)


@pytest.mark.parametrize("follow,examined", [(False, 1), (True, 2)])
def test_directory_links_control_descent(
    payload: ModuleType, follow: bool, examined: int
) -> None:
    payload.filesystem.directory_entries.side_effect = [
        [{**ENTRY, "name": "junction", "attributes": 16 | 1024}],
        [dict(ENTRY)],
    ]
    result = _find(payload, recurse=True, depth=2, follow=follow)
    assert result["examined"] == examined
    assert result["matched"] == int(follow)


def test_invalid_regex_is_lazy_but_not_short_circuited_by_other_filters(
    payload: ModuleType,
) -> None:
    payload.filesystem.directory_entries.return_value = []
    assert _find(payload, patterns=["["], use_regex=True)["matched"] == 0
    payload.filesystem.directory_entries.return_value = [{**ENTRY, "attributes": 16}]
    with pytest.raises(ValueError, match="regular expression"):
        _find(payload, patterns=["["], use_regex=True)
    assert (
        _find(payload, file_type="any", patterns=[".*", "["], use_regex=True)["matched"]
        == 1
    )


@pytest.mark.parametrize("count", [1, 2, 300])
def test_old_windows_hardlink_count(payload: ModuleType, count: int) -> None:
    payload.links.get_link_info.side_effect = NotImplementedError("old Windows")
    payload.filesystem.hardlink_count.return_value = count
    info = _find(payload)["files"][0]
    assert info["nlink"] == count
    assert info["hlnk_targets"] == ([None] if count > 1 else [])
    assert "warnings" not in info


def test_modern_hardlink_keeps_upstream_null_target_bug(payload: ModuleType) -> None:
    payload.links.get_link_info.return_value = {
        "type": "hard",
        "target": [r"C:\one", r"C:\two"],
    }
    info = _find(payload)["files"][0]
    assert info["nlink"] == 2
    assert info["hlnk_targets"] == [None]
    assert "lnk_type" not in info


@pytest.mark.parametrize("kind", ["symbolic", "junction"])
def test_link_target_metadata(payload: ModuleType, kind: str) -> None:
    payload.links.get_link_info.return_value = {
        "type": kind,
        "target": r"..\target",
        "relative": True,
    }
    info = _find(payload)["files"][0]
    assert info["lnk_source"] == r"C:\target"
    assert info["lnk_target"] == r"..\target"
    assert info["islnk"] == (kind == "symbolic")
    assert info["isjunction"] == (kind == "junction")
    assert not info["isreg"]


def test_owner_and_share_failures_warn_without_discarding_entry(
    payload: ModuleType,
) -> None:
    payload.filesystem.directory_entries.return_value = [{**ENTRY, "attributes": 16}]
    payload.filesystem.owner.side_effect = OSError("owner denied")
    payload.filesystem.shares.side_effect = ValueError("share failed")
    result = _find(payload, file_type="directory")
    assert result["matched"] == 1
    assert result["files"][0]["owner"] is None
    assert result["files"][0]["sharename"] is None
    assert len(result["warnings"]) == 2


@pytest.mark.parametrize(
    "names,expected", [(["one"], "one"), (["one", "two"], ["one", "two"])]
)
def test_shared_directory(
    payload: ModuleType, names: list[str], expected: object
) -> None:
    payload.filesystem.directory_entries.return_value = [{**ENTRY, "attributes": 16}]
    payload.filesystem.shares.return_value = names
    info = _find(payload, file_type="directory")["files"][0]
    assert info["isshared"]
    assert info["sharename"] == expected


@pytest.mark.parametrize(
    "options",
    [
        {"paths": True},
        {"paths": 1.5},
        {"paths": {}},
        {"paths": [None]},
        {"depth": True},
        {"depth": 1.5},
        {"depth": 2**31},
        {"age": "١"},
        {"size": "١"},
        {"size": str(2**63)},
        {"age": str(2**63)},
        {"age": "9223372036854775807w"},
        {"file_type": " file"},
        {"checksum_algorithm": "bad"},
        {"hidden": "bad"},
    ],
)
def test_validation_rejects_invalid_values(
    payload: ModuleType, options: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        _find(payload, **options)
    payload.filesystem.directory_entries.assert_not_called()


@pytest.mark.parametrize("name", ["age", "size"])
@pytest.mark.parametrize("path", [ROOT, ROOT + r"\*"])
def test_invalid_quantity_pattern_retains_empty_results(
    payload: ModuleType, name: str, path: str
) -> None:
    assert _find(payload, paths=[path], **{name: "nonsense"}) == {
        "changed": False,
        "failed": True,
        "msg": "Invalid " + name + " pattern specified",
        "examined": 0,
        "matched": 0,
        "files": [],
    }
    payload.filesystem.full_path.assert_not_called()
    payload.filesystem.file_info.assert_not_called()
    payload.filesystem.directory_entries.assert_not_called()


def test_unhandled_pattern_failure_has_no_partial_result(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        payload,
        "read_arguments",
        lambda *_args: {"paths": [ROOT], "patterns": ["["], "use_regex": True},
    )
    with pytest.raises(SystemExit) as error:
        payload.main()
    assert error.value.code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["failed"] and not result["changed"]
    assert not {"examined", "matched", "files"} & result.keys()


@pytest.mark.parametrize(
    "code,suppressed", [(2, True), (3, True), (5, True), (32, False)]
)
def test_enumeration_suppresses_only_upstream_missing_and_access_errors(
    payload: ModuleType, code: int, suppressed: bool
) -> None:
    error = OSError("native enumeration error")
    error.winerror = code  # type: ignore[attr-defined]
    payload.filesystem.directory_entries.side_effect = error
    if suppressed:
        assert _find(payload)["examined"] == 0
    else:
        with pytest.raises(OSError):
            _find(payload)
