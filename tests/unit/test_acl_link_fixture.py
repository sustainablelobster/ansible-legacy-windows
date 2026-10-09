"""Exercise junction-fixture cleanup and permission recovery without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# The pinned Nix environment supplies PyYAML without its optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT, native_error


@pytest.fixture(name="fixture")
def link_fixture(tmp_path: Path) -> Any:
    """Load cleanup functions against owned files and simulated native attributes.

    :param tmp_path: Disposable local workspace for the recovery journal.
    :returns: Fixture functions, files, and observable native operations.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/acl_link_fixture.yml").read_text()
    )["acl_link_fixture"]
    functions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef)
        and node.name in ("cleanup", "exists", "sid_order")
    ]
    target, link = tmp_path / "target", tmp_path / "link"
    target.mkdir()
    link.mkdir()
    child = target / "unchanged.bin"
    child.write_bytes(b"unchanged contents")
    paths = {"link": str(link), "target": str(target), "file": str(child)}
    journal = tmp_path / "acl-links.json"
    journal.write_text(json.dumps({"paths": paths}), encoding="utf-8")
    state = SimpleNamespace(
        paths=paths, journal=journal, readable=False, error=0, events=[]
    )

    def _attributes(path: str) -> int:
        state.events.append(("inspect", path))
        if path == paths["file"] and not state.readable:
            state.error = 5
            return 0xFFFFFFFF
        if not os.path.exists(path):
            state.error = 2
            return 0xFFFFFFFF
        return 16 if os.path.isdir(path) else 0

    def _protect(path: str, _user: str, inheritable: bool = False) -> None:
        state.events.append(("protect", path, inheritable))
        if path == paths["target"] and inheritable:
            state.readable = True

    def _remove(path: str) -> None:
        state.events.append(("remove", path))
        os.remove(path)

    def _rmdir(path: str) -> None:
        state.events.append(("rmdir", path))
        os.rmdir(path)

    namespace = {
        "STATE": str(journal),
        "PATHS": paths,
        "json": json,
        "os": SimpleNamespace(path=os.path, remove=_remove, rmdir=_rmdir),
        "ctypes": SimpleNamespace(
            get_last_error=lambda: state.error, WinError=native_error
        ),
        "attributes": _attributes,
        "protect": _protect,
        "current_user": lambda: "S-1-5-21-1-2-3-1000",
    }
    # Execute only selected functions; no DLL loading or Windows setup runs here.
    # pylint: disable-next=exec-used
    exec(
        compile(ast.Module(body=functions, type_ignores=[]), "<link fixture>", "exec"),
        namespace,
    )
    state.calls = namespace
    state.cleanup = namespace["cleanup"]
    return state


def test_cleanup_restores_child_access_before_inspection_and_deletion(
    fixture: Any,
) -> None:
    assert fixture.cleanup() == {"cleaned": True}
    assert not fixture.journal.exists()
    assert not any(os.path.exists(path) for path in fixture.paths.values())
    recovery = fixture.events.index(("protect", fixture.paths["target"], True))
    child_read = fixture.events.index(("inspect", fixture.paths["file"]))
    link_removal = fixture.events.index(("rmdir", fixture.paths["link"]))
    assert link_removal < recovery < child_read
    assert fixture.events[-1] == ("remove", str(fixture.journal))


@pytest.mark.parametrize("error", [2, 3, 5])
def test_native_access_denial_is_not_treated_as_a_missing_path(
    fixture: Any, error: int
) -> None:
    fixture.error = error
    fixture.calls["attributes"] = Mock(return_value=0xFFFFFFFF)
    if error == 5:
        with pytest.raises(OSError) as raised:
            fixture.calls["exists"](fixture.paths["file"])
        assert raised.value.errno == 5
    else:
        assert fixture.calls["exists"](fixture.paths["file"]) is False


@pytest.mark.parametrize("failure", ["restore permissions", "remove child"])
def test_failed_cleanup_retains_journal_and_recovers_on_retry(
    fixture: Any, failure: str
) -> None:
    journal_before = fixture.journal.read_bytes()
    if failure == "restore permissions":
        original = fixture.calls["protect"]
        fixture.calls["protect"] = Mock(side_effect=OSError(failure))
    else:
        original = fixture.calls["os"].remove
        fixture.calls["os"].remove = Mock(side_effect=OSError(failure))
    with pytest.raises(OSError, match=failure):
        fixture.cleanup()
    assert fixture.journal.read_bytes() == journal_before
    assert Path(fixture.paths["file"]).read_bytes() == b"unchanged contents"
    assert Path(fixture.paths["target"]).is_dir()
    assert not Path(fixture.paths["link"]).exists()
    if failure == "restore permissions":
        fixture.calls["protect"] = original
    else:
        fixture.calls["os"].remove = original
    assert fixture.cleanup() == {"cleaned": True}
    assert not fixture.journal.exists()


def test_no_journal_means_no_owned_paths_are_touched(fixture: Any) -> None:
    fixture.journal.unlink()
    assert fixture.cleanup() == {"cleaned": False}
    assert fixture.events == []
    assert all(os.path.exists(path) for path in fixture.paths.values())


def test_sid_order_uses_authority_then_subauthority_count_then_numeric_values(
    fixture: Any,
) -> None:
    expected = [
        "S-1-2-100",
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-21-8-9-10-1000",
        "S-1-5-21-10-9-10-1000",
        "S-1-12-1",
    ]
    assert sorted(reversed(expected), key=fixture.calls["sid_order"]) == expected
