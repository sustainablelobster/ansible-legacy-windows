"""Fault-test process-tree identities, protected inputs and bounded evidence."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def children_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load only the concrete fixture around recorded native boundaries.

    :param tmp_path: Owner-private workspace.
    :param monkeypatch: Scoped platform and registry fixture substitutions.
    :returns: Real fixture and observable protected-state operations.
    """
    base = SimpleNamespace(
        source_files=Mock(return_value={"registry_installer.py": {"bytes": b"old"}}),
        file_state=Mock(return_value={"bytes": b"tree", "mtime": 1}),
        INSTALLER=str(tmp_path / "registry installer.exe"),
        cleanup=Mock(return_value={"restored": True}),
        now=Mock(return_value=1),
        prepare=Mock(return_value={"protected": "literal"}),
        snapshot=Mock(return_value={"protected": "literal"}),
    )
    monkeypatch.setitem(sys.modules, "package_registry_fixture", base)
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "observe"])
    module = load_module(
        ROOT / "tests/integration/fixtures/package_children_fixture.py", "fixture"
    )
    return SimpleNamespace(module=module, base=base, root=tmp_path)


def records(root: str) -> dict[str, Any]:
    """Produce complete, raw-serialized receipts with distinct real PID links.

    :param root: Exact owned workspace.
    :returns: Synthetic full receipt observations.
    """
    result = {}
    for role, pid, parent, child, code in (
        ("parent", 10, 0, 11, 0),
        ("child", 11, 10, 12, 19),
        ("grandchild", 12, 11, None, 29),
    ):
        data = {
            "workspace": root,
            "role": role,
            "pid": pid,
            "parent": parent,
            "code": code,
            "utc": 2,
            "cwd": root,
        }
        if child:
            data["child"] = child
        raw = json.dumps(data, sort_keys=True).encode("utf-8")
        result[role] = {
            "data": data,
            "file": {
                "bytes": {"raw_bytes": base64.b64encode(raw).decode("ascii")},
                "sha256": hashlib.sha256(raw).hexdigest(),
                "length": len(raw),
                "mtime": 2000000000,
                "attributes": 32,
                "acl": "literal",
            },
        }
    return result


@pytest.fixture(name="comparator")
def children_comparator() -> Any:
    """Load maintained evidence checks without contacting Windows.

    :returns: Real whole-result comparator.
    """
    return load_module(
        ROOT / "tests/integration/files/package_children_compare.py", "compare"
    )


def test_tree_program_is_part_of_literal_protected_sources(fixture: Any) -> None:
    (fixture.root / "tree_installer.py").touch()
    assert fixture.module.sources() == {
        "registry_installer.py": {"bytes": b"old"},
        "tree_installer.py": {"bytes": b"tree", "mtime": 1},
    }


def test_partial_receipts_are_not_adopted(fixture: Any) -> None:
    (fixture.root / "parent.json").touch()
    fixture.base.file_state.return_value = {
        "bytes": json.dumps(
            {"workspace": str(fixture.root), "role": "parent", "pid": 10, "parent": 0}
        ).encode()
    }
    with pytest.raises(AssertionError):
        fixture.module.receipts()


@pytest.mark.parametrize("mutation", ["workspace", "bool_pid", "broken_graph"])
def test_receipt_identity_or_graph_mutation_is_rejected(
    fixture: Any, mutation: str
) -> None:
    observed = records(str(fixture.root))
    for role in observed:
        (fixture.root / (role + ".json")).touch()
    if mutation == "workspace":
        observed["parent"]["data"]["workspace"] = "unowned"
    elif mutation == "bool_pid":
        observed["child"]["data"]["pid"] = True
    else:
        observed["grandchild"]["data"]["parent"] = 99
    fixture.base.file_state.side_effect = lambda path: {
        "bytes": json.dumps(observed[Path(path).stem]["data"]).encode()
    }
    with pytest.raises(AssertionError):
        fixture.module.receipts()


def test_unknown_active_process_blocks_cleanup_without_killing(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fixture.module, "receipts", lambda: records(str(fixture.root)))
    monkeypatch.setattr(
        fixture.module,
        "running",
        lambda: [{"ProcessId": 99, "ExecutablePath": "unowned"}],
    )
    with pytest.raises(AssertionError):
        fixture.module.cleanup()
    fixture.base.cleanup.assert_not_called()


def test_mutated_receipt_blocks_deletion_and_registry_recovery(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = records(str(fixture.root))
    monkeypatch.setattr(fixture.module, "settle", lambda: observed)
    with pytest.raises(AssertionError):
        fixture.module.cleanup()
    fixture.base.cleanup.assert_not_called()


def test_cleanup_settles_and_clears_receipts_before_registry_restoration(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    ordering = []
    monkeypatch.setattr(fixture.module, "clear_tree", lambda: ordering.append("tree"))
    monkeypatch.setattr(fixture.module, "running", lambda: [])
    monkeypatch.setattr(fixture.module, "receipts", lambda: {})

    def _cleanup() -> dict[str, bool]:
        ordering.append("registry")
        return {"restored": True}

    fixture.base.cleanup.side_effect = _cleanup
    assert fixture.module.cleanup() == {
        "restored": True,
        "process_tree_absent": True,
        "receipt_files_absent": True,
    }
    assert ordering == ["tree", "registry"]


def test_generated_identity_qualification_retains_unknown_fields(
    comparator: Any,
) -> None:
    after: dict[str, Any] = {"utc": 4, "receipts": records("owned"), "running": []}
    after["receipts"]["parent"]["data"]["unknown"] = "preserved"
    raw = json.dumps(after["receipts"]["parent"]["data"], sort_keys=True).encode()
    file = after["receipts"]["parent"]["file"]
    file.update(
        bytes={"raw_bytes": base64.b64encode(raw).decode("ascii")},
        sha256=hashlib.sha256(raw).hexdigest(),
        length=len(raw),
    )
    value = comparator.portable_receipts(after, {"utc": 1}, {"executed": True})
    assert value["parent"]["data"]["unknown"] == "preserved"
    assert value["child"]["data"]["parent"] == "<owned-parent>"
    assert value["grandchild"]["data"]["parent"] == "<owned-child>"
    assert value["parent"]["file"]["attributes"] == 32
    assert value["parent"]["file"]["acl"] == "literal"


@pytest.mark.parametrize(
    "mutation", ["bytes", "mtime", "clock", "root_code", "graph", "active"]
)
def test_receipt_comparator_rejects_each_concrete_unqualified_difference(
    comparator: Any, mutation: str
) -> None:
    after: dict[str, Any] = {"utc": 4, "receipts": records("owned"), "running": []}
    record = after["receipts"]["parent"]
    if mutation == "bytes":
        record["file"]["bytes"] = {"raw_bytes": base64.b64encode(b"other").decode()}
    elif mutation == "mtime":
        record["file"]["mtime"] = 5000000000
    elif mutation == "clock":
        record["data"]["utc"] = 0
    elif mutation == "root_code":
        record["data"]["code"] = 19
    elif mutation == "graph":
        record["data"]["child"] = 12
    else:
        after["running"] = [{"ProcessId": 99}]
    with pytest.raises(AssertionError):
        comparator.portable_receipts(after, {"utc": 1}, {"executed": True})


def test_protected_mtime_and_unknown_fields_are_not_qualified(comparator: Any) -> None:
    baseline: dict[str, Any] = {
        "utc": 1,
        "registry": {"HKCU/native": {"values": [], "children": []}},
        "sources": {"tree.py": {"mtime": 1, "bytes": "literal", "unknown": 7}},
        "outputs": {},
    }
    observed = copy.deepcopy(baseline)
    observed["sources"]["tree.py"]["mtime"] = 2
    assert comparator.protected(observed, baseline, "owned") != comparator.protected(
        baseline, baseline, "owned"
    )
    assert comparator.state(baseline)["sources"]["tree.py"]["unknown"] == 7


def test_owned_identity_replacement_preserves_typed_and_unknown_fields(
    comparator: Any,
) -> None:
    value = {
        "path": r"C:\owned\installer.exe",
        "msg": r"Product123 failed in C:\owned",
        "unexpected": ["other-root", 19, False, None],
    }
    assert comparator.rewrite_owned(value, r"C:\owned", "Product123") == {
        "path": r"<owned-workspace>\installer.exe",
        "msg": "<owned-product> failed in <owned-workspace>",
        "unexpected": ["other-root", 19, False, None],
    }


def test_zero_retained_cases_do_not_count_as_public_evidence(comparator: Any) -> None:
    with pytest.raises(AssertionError, match="No complete observed public case"):
        comparator.verify_capture({"results": []}, True)


def test_owned_descendants_cannot_inherit_unused_root_output_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    creation, closure = Mock(return_value=(10, 11, 12, 13)), Mock()
    monkeypatch.setitem(
        sys.modules,
        "_winapi",
        SimpleNamespace(CreateProcess=creation, CloseHandle=closure),
    )
    installer = load_module(
        ROOT / "tests/integration/fixtures/package_children_installer.py", "tree"
    )
    monkeypatch.setattr(
        installer.subprocess, "STARTUPINFO", SimpleNamespace, raising=False
    )
    assert installer.spawn("owned", "child", "install", "0", "20") == 12
    assert creation.call_args.args[4:9] == (
        False,
        0x08000000,
        None,
        "owned",
        creation.call_args.args[8],
    )
    assert [call.args for call in closure.call_args_list] == [(11,), (10,)]
