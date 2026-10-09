"""Check the Stat and Find fixtures' explicit directory attribute baselines."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import os
from pathlib import Path
from types import CodeType, SimpleNamespace
from unittest.mock import Mock

import pytest

# PyYAML's fixture loader has no stubs in the pinned development environment.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT, native_error


def _directory_setup(playbook: str) -> CodeType:
    play = yaml.safe_load(
        (ROOT / "tests/integration" / playbook).read_text(encoding="utf-8")
    )[0]
    setup = next(task for task in play["tasks"] if "block" in task)["block"][0]
    source = setup["sustainablelobster.legacy_windows.win_command"]["argv"][2]
    statements = ast.parse(source).body
    parent_reset = next(
        node
        for node in statements
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.UnaryOp)
        and isinstance(node.test.operand, ast.Call)
        and isinstance(node.test.operand.func, ast.Attribute)
        and node.test.operand.func.attr == "SetFileAttributesW"
        and isinstance(node.test.operand.args[0], ast.Name)
        and node.test.operand.args[0].id == "root"
    )
    directory_loop = next(
        node
        for node in statements
        if isinstance(node, ast.For)
        and isinstance(node.iter, ast.Name)
        and node.iter.id == "directories"
    )
    return compile(
        ast.Module(body=[parent_reset, directory_loop], type_ignores=[]),
        "<metadata fixture>",
        "exec",
    )


@pytest.mark.parametrize("inherited", [0x10, 0x2010])
@pytest.mark.parametrize("playbook", ["win_stat.yml", "win_find.yml"])
def test_directory_baseline_does_not_depend_on_temp_parent_attributes(
    tmp_path: Path, inherited: int, playbook: str
) -> None:
    attributes = {str(tmp_path): inherited}

    def _mkdir(path: str) -> None:
        os.mkdir(path)
        attributes[path] = attributes[os.path.dirname(path)]

    def _set_attributes(path: str, value: int) -> bool:
        assert Path(path).is_dir()
        attributes[path] = value
        return True

    directories = ["nested", "nested/child", "empty", "hidden-dir"]
    namespace = {
        "root": str(tmp_path),
        "directories": directories,
        "os": SimpleNamespace(path=os.path, mkdir=_mkdir),
        "kernel": SimpleNamespace(SetFileAttributesW=_set_attributes),
    }
    # Run the actual baseline and loop without DLL bindings or other effects.
    # pylint: disable-next=exec-used
    exec(_directory_setup(playbook), namespace)
    assert attributes == {
        str(tmp_path): 16,
        **{str(tmp_path / name): 16 for name in directories},
    }


@pytest.mark.parametrize("playbook", ["win_stat.yml", "win_find.yml"])
def test_failed_attribute_reset_stops_before_public_metadata_tests(
    tmp_path: Path, playbook: str
) -> None:
    setter = Mock(return_value=False)
    namespace = {
        "root": str(tmp_path),
        "directories": ["first", "must-not-be-created"],
        "os": os,
        "kernel": SimpleNamespace(SetFileAttributesW=setter),
        "ctypes": SimpleNamespace(get_last_error=lambda: 5, WinError=native_error),
    }
    with pytest.raises(OSError) as raised:
        # Execute the real baseline and loop with a simulated native denial.
        # pylint: disable-next=exec-used
        exec(_directory_setup(playbook), namespace)
    assert raised.value.errno == 5
    setter.assert_called_once_with(str(tmp_path), 16)
    assert not (tmp_path / "first").exists()
    assert not (tmp_path / "must-not-be-created").exists()
