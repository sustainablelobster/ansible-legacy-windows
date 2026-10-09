"""Keep real copied-image denial tests isolated from production and existing files."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import load_module

_ROOT = Path(__file__).resolve().parents[2]


def _play() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        yaml.safe_load(
            (_ROOT / "tests/integration/win_updates_launch_fallback.yml").read_text()
        )[0],
    )


def test_public_search_and_check_mode_use_shipping_module_with_bounded_filters() -> (
    None
):
    play = _play()
    assert play["vars"]["updates_launch_cases"] == [
        {"state": "searched", "check": False},
        {"state": "installed", "check": True},
    ]
    cohort = yaml.safe_load(
        (_ROOT / "tests/integration/tasks/win_updates_launch_case.yml").read_text()
    )
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    requests = [
        task
        for task in block + cohort
        if "sustainablelobster.legacy_windows.win_updates" in task
    ]
    assert len(requests) == 2
    for task in requests:
        options = task["sustainablelobster.legacy_windows.win_updates"]
        assert options["category_names"] == ["*"]
        assert options["accept_list"] == [r".*\Z"]
        assert list(options["accept_list"][0].encode("ascii")) == [46, 42, 92, 90]
        assert options["reject_list"] == [".*"]
        assert options["server_selection"] == "managed_server"
        assert (
            task["vars"]["ansible_python_interpreter"]
            == "{{ updates_launch_interpreter }}"
        )
        assert task["environment"] == "{{ updates_launch_environment }}"
        assert "become" not in task and "reboot" not in options
        if "async" in task:
            assert options["state"] == "searched" and task["poll"] == 1
        else:
            assert task["check_mode"] == "{{ item.check }}"


def test_fixture_changes_only_new_files_and_restores_before_workspace_deletion() -> (
    None
):
    play = _play()
    text = (_ROOT / "tests/integration/win_updates_launch_fallback.yml").read_text()
    assert "win_user:" not in text and "win_user_right:" not in text
    assert "win_reboot:" not in text and "namespace-security" not in text
    cleanup = next(task["always"] for task in play["tasks"] if "always" in task)
    restore = next(
        index
        for index, task in enumerate(cleanup)
        if task.get("register") == "updates_launch_restored"
    )
    close = next(
        index
        for index, task in enumerate(cleanup)
        if task.get("register") == "updates_launch_closed"
    )
    delete = next(
        index
        for index, task in enumerate(cleanup)
        if "sustainablelobster.legacy_windows.win_file" in task
    )
    capture = next(
        index
        for index, task in enumerate(cleanup)
        if task.get("ansible.builtin.copy", {})
        .get("dest", "")
        .endswith(".partial.json")
    )
    assert capture < restore < close < delete
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    copies = [
        task["sustainablelobster.legacy_windows.win_copy"]
        for task in block
        if "sustainablelobster.legacy_windows.win_copy" in task
    ]
    assert all("updates_launch_workspace.path" in task["dest"] for task in copies)
    assert any(task.get("remote_src") is True for task in copies)


def test_native_observation_and_finite_lifecycle_programs_compile() -> None:
    block = next(task for task in _play()["tasks"] if "block" in task)
    for task in _play()["tasks"] + block["block"] + block["always"]:
        source = task.get("sustainablelobster.legacy_windows.win_command", {}).get(
            "stdin", ""
        )
        if source and "{{" not in source:
            compile(source, task["name"], "exec")
    source = (
        _ROOT / "tests/integration/fixtures/win_updates_launch_lifecycle.py"
    ).read_text()
    programs = {
        target.id: ast.literal_eval(node.value)
        for node in ast.parse(source).body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
        and target.id in ("_CANCEL_PROGRAM", "_OBSERVE_PROGRAM")
    }
    assert set(programs) == {"_CANCEL_PROGRAM", "_OBSERVE_PROGRAM"}
    for name, program in programs.items():
        compile(program, name, "exec")
    assert "worker.updates.run = controlled_operation" in programs["_CANCEL_PROGRAM"]
    assert "controlled_lifecycle_not_WUA" in programs["_CANCEL_PROGRAM"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("updates", {"unexpected": {}}),
        ("filtered_updates", {"unexpected": {}}),
        ("found_update_count", 1),
        ("failed_update_count", 1),
        ("installed_update_count", 1),
        ("changed", True),
        ("msg", "The launch outcome is uncertain; retained workspace"),
        ("msg", "SYSTEM worker launch failed before dispatch; workspace retained"),
    ],
)
def test_unavailable_system_oracle_accepts_only_empty_predispatch_results(
    field: str, value: Any
) -> None:
    task = next(
        task
        for task in _play()["tasks"]
        if task.get("when") == "not updates_launch_system_available | bool"
    )
    conditions = task["ansible.builtin.assert"]["that"]
    environment = Environment()
    expressions = [
        environment.compile_expression(condition) for condition in conditions
    ]
    result = {
        "updates": {},
        "filtered_updates": {},
        "found_update_count": 0,
        "failed_update_count": 0,
        "installed_update_count": 0,
        "changed": False,
        "msg": (
            "SYSTEM worker launch failed before dispatch; "
            "its owned workspace was removed"
        ),
    }
    assert all(expression(item=result) for expression in expressions)
    assert not all(
        expression(item={**result, field: value}) for expression in expressions
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("msg", "Searching for updates: Exception from HRESULT: 0x80070005"),
        ("hresult", -2147024891),
        ("updates", {"unexpected": {}}),
        ("filtered_updates", {"unexpected": {}}),
        ("found_update_count", 1),
        ("failed_update_count", 1),
        ("installed_update_count", 1),
        ("reboot_required", True),
        ("rebooted", True),
        ("changed", True),
    ],
)
def test_real_operation_oracle_rejects_different_observable_results(
    field: str, value: Any
) -> None:
    task = next(
        task
        for task in _play()["tasks"]
        if task["name"]
        == "Require identical real operation results without servicing retries"
    )
    environment = Environment()
    expressions = [
        environment.compile_expression(condition)
        for condition in task["ansible.builtin.assert"]["that"]
    ]
    result = {
        "msg": "Searching for updates: Exception from HRESULT: 0x8024001A",
        "updates": {},
        "filtered_updates": {},
        "found_update_count": 0,
        "failed_update_count": 0,
        "installed_update_count": 0,
        "reboot_required": False,
        "rebooted": False,
        "changed": False,
    }
    assert all(expression(item=(result, result)) for expression in expressions)
    assert not all(
        expression(item=(result, {**result, field: value}))
        for expression in expressions
    )
    successful = {key: value for key, value in result.items() if key != "msg"}
    assert all(expression(item=(successful, successful)) for expression in expressions)
    assert not all(expression(item=(result, successful)) for expression in expressions)


# The independent test fixture's private decisions are the contracts under test.
# pylint: disable=protected-access
@pytest.fixture(name="site_fixture")
def load_site_fixture() -> ModuleType:
    """Load isolation decisions without invoking any Windows operation.

    :returns: The independent copied-image startup fixture.
    """
    return load_module(
        _ROOT / "tests/integration/fixtures/win_updates_launch_site.py",
        "tested_updates_site",
    )


@pytest.mark.parametrize(
    "arguments,script",
    [
        (
            ["python.exe", "-u", "-B", "AnsiballZ_win_updates.py", "args"],
            "AnsiballZ_win_updates.py",
        ),
        (
            ["python.exe", "-B", "win_updates_launch_lifecycle.py", "root", "cancel"],
            "win_updates_launch_lifecycle.py",
        ),
        (["python.exe", "-c", "worker.py"], "-c"),
        (["python.exe", "-m", "worker.py"], "-m"),
        (["python.exe", "-", "root"], "-"),
        (["python.exe"], ""),
    ],
)
def test_native_startup_arguments_select_scripts_without_python_argv(
    site_fixture: ModuleType,
    arguments: list[str],
    script: str,
) -> None:
    assert site_fixture._script_argument(arguments) == script


def test_startup_gate_works_before_sys_argv_exists(
    site_fixture: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = str(_ROOT / "tmp/codex/python.exe")
    config = {
        "sid": "S-1-5-21-1000",
        "image": image,
        "image_sha256": "hash",
        "original": b"original".hex(),
        "revised": b"revised".hex(),
    }
    monkeypatch.setattr(
        site_fixture, "sys", SimpleNamespace(executable=image, version_info=(3, 4, 4))
    )
    monkeypatch.setattr(site_fixture.os.path, "isfile", lambda _path: True)
    monkeypatch.setattr(site_fixture, "_read", lambda _root: config)
    monkeypatch.setattr(
        site_fixture, "_startup_script", lambda: "AnsiballZ_win_updates.py"
    )
    monkeypatch.setattr(site_fixture, "_sid", lambda: config["sid"])
    monkeypatch.setattr(site_fixture, "_hash", lambda _image: "hash")
    monkeypatch.setattr(
        site_fixture, "_dacl", Mock(side_effect=[b"original", b"revised"])
    )
    write, register, event = Mock(), Mock(), Mock()
    monkeypatch.setattr(site_fixture, "_set_dacl", write)
    monkeypatch.setattr(site_fixture.atexit, "register", register)
    monkeypatch.setattr(site_fixture, "_event", event)
    site_fixture._activate()
    write.assert_called_once_with(image, b"revised")
    register.assert_called_once()
    assert event.call_args.args[1] == "denied"


@pytest.mark.parametrize(
    "script,eligible",
    [
        ("AnsiballZ_win_updates.py", True),
        ("win_updates_launch_lifecycle.py", True),
        ("legacy_windows_runas.py", False),
        ("legacy_windows_async_wrapper.py", False),
        ("worker.py", False),
        ("-c", False),
        ("-", False),
        ("AnsiballZ_win_command.py", False),
    ],
)
def test_only_selected_already_running_frontends_can_deny_the_owned_image(
    site_fixture: ModuleType,
    script: str,
    eligible: bool,
) -> None:
    image = str(_ROOT / "tmp/codex/owned-python.exe")
    config = {"image": image, "sid": "S-1-5-21-1000"}
    assert site_fixture._should_deny(image, script, config["sid"], config) is eligible
    assert not site_fixture._should_deny(image, script, "S-1-5-18", config)
    assert not site_fixture._should_deny(image, script, "S-1-5-21-9999", config)
    assert not site_fixture._should_deny(
        str(_ROOT / "python.exe"), script, config["sid"], config
    )


@pytest.mark.parametrize("current", [b"original", b"revised"])
def test_owned_image_restoration_requires_exact_recorded_acl_and_readback(
    site_fixture: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    current: bytes,
) -> None:
    config = {
        "image": "owned.exe",
        "original": b"original".hex(),
        "revised": b"revised".hex(),
    }
    read, write = Mock(side_effect=[current, b"original"]), Mock()
    monkeypatch.setattr(site_fixture, "_dacl", read)
    monkeypatch.setattr(site_fixture, "_set_dacl", write)
    site_fixture._restore(config)
    write.assert_called_once_with("owned.exe", b"original")


def test_unknown_owned_image_acl_is_not_overwritten(
    site_fixture: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(site_fixture, "_dacl", Mock(return_value=b"external"))
    write = Mock()
    monkeypatch.setattr(site_fixture, "_set_dacl", write)
    with pytest.raises(AssertionError, match="outside this fixture"):
        site_fixture._restore(
            {
                "image": "owned.exe",
                "original": b"original".hex(),
                "revised": b"revised".hex(),
            }
        )
    write.assert_not_called()


def test_restoration_failure_is_not_reported_as_an_exact_original_acl(
    site_fixture: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        site_fixture, "_dacl", Mock(side_effect=[b"revised", b"different"])
    )
    monkeypatch.setattr(site_fixture, "_set_dacl", Mock())
    with pytest.raises(AssertionError):
        site_fixture._restore(
            {
                "image": "owned.exe",
                "original": b"original".hex(),
                "revised": b"revised".hex(),
            }
        )


# pylint: enable=protected-access
