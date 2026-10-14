"""Exercise owned helper staging across installed collection namespaces."""

# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
from types import SimpleNamespace

import pytest

# The locked YAML package does not distribute typing metadata.
import yaml  # type: ignore[import-untyped]

# Ansible's extension API is supplied by the locked controller environment.
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)

from tests.unit.test_python_action import _action


def test_domain_action_group_matches_released_upstream_membership() -> None:
    runtime = Path(__file__).resolve().parents[2] / "legacy_ad/meta/runtime.yml"
    assert yaml.safe_load(runtime.read_text())["action_groups"]["domain"] == [
        "computer",
        "group",
        "object_info",
        "object",
        "ou",
        "service_account",
        "user",
    ]


def test_consumer_helpers_are_staged_with_windows_runtime_and_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = tmp_path / "legacy_ad_example.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")

    # Ansible supplies the inherited action hierarchy, not additional AD layers.
    class _AdAction(PythonModuleAction):  # pylint: disable=too-many-ancestors
        EXTRA_MODULE_UTILS = ("legacy_windows_account.py",)
        COLLECTION_MODULE_UTILS = (helper,)

    action, shell, events = _action(_AdAction, monkeypatch)
    assert action.run() == {"changed": False, "ping": "pong"}
    transferred = [event for event in events if event[0] == "transfer"]
    assert [Path(str(event[1])).name for event in transferred] == [
        "legacy_windows_module.py",
        "legacy_windows_account.py",
        helper.name,
    ]
    assert transferred[-1][1] == str(helper)
    assert transferred[0][1] != str(helper.parent / "legacy_windows_module.py")
    assert shell.tmpdir is None
    assert len([event for event in events if event[0] == "cleanup"]) == 1


@pytest.mark.parametrize(
    "name", ["legacy_windows_module.py", "LEGACY_WINDOWS_MODULE.PY"]
)
def test_helper_name_conflicts_fail_before_transfer_and_cleanup_owned_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    helper = tmp_path / name
    helper.write_text("VALUE = 1\n", encoding="utf-8")

    # Ansible supplies the inherited action hierarchy, not additional AD layers.
    class _AdAction(PythonModuleAction):  # pylint: disable=too-many-ancestors
        COLLECTION_MODULE_UTILS = (helper,)

    action, shell, events = _action(_AdAction, monkeypatch)
    with pytest.raises(AnsibleActionFail, match="Distinct helper sources"):
        action.run()
    assert not any(event[0] in ("transfer", "module") for event in events)
    assert shell.tmpdir is None
    assert len([event for event in events if event[0] == "cleanup"]) == 1


def test_consumer_helper_conflict_with_runas_is_detected_before_transfer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = tmp_path / "legacy_windows_runas.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")

    # Ansible supplies the inherited action hierarchy, not additional AD layers.
    class _AdAction(PythonModuleAction):  # pylint: disable=too-many-ancestors
        COLLECTION_MODULE_UTILS = (helper,)

    action, shell, events = _action(
        _AdAction, monkeypatch, become=SimpleNamespace(name="runas")
    )
    with pytest.raises(AnsibleActionFail, match="Distinct helper sources"):
        action.run()
    assert not any(event[0] in ("transfer", "module") for event in events)
    assert shell.tmpdir is None


def test_repeated_same_source_is_transferred_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = tmp_path / "legacy_ad_example.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")

    # Ansible supplies the inherited action hierarchy, not additional AD layers.
    class _AdAction(PythonModuleAction):  # pylint: disable=too-many-ancestors
        COLLECTION_MODULE_UTILS = (helper, helper)

    action, _, events = _action(_AdAction, monkeypatch)
    action.run()
    assert (
        len(
            [
                event
                for event in events
                if event[0] == "transfer" and event[1] == str(helper)
            ]
        )
        == 1
    )


def test_cross_collection_async_keeps_windows_wrapper_and_consumer_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = tmp_path / "legacy_ad_example.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")

    # Ansible supplies the inherited action hierarchy, not additional AD layers.
    class _AdAction(PythonModuleAction):  # pylint: disable=too-many-ancestors
        _supports_async = True
        COLLECTION_MODULE_UTILS = (helper,)

    action, _, events = _action(_AdAction, monkeypatch, async_val=30)
    action._task.poll = 0  # pylint: disable=protected-access
    assert action.run() == {"changed": False, "ping": "pong"}
    names = [Path(str(event[1])).name for event in events if event[0] == "transfer"]
    assert names == [
        "legacy_windows_module.py",
        "legacy_windows_wmi.py",
        "legacy_windows_async_native.py",
        "legacy_windows_async_worker.py",
        helper.name,
    ]
