"""Exercise the released target-side single-round async update projection."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Progress substitutes prove controller behavior, not Windows execution.
# pylint: disable=protected-access

from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import load_module


@pytest.fixture(name="projector")
def async_projector(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply recorded worker packets without native COM or Windows processes.

    :param monkeypatch: Scoped import-path and worker boundary substitutions.
    :returns: The real target-side async projector with worker recorders.
    """
    root = (
        Path(__file__).resolve().parents[2] / "legacy_windows/plugins" / "module_utils"
    )
    monkeypatch.syspath_prepend(str(root))
    module = load_module(root / "legacy_windows_updates_async.py", "updates_async")
    monkeypatch.setattr(
        module.worker,
        "start",
        Mock(
            return_value={
                "poll_options": {"offset": 0},
                "cancel_options": {"nonce": "owned"},
            }
        ),
    )
    monkeypatch.setattr(module.worker, "poll", Mock())
    monkeypatch.setattr(module.worker, "cancel", Mock(return_value={"changed": False}))
    return module


def _exit(**changes: Any) -> dict[str, Any]:
    return {
        "task": "exit",
        "result": {
            "changed": False,
            "reboot_required": False,
            "failed": False,
            "exception": None,
            **changes,
        },
    }


def _search() -> dict[str, Any]:
    return {
        "task": "search_result",
        "result": {
            "updates": [
                {
                    "id": identifier,
                    "title": "Update " + identifier,
                    "kb": ["KB123", "not-KB", "KB123"],
                    "categories": ["Updates", "Security Updates"],
                }
                for identifier in ["selected", "filtered"]
            ],
            "filtered": [
                {"id": "filtered", "reasons": ["reject_list", "category_names"]}
            ],
        },
    }


def test_access_async_returns_complete_empty_result_and_supervised_cleanup(
    projector: Any,
) -> None:
    projector.worker.poll.return_value = {"output": [_exit()], "offset": 1}
    assert projector.wait({"test": True}) == {
        "changed": False,
        "reboot_required": False,
        "rebooted": False,
        "failed": False,
        "found_update_count": 0,
        "failed_update_count": 0,
        "installed_update_count": 0,
        "updates": {},
        "filtered_updates": {},
    }
    projector.worker.start.assert_called_once_with({"test": True}, supervised=True)
    projector.worker.cancel.assert_called_once_with({"nonce": "owned"})


@pytest.mark.parametrize("failed", [True, False])
def test_async_projection_keeps_arrays_raw_hresult_and_no_failure_description(
    projector: Any, failed: bool
) -> None:
    projector.worker.poll.side_effect = [
        {"output": [_search()], "offset": 1},
        {
            "output": [
                {
                    "task": "download_result",
                    "result": {
                        "info": [{"id": "selected", "result_code": 2, "hresult": 0}]
                    },
                },
                {
                    "task": "install_result",
                    "result": {
                        "info": [
                            {
                                "id": "selected",
                                "result_code": 4 if failed else 2,
                                "hresult": -2145124329 if failed else 0,
                                "hresult_description": "Native text for synchronous output",
                            }
                        ]
                    },
                },
                _exit(changed=True, reboot_required=True, failed=failed),
            ],
            "offset": 4,
        },
    ]
    result = projector.wait({})
    assert result["found_update_count"] == 1
    assert result["failed_update_count"] == int(failed)
    assert result["installed_update_count"] == int(not failed)
    assert result["changed"] and result["reboot_required"]
    assert result["rebooted"] is False
    selected = result["updates"]["selected"]
    assert selected["downloaded"] and selected["installed"] is not failed
    assert selected["kb"] == ["123", "not-KB", "123"]
    assert selected["categories"] == ["Updates", "Security Updates"]
    assert "failure_msg" not in selected
    if failed:
        assert selected["failure_hresult_code"] == -2145124329
    assert result["filtered_updates"]["filtered"]["filtered_reasons"] == [
        "reject_list",
        "category_names",
    ]
    assert projector.worker.poll.call_args_list[1].args[0]["offset"] == 1
    projector.worker.cancel.assert_called_once()


@pytest.mark.parametrize(
    "hresult,expected",
    [(0, None), (-1, -1), (0xFFFFFFFF, -1), (0x8024002E, -2145124306), (1, 1)],
)
def test_failed_exit_keeps_message_and_released_signed_com_hresult(
    projector: Any, hresult: int, expected: int | None
) -> None:
    projector.worker.poll.return_value = {
        "output": [
            _exit(
                failed=True,
                exception={
                    "message": "source failure",
                    "exception": "trace",
                    "hresult": hresult,
                },
            )
        ],
        "offset": 1,
    }
    result = projector.wait({})
    assert result["failed"] and result["msg"] == "source failure"
    assert result["exception"] == "trace"
    assert ("hresult" in result) is bool(hresult)
    if hresult:
        assert result["hresult"] == expected


@pytest.mark.parametrize("description", [None, "", "  ", "Access is denied.\r\n"])
def test_async_failure_carries_available_description_without_losing_provider_text(
    projector: Any, description: str | None
) -> None:
    projector.worker.poll.return_value = {
        "output": [
            _exit(
                failed=True,
                exception={
                    "message": "Native provider failure",
                    "hresult": -2147024891,
                    "hresult_description": description,
                },
            )
        ],
        "offset": 1,
    }
    result = projector.wait({})
    expected = "Native provider failure"
    if description and description.strip():
        expected += " - Access is denied. (Windows Update HRESULT 0x80070005)"
    assert result["msg"] == expected
    assert result["hresult"] == -2147024891
    projector.worker.cancel.assert_called_once()


def test_poll_failure_cancels_the_exact_owned_worker(projector: Any) -> None:
    projector.worker.poll.side_effect = OSError("owned poll failed")
    with pytest.raises(OSError, match="owned poll failed"):
        projector.wait({})
    projector.worker.cancel.assert_called_once_with({"nonce": "owned"})


@pytest.mark.parametrize(
    "message,expected",
    [
        (
            "Searching for updates: WUA.EndSearch failed (HRESULT 0x80244011).",
            "Searching for updates: Exception from HRESULT: 0x80244011",
        ),
        (
            "WUA.BeginDownload failed (HRESULT 0x80244011).",
            "Exception from HRESULT: 0x80244011",
        ),
        ("An actual EXCEPINFO description", "An actual EXCEPINFO description"),
        (
            "WUA.EndSearch failed (HRESULT 0x80244012).",
            "WUA.EndSearch failed (HRESULT 0x80244012).",
        ),
        (
            "WUA.not a method failed (HRESULT 0x80244011).",
            "WUA.not a method failed (HRESULT 0x80244011).",
        ),
    ],
)
def test_async_only_default_com_message_preserves_real_native_descriptions(
    projector: Any,
    message: str,
    expected: str,
) -> None:
    projector.worker.poll.return_value = {
        "output": [
            _exit(failed=True, exception={"message": message, "hresult": 0x80244011})
        ],
        "offset": 1,
    }
    result = projector.wait({})
    assert result["msg"] == expected
    assert result["hresult"] == -2145107951


def test_launch_failure_never_invents_cancellation_ownership(projector: Any) -> None:
    projector.worker.start.side_effect = OSError("owned launch failed")
    with pytest.raises(OSError, match="owned launch failed"):
        projector.wait({})
    projector.worker.cancel.assert_not_called()


def test_cleanup_failure_never_returns_a_successful_projection(projector: Any) -> None:
    projector.worker.poll.return_value = {"output": [_exit()], "offset": 1}
    projector.worker.cancel.side_effect = OSError("owned cleanup failed")
    with pytest.raises(OSError, match="owned cleanup failed"):
        projector.wait({})
