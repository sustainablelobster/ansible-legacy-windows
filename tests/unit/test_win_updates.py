"""Exercise native update public binding and the released servicing sequence."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native provider substitutes are controller-only evidence.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def public_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> Any:
    """Supply the public JSON entry point with recorded worker boundaries.

    :param monkeypatch: Scoped worker and argument substitutions.
    :param capsys: Captured result protocol.
    :param tmp_path: Private argument path.
    :returns: Request runner and worker recorders.
    """
    payload = load_payload("win_updates", monkeypatch)
    boundaries = SimpleNamespace(
        start=Mock(return_value={"changed": False}),
        poll=Mock(return_value={"changed": False, "output": []}),
        cancel=Mock(return_value={"changed": False}),
        wait=Mock(return_value={"changed": False, "updates": {}}),
    )
    for name in ("start", "poll", "cancel"):
        monkeypatch.setattr(payload.worker, name, getattr(boundaries, name))
    import legacy_windows_updates_async as asynchronous  # type: ignore[import-not-found] # pylint: disable=import-error,import-outside-toplevel

    monkeypatch.setattr(asynchronous, "wait", boundaries.wait)
    path = tmp_path / "arguments.json"

    def _request(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_updates.py", str(path)])
        return invoke_payload(payload, capsys)

    return SimpleNamespace(run=_request, payload=payload, worker=boundaries)


def test_public_defaults_and_access_test_keep_source_options(runner: Any) -> None:
    assert runner.run({"_operation": "test"}) == (0, {"changed": False})
    assert runner.worker.start.call_args.args[0] == {
        "accept_list": [],
        "reject_list": [],
        "category_names": ["CriticalUpdates", "SecurityUpdates", "UpdateRollups"],
        "skip_optional": False,
        "reboot": False,
        "reboot_timeout": 1200,
        "maximum_retries_on_failed_updates": 1,
        "state": "installed",
        "server_selection": "default",
        "log_path": None,
        "check_mode": False,
        "test": True,
    }


@pytest.mark.parametrize("operation", ["poll", "cancel"])
def test_internal_worker_operations_preserve_ownership(
    runner: Any, operation: str
) -> None:
    options = {"root": "owned", "nonce": "nonce", "offset": 11}
    assert runner.run({"_operation": operation, "_operation_options": options})[0] == 0
    getattr(runner.worker, operation).assert_called_once_with(options)
    runner.worker.start.assert_not_called()


@pytest.mark.parametrize(
    "value,expected",
    [
        ("SecurityUpdates, Updates", ["SecurityUpdates", "Updates"]),
        (["*", "*"], ["*", "*"]),
        (None, []),
        ([], []),
    ],
)
def test_category_binding_preserves_order_and_source_empty_selection(
    runner: Any, value: Any, expected: list[str]
) -> None:
    assert runner.run({"category_names": value})[0] == 0
    assert runner.worker.start.call_args.args[0]["category_names"] == expected


@pytest.mark.parametrize(
    "name", ["reboot_timeout", "maximum_retries_on_failed_updates"]
)
@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        (0, 0),
        (-1, -1),
        (" +12\t\x00", 12),
        (-(2**31), -(2**31)),
        (2**31 - 1, 2**31 - 1),
    ],
)
def test_int32_binding_keeps_source_limits_and_trailing_nulls(
    runner: Any, name: str, value: Any, expected: int | None
) -> None:
    assert runner.run({name: value})[0] == 0
    assert runner.worker.start.call_args.args[0][name] == expected


@pytest.mark.parametrize(
    "name", ["reboot_timeout", "maximum_retries_on_failed_updates"]
)
@pytest.mark.parametrize(
    "value", [True, False, "12\xa0", "0\x00 ", "", 1.5, 2**31, -(2**31) - 1, [], {}]
)
def test_invalid_int32_fails_before_native_launch(
    runner: Any, name: str, value: Any
) -> None:
    code, result = runner.run({name: value})
    assert code == 1 and result["failed"] and not result["changed"]
    assert "argument for " + name in result["msg"]
    runner.worker.start.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        {"unknown": 1},
        {"state": "invalid"},
        {"server_selection": "invalid"},
        {"skip_optional": "invalid"},
        {"_operation_options": [1]},
    ],
)
def test_invalid_public_options_never_start_updates(
    runner: Any, arguments: dict[str, Any]
) -> None:
    code, result = runner.run(arguments)
    assert code == 1 and result["failed"]
    runner.worker.start.assert_not_called()


def test_async_wait_is_target_projected_before_reporting_complete_result(
    runner: Any,
) -> None:
    assert runner.run({"_operation": "test", "_operation_options": {"wait": True}}) == (
        0,
        {"changed": False, "updates": {}},
    )
    runner.worker.wait.assert_called_once()
    assert runner.worker.wait.call_args.args[0]["test"] is True
    runner.worker.start.assert_not_called()


# This private provider double mirrors obvious COM operations, not a public API.
# pylint: disable=missing-function-docstring,missing-return-doc
class _Object:
    def __init__(self, **properties: Any) -> None:
        self.properties = properties
        self.calls: list[Any] = []

    def get(self, name: str) -> Any:
        value = self.properties[name]
        if isinstance(value, Exception):
            raise value
        return value

    def put(self, name: str, value: Any) -> None:
        self.properties[name] = value
        self.calls.append((name, value))

    def call(self, name: str, *arguments: Any) -> Any:
        self.calls.append((name,) + arguments)
        if name == "AcceptEula":
            self.properties["EulaAccepted"] = True
            return None
        value = self.properties[name]
        return value(*arguments) if callable(value) else value

    def items(self) -> list[Any]:
        return cast(list[Any], self.properties["items"])


# pylint: enable=missing-function-docstring,missing-return-doc


def _update(identifier: str = "a", **changes: Any) -> _Object:
    fields = {
        "Identity": _Object(UpdateID=identifier, RevisionNumber=3),
        "Title": "Update KB123",
        "Description": "detail",
        "KBArticleIDs": _Object(items=["123"]),
        "Categories": _Object(items=[_Object(Name="Security Updates")]),
        "InstallationBehavior": _Object(Impact=0, RebootBehavior=2),
        "Type": 1,
        "DeploymentAction": 1,
        "AutoSelectOnWebSites": True,
        "BrowseOnly": False,
        "IsInstalled": False,
        "IsHidden": False,
        "IsPresent": True,
        "RebootRequired": False,
        "IsBeta": False,
        "IsDownloaded": False,
        "IsMandatory": False,
        "IsUninstallable": True,
        "AutoSelection": 0,
        "AutoDownload": 0,
        "EulaAccepted": False,
    }
    fields.update(changes)
    return _Object(**fields)


@pytest.fixture(name="workflow")
# Explicit independent fake COM objects expose resource order and per-phase
# outcomes to every public behavior test, rather than hide them in a factory.
# pylint: disable-next=too-many-locals
def workflow_runner(runner: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply native update objects and retain every emitted progress packet.

    :param runner: Public payload loader.
    :param monkeypatch: Scoped boot and native-agent boundaries.
    :returns: Round runner, update objects, agent and progress packets.
    """
    helper: ModuleType = runner.payload.worker.updates
    monkeypatch.setattr(helper, "hresult_description", Mock(return_value=None))
    pending = [_update()]
    searcher, downloader, installer = _Object(), _Object(), _Object()
    session = _Object(
        CreateUpdateSearcher=searcher,
        CreateUpdateDownloader=downloader,
        CreateUpdateInstaller=installer,
    )
    agent = Mock()
    agent.__enter__ = Mock(return_value=agent)
    agent.__exit__ = Mock(return_value=False)
    agent.create_session.return_value = session
    agent.reboot_required.return_value = False
    agent.collection.side_effect = lambda rows: _Object(items=rows)
    search_result = _Object(
        ResultCode=2, Updates=_Object(items=pending), Warnings=_Object(items=[])
    )
    download_results, install_results = [_Object(ResultCode=2, HResult=0)], [
        _Object(ResultCode=2, HResult=0, RebootRequired=False)
    ]

    def _operation(
        _target: Any, phase: str, _argument: Any, _cancelled: Any, _progress: Any
    ) -> _Object:
        if phase == "Search":
            return search_result
        outcomes = download_results if phase == "Download" else install_results
        return _Object(GetUpdateResult=lambda index: outcomes[index])

    agent.operation.side_effect = _operation
    monkeypatch.setattr(
        helper, "observe_boot", lambda: {"rc": 0, "stdout": "1234", "stderr": ""}
    )
    monkeypatch.setattr(helper.os.path, "exists", lambda _path: False)
    packets: list[Any] = []
    logs: list[str] = []

    def _run(**changes: Any) -> list[Any]:
        options, _internal = runner.payload._parameters({})
        options.update(changes)
        helper.run(
            options,
            lambda name, result: packets.append((name, result.copy())),
            lambda: False,
            logs.append,
            lambda: agent,
        )
        return packets

    return SimpleNamespace(
        run=_run,
        packets=packets,
        logs=logs,
        agent=agent,
        pending=pending,
        search=search_result,
        download=download_results,
        install=install_results,
        searcher=searcher,
        installer=installer,
        helper=helper,
    )


@pytest.mark.parametrize("mode", [{"state": "searched"}, {"check_mode": True}])
def test_search_and_check_accept_selected_eula_but_never_transfer(
    workflow: Any, mode: dict[str, Any]
) -> None:
    packets = workflow.run(**mode)
    assert [name for name, _result in packets] == ["started", "search_result", "exit"]
    assert workflow.pending[0].get("EulaAccepted")
    assert packets[-1][1]["changed"] == bool(mode.get("check_mode"))
    assert [call.args[1] for call in workflow.agent.operation.call_args_list] == [
        "Search"
    ]


def test_access_only_test_does_not_search_filter_accept_or_install(
    workflow: Any,
) -> None:
    assert [name for name, _result in workflow.run(test=True)] == ["started", "exit"]
    workflow.agent.operation.assert_not_called()
    assert not workflow.pending[0].get("EulaAccepted")
    assert workflow.searcher.get("ServerSelection") == 0


def test_all_filter_reasons_are_ordered_and_filtered_eula_is_untouched(
    workflow: Any,
) -> None:
    workflow.pending[0].properties.update(IsHidden=True, BrowseOnly=True)
    packets = workflow.run(
        accept_list=["never"],
        reject_list=["KB123"],
        category_names=["Updates"],
        skip_optional=True,
    )
    assert packets[1][1]["filtered"] == [
        {
            "id": "a",
            "reasons": [
                "accept_list",
                "reject_list",
                "hidden",
                "category_names",
                "skip_optional",
            ],
        }
    ]
    assert not workflow.pending[0].get("EulaAccepted")
    assert not packets[-1][1]["changed"]


@pytest.mark.parametrize("option", ["accept_list", "reject_list"])
@pytest.mark.parametrize(
    "source_case",
    [
        ("Title", [], "^Title$", True),
        ("Title", [], "KB123", False),
        ("Title", ["123"], "^KB123$", False),
        ("Title", ["123"], "^Title$", False),
        ("Title", ["123"], "KB123", True),
        ("Title", ["123"], "^TitleKB123$", True),
        ("Title", ["123", "456"], "^TitleKB123 KB456$", True),
        ("Title", ["123", "456"], "^KB456$", False),
        ("Title", ["123", "456"], "KB456$", True),
        ("", ["123"], "^KB123$", True),
    ],
)
def test_filter_uses_one_released_title_plus_kb_string_before_eula_acceptance(
    workflow: Any,
    option: str,
    source_case: tuple[str, list[str], str, bool],
) -> None:
    title, kbs, expression, matches = source_case
    workflow.pending[0].properties.update(Title=title, KBArticleIDs=_Object(items=kbs))
    packets = workflow.run(state="searched", **{option: [expression]})
    filtered = not matches if option == "accept_list" else matches
    assert packets[1][1]["filtered"] == (
        [{"id": "a", "reasons": [option]}] if filtered else []
    )
    assert workflow.pending[0].get("EulaAccepted") is not filtered
    assert [call.args[1] for call in workflow.agent.operation.call_args_list] == [
        "Search"
    ]


@pytest.mark.parametrize(
    "categories", [[], ["*"], ["sEcUrItYuPdAtEs"], ["security updates"]]
)
def test_empty_wildcard_alias_and_case_insensitive_categories_select(
    workflow: Any, categories: list[str]
) -> None:
    assert (
        workflow.run(state="searched", category_names=categories)[1][1]["filtered"]
        == []
    )


def test_preexisting_reboot_fails_after_eula_and_search_without_transfer(
    workflow: Any,
) -> None:
    workflow.agent.reboot_required.return_value = True
    packets = workflow.run()
    assert workflow.pending[0].get("EulaAccepted")
    assert (
        packets[-1][1]["exception"]["message"]
        == "A reboot is required before more updates can be installed"
    )
    assert packets[-1][1]["reboot_required"] and not packets[-1][1]["changed"]


@pytest.mark.parametrize(
    "state,phases",
    [
        ("downloaded", ["Search", "Download"]),
        ("installed", ["Search", "Download", "Install"]),
    ],
)
def test_transfer_round_emits_ordered_results_and_keeps_native_install_flags(
    workflow: Any, state: str, phases: list[str]
) -> None:
    packets = workflow.run(state=state)
    assert [call.args[1] for call in workflow.agent.operation.call_args_list] == phases
    assert packets[-1][1]["changed"] and not packets[-1][1]["failed"]
    if state == "installed":
        assert workflow.installer.get("AllowSourcePrompts") is False
        assert (
            workflow.installer.get("ClientApplicationID")
            == "ansible.windows.win_updates"
        )


def test_already_downloaded_update_has_no_download_result_packet(workflow: Any) -> None:
    workflow.pending[0].properties["IsDownloaded"] = True
    packets = workflow.run(state="downloaded")
    assert [name for name, _result in packets] == ["started", "search_result", "exit"]
    assert not packets[-1][1]["changed"]


@pytest.mark.parametrize("phase", ["Download", "Install"])
def test_partial_transfer_failure_retains_changed_results_and_reboot(
    workflow: Any, phase: str
) -> None:
    results = workflow.download if phase == "Download" else workflow.install
    results[0].properties.update(ResultCode=4, HResult=-2145124322, RebootRequired=True)
    packets = workflow.run()
    final = packets[-1][1]
    assert final["changed"] and final["failed"]
    assert final["reboot_required"] == (phase == "Install")
    assert (
        final["exception"]["message"]
        == "Failed to "
        + phase.lower()
        + " all updates - see updates for more information"
    )
    assert packets[-2][0] == phase.lower() + "_result"


def test_shutdown_hresult_retains_boot_marker_and_phase_prefix(workflow: Any) -> None:
    class _Shutdown(OSError):
        hresult = 0x8007045B

    failure = _Shutdown("shutdown in progress")
    workflow.agent.operation.side_effect = failure
    final = workflow.run()[-1][1]
    assert final["exception"]["hresult"] == 0x8007045B
    assert final["exception"]["_is_rebooting_last_boot_time"] == "1234"
    assert (
        final["exception"]["message"] == "Searching for updates: shutdown in progress"
    )


@pytest.mark.parametrize("phase", ["Download", "Install"])
def test_failed_update_carries_available_native_description(
    workflow: Any, phase: str
) -> None:
    results = workflow.download if phase == "Download" else workflow.install
    results[0].properties.update(ResultCode=4, HResult=-2147024891)
    workflow.helper.hresult_description.return_value = "Access is denied."
    packets = workflow.run()
    packet = next(
        result for name, result in packets if name == phase.lower() + "_result"
    )
    assert packet["info"][0]["hresult"] == -2147024891
    assert packet["info"][0]["hresult_description"] == "Access is denied."
    workflow.helper.hresult_description.assert_called_once_with(-2147024891)


def test_native_exception_description_does_not_replace_provider_message(
    workflow: Any,
) -> None:
    class _Denied(OSError):
        hresult = 0x80070005

    failure = _Denied("Provider-specific refusal")
    workflow.agent.operation.side_effect = failure
    workflow.helper.hresult_description.return_value = "Access is denied."
    error = workflow.run()[-1][1]["exception"]
    assert error["message"] == "Searching for updates: Provider-specific refusal"
    assert error["hresult"] == 0x80070005
    assert error["hresult_description"] == "Access is denied."


def test_search_success_with_warnings_logs_without_public_warning_field(
    workflow: Any,
) -> None:
    workflow.search.properties.update(
        ResultCode=3,
        Warnings=_Object(items=[_Object(Context=2, HResult=-1, Message="partial")]),
    )
    final = workflow.run(state="searched")[-1][1]
    assert not final["failed"] and "warnings" not in final
    assert any("0xFFFFFFFF" in message for message in workflow.logs)


@pytest.mark.parametrize(
    "code,name", [(0, "NotStarted"), (4, "Failed"), (5, "Aborted"), (99, "99")]
)
def test_search_non_success_is_actionable_without_eula(
    workflow: Any, code: int, name: str
) -> None:
    workflow.search.properties["ResultCode"] = code
    final = workflow.run()[-1][1]
    assert (
        final["failed"]
        and final["exception"]["message"]
        == f"Failed to search for updates ({name} {code})"
    )
    assert not workflow.pending[0].get("EulaAccepted")
