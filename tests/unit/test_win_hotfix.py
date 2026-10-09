"""Exercise public hotfix selection, previews, failures and pending states."""

# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def hotfix_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Supply an observable provider without claiming Windows execution.

    :param monkeypatch: Scoped provider and argument substitutions.
    :param capsys: Public JSON capture.
    :returns: Payload runner and provider boundaries.
    """
    module = load_payload("win_hotfix", monkeypatch)
    session = SimpleNamespace(
        add=Mock(return_value=False), remove=Mock(return_value=False)
    )
    constructor = Mock(side_effect=lambda: nullcontext(session))
    monkeypatch.setattr(module.hotfix, "HotfixSession", constructor)
    by_name = Mock(
        return_value={"name": "Package", "state": "NotPresent", "kb": "KB42"}
    )
    by_kb = Mock(return_value={"name": "Package", "state": "Installed", "kb": "KB42"})
    installed = Mock(return_value=True)
    from_file = Mock(
        return_value=[
            {
                "path": "expanded/one.cab",
                "name": "Package",
                "state": "NotPresent",
                "kb": "KB42",
            }
        ]
    )
    expand = Mock(side_effect=lambda _source: nullcontext("expanded"))
    for name, value in (
        ("metadata_from_name", by_name),
        ("metadata_from_kb", by_kb),
        ("installed_kb", installed),
        ("metadata_from_file", from_file),
        ("ExpandedMsu", expand),
    ):
        monkeypatch.setattr(module.hotfix, name, value)
    monkeypatch.setattr(module.os.path, "isfile", lambda _path: True)

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(
            module, "read_arguments", lambda *_args, **_kwargs: arguments
        )
        return invoke_payload(module, capsys)

    return SimpleNamespace(
        run=_run,
        module=module,
        session=session,
        constructor=constructor,
        by_name=by_name,
        by_kb=by_kb,
        installed=installed,
        from_file=from_file,
        expand=expand,
    )


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize(
    "parameters,message",
    [
        ({}, "source must be set when state=present"),
        (
            {"state": "absent"},
            "either hotfix_identifier or hotfix_kb needs to be set when state=absent",
        ),
    ],
)
def test_missing_input_is_checked_after_provider_prerequisite(
    runner: Any, check: bool, parameters: dict[str, Any], message: str
) -> None:
    assert runner.run(dict(parameters, _ansible_check_mode=check)) == (
        1,
        {"changed": False, "reboot_required": False, "failed": True, "msg": message},
    )
    runner.constructor.assert_called_once_with()
    runner.expand.assert_not_called()
    runner.session.add.assert_not_called()
    runner.session.remove.assert_not_called()


def test_unavailable_provider_precedes_source_validation(runner: Any) -> None:
    runner.constructor.side_effect = OSError("DISM unavailable")
    assert runner.run({}) == (
        1,
        {
            "changed": False,
            "reboot_required": False,
            "failed": True,
            "msg": "DISM unavailable",
        },
    )


@pytest.mark.parametrize("state,text", [(None, ""), ("invalid", "invalid")])
def test_invalid_state_precedes_provider_and_has_no_reboot_field(
    runner: Any, state: str | None, text: str
) -> None:
    assert runner.run({"state": state}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Get-AnsibleParam: Argument state needs to be one of absent,present "
            "but was " + text + ".",
        },
    )
    runner.constructor.assert_not_called()


def test_invalid_source_path_preserves_legacy_parameter_error(runner: Any) -> None:
    assert runner.run({"source": r"C:\invalid|source.msu"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Get-AnsibleParam: Parameter 'source' has an invalid path "
            "'C:\\invalid|source.msu' specified.",
        },
    )
    runner.constructor.assert_not_called()


@pytest.mark.parametrize(
    "state", ["NotPresent", "Staged", "Removed", "Superseded", "PartiallyInstalled"]
)
def test_absent_ignores_noninstalled_states_without_metadata_fields(
    runner: Any, state: str
) -> None:
    runner.by_name.return_value["state"] = state
    assert runner.run(
        {"state": "absent", "hotfix_identifier": "Package", "hotfix_kb": "KB42"}
    ) == (0, {"changed": False, "reboot_required": False})
    runner.by_name.assert_called_once_with(runner.session, "Package")
    runner.installed.assert_not_called()
    runner.by_kb.assert_not_called()
    runner.session.remove.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_pending_removal_returns_metadata_and_reboot_without_a_write(
    runner: Any, check: bool
) -> None:
    runner.by_name.return_value["state"] = "UninstallPending"
    assert runner.run(
        {
            "state": "absent",
            "hotfix_identifier": "Package",
            "_ansible_check_mode": check,
        }
    ) == (
        0,
        {
            "changed": False,
            "reboot_required": True,
            "identifier": "Package",
            "kb": "KB42",
        },
    )
    runner.session.remove.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_installed_removal_and_preview(runner: Any, check: bool) -> None:
    runner.by_name.return_value["state"] = "Installed"
    runner.session.remove.return_value = True
    assert runner.run(
        {
            "state": "absent",
            "hotfix_identifier": "Package",
            "_ansible_check_mode": check,
        }
    ) == (
        0,
        {
            "changed": True,
            "reboot_required": not check,
            "identifier": "Package",
            "kb": "KB42",
        },
    )
    assert runner.session.remove.call_count == (0 if check else 1)


def test_removal_failure_preserves_identifier_and_unchanged_flag(runner: Any) -> None:
    runner.by_name.return_value["state"] = "Installed"
    runner.session.remove.side_effect = OSError("provider failed")
    assert runner.run({"state": "absent", "hotfix_identifier": "Package"}) == (
        1,
        {
            "changed": False,
            "reboot_required": False,
            "identifier": "Package",
            "kb": "KB42",
            "failed": True,
            "msg": "failed to remove package Package: provider failed",
        },
    )


@pytest.mark.parametrize("installed", [False, True])
def test_kb_resolution_is_only_reached_for_an_installed_hotfix(
    runner: Any, installed: bool
) -> None:
    runner.installed.return_value = installed
    code, result = runner.run(
        {"state": "absent", "hotfix_kb": "KB42", "_ansible_check_mode": True}
    )
    assert code == 0 and result["changed"] is installed
    assert runner.by_kb.call_count == (1 if installed else 0)


def test_source_file_failure_never_expands(
    runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner.module.os.path, "isfile", lambda _path: False)
    assert runner.run({"source": "missing.msu"}) == (
        1,
        {
            "changed": False,
            "reboot_required": False,
            "failed": True,
            "msg": "the path set for source missing.msu does not exist or is not a file",
        },
    )
    runner.expand.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_source_install_and_preview_return_ordered_identifiers(
    runner: Any, check: bool
) -> None:
    runner.from_file.return_value.append(
        {
            "path": "expanded/two.cab",
            "name": "Second",
            "state": "Installed",
            "kb": "KB43",
        }
    )
    runner.session.add.side_effect = [False, True]
    assert runner.run({"source": "update.msu", "_ansible_check_mode": check}) == (
        0,
        {
            "changed": True,
            "reboot_required": not check,
            "identifier": "Package",
            "kb": "KB42",
            "identifiers": ["Package", "Second"],
            "kbs": ["KB42", "KB43"],
        },
    )
    assert [call.args[0] for call in runner.session.add.call_args_list] == (
        [] if check else ["expanded/one.cab", "expanded/two.cab"]
    )


@pytest.mark.parametrize(
    "option, supplied, message",
    [
        (
            "hotfix_identifier",
            "Other",
            "the hotfix identifier Other does not match with the source msu "
            "identifier Package, please omit or specify the correct identifier "
            "to continue",
        ),
        (
            "hotfix_kb",
            "KB99",
            "the hotfix KB KB99 does not match with the source msu KB KB42, "
            "please omit or specify the correct KB to continue",
        ),
    ],
)
def test_source_validation_precedes_any_public_metadata_or_write(
    runner: Any, option: str, supplied: str, message: str
) -> None:
    assert runner.run({"source": "update.msu", option: supplied}) == (
        1,
        {"changed": False, "reboot_required": False, "failed": True, "msg": message},
    )
    runner.session.add.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        ("Installed", "KB42", True, False, False),
        ("Installed", "KB42", False, True, False),
        ("Installed", "UNKNOWN", False, False, False),
        ("InstallPending", "UNKNOWN", False, False, True),
        ("InstallPending", "KB42", True, False, True),
        ("InstallPending", "KB42", False, True, False),
    ],
)
def test_present_states_and_meta_package_hotfix_workaround(
    runner: Any, case: tuple[str, str, bool, bool, bool]
) -> None:
    state, kb, installed, changed, reboot = case
    runner.from_file.return_value[0].update(state=state, kb=kb)
    runner.installed.return_value = installed
    code, result = runner.run(
        {
            "source": "update.msu",
            "hotfix_identifier": "package",
            "_ansible_check_mode": True,
        }
    )
    assert (
        code == 0
        and result["changed"] is changed
        and result["reboot_required"] is reboot
    )
    assert runner.installed.call_count == (0 if kb == "UNKNOWN" else 1)
    runner.session.add.assert_not_called()


def test_partial_package_failure_keeps_public_metadata_and_original_changed_semantics(
    runner: Any,
) -> None:
    runner.from_file.return_value.append(
        {
            "path": "expanded/two.cab",
            "name": "Second",
            "state": "NotPresent",
            "kb": "KB42",
        }
    )
    runner.session.add.side_effect = [False, OSError("second failed")]
    code, result = runner.run({"source": "update.msu"})
    assert (
        code == 1 and result["changed"] is False and result["reboot_required"] is False
    )
    assert result["identifiers"] == ["Package", "Second"]
    assert (
        result["msg"] == "failed to add windows package from path expanded/one.cab "
        "expanded/two.cab: second failed"
    )
